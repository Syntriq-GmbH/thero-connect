//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Syntriq-GmbH/thero-connect/core"
	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/test/testdata"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

const (
	testDomain = "S-1-5-21-1-2-3"
	testMember = "S-1-5-21-7-8-9"
)

var (
	aes128 = types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x11}, 16)}
	aes256 = types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x22}, 32)}
)

func sidBytes(sid string) []byte {
	parts := strings.Split(sid, "-")
	authority, _ := strconv.ParseUint(parts[2], 10, 32)
	raw := binary.BigEndian.AppendUint32([]byte{1, byte(len(parts) - 3), 0, 0}, uint32(authority))
	for _, part := range parts[3:] {
		value, _ := strconv.ParseUint(part, 10, 32)
		raw = binary.LittleEndian.AppendUint32(raw, uint32(value))
	}
	return raw
}

func userValues(rid string, control string, groups, universal []string) map[string][][]byte {
	values := map[string][][]byte{
		"objectSid":          {sidBytes(testDomain + "-" + rid)},
		"objectGUID":         {bytes.Repeat([]byte{1}, 16)},
		"primaryGroupID":     {[]byte("513")},
		"userAccountControl": {[]byte(control)},
		"accountExpires":     {[]byte("0")},
	}
	for _, sid := range groups {
		values["tokenGroups"] = append(values["tokenGroups"], sidBytes(sid))
	}
	for _, sid := range universal {
		values["tokenGroupsGlobalAndUniversal"] = append(values["tokenGroupsGlobalAndUniversal"], sidBytes(sid))
	}
	return values
}

func TestUnder(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-5-21-1-2-34-500":  false,
		"S-1-5-21-1-2-3-500":   true,
		"S-1-5-21-1-2-3-500-1": false,
		"S-1-5-21-1-2-3":       false,
		"S-1-5-21-1-2-3-":      false,
	} {
		if got := under(sid, testDomain); got != want {
			t.Errorf("under(%s) = %v, want %v", sid, got, want)
		}
	}
	if under("S-1-5-21-1-2-3-500", "") {
		t.Error("an empty domain matched")
	}
}

func TestTokenAbsent(t *testing.T) {
	plain := userValues("1105", "512", []string{testDomain + "-513", testDomain + "-2001"}, []string{testDomain + "-513"})
	history := userValues("1105", "512", []string{testDomain + "-513", "S-1-5-21-9-9-9-3001"}, []string{testDomain + "-513"})
	group := testDomain + "-2001"
	other := testDomain + "-2002"
	tests := []struct {
		name     string
		values   map[string][][]byte
		samrOK   bool
		account  string
		denied   string
		provable bool
		sure     []string
		possible []string
		absent   bool
	}{
		{"anonymous", plain, false, "", "S-1-5-7", false, nil, nil, true},
		{"builtin not possible", plain, true, testMember, "S-1-5-32-550", false, nil, nil, true},
		{"builtin samr failed", plain, false, "", "S-1-5-32-550", false, nil, nil, false},
		{"builtin from samr alias", plain, true, testMember, "S-1-5-32-550", false, nil, []string{"S-1-5-32-550"}, false},
		{"builtin users with empty alias answer", plain, true, testMember, "S-1-5-32-545", false, nil, nil, false},
		{"member local not possible", plain, true, testMember, testMember + "-1000", false, nil, nil, true},
		{"member local samr failed", plain, false, "", testMember + "-1000", false, nil, nil, false},
		{"member local from alias", plain, true, testMember, testMember + "-1000", false, []string{testMember + "-1000"}, nil, false},
		{"domain provable", plain, true, testMember, other, true, nil, nil, true},
		{"domain provable on a dc", plain, true, testDomain, other, true, nil, nil, true},
		{"domain alias on a dc", plain, true, testDomain, other, true, nil, []string{other}, false},
		{"domain not provable", plain, true, testMember, other, false, nil, nil, false},
		{"domain group in token groups", plain, true, testMember, group, true, nil, nil, false},
		{"domain history unknown", history, true, testMember, other, true, nil, nil, false},
		{"old domain", plain, true, testMember, "S-1-5-21-9-9-9-1105", true, nil, nil, false},
		{"everyone", plain, true, testMember, "S-1-1-0", true, nil, nil, false},
		{"authenticated users", plain, true, testMember, "S-1-5-11", true, nil, nil, false},
	}
	for _, test := range tests {
		got := token(test.values, test.sure, test.possible, test.samrOK, testDomain, test.account, []string{test.denied}, map[string]bool{test.denied: test.provable})
		if got.Sure == nil {
			t.Fatalf("%s: empty token", test.name)
		}
		if got.Absent[test.denied] != test.absent {
			t.Errorf("%s: absent = %v, want %v", test.name, got.Absent[test.denied], test.absent)
		}
	}
}

func TestTokenSure(t *testing.T) {
	values := userValues("1105", "512", []string{testDomain + "-513", testDomain + "-2001", testDomain + "-3001"}, []string{testDomain + "-513", testDomain + "-2001"})
	got := token(values, []string{testMember + "-1000"}, []string{testMember + "-1001"}, true, testDomain, testMember, nil, nil)
	for _, sid := range []string{testDomain + "-1105", testDomain + "-513", testDomain + "-2001", "S-1-1-0", "S-1-5-2", "S-1-5-11", testMember + "-1000"} {
		if !got.Sure[sid] {
			t.Errorf("%s is not sure", sid)
		}
	}
	for _, sid := range []string{testDomain + "-3001", testMember + "-1001", "S-1-5-15", "S-1-18-1", "S-1-5-32-545"} {
		if got.Sure[sid] {
			t.Errorf("%s is sure", sid)
		}
	}
	if failed := token(values, []string{testMember + "-1000"}, nil, false, testDomain, testMember, nil, nil); failed.Sure[testMember+"-1000"] {
		t.Error("an alias is sure although samr failed")
	}
}

func TestTokenBuiltinAdditions(t *testing.T) {
	tests := []struct {
		group   string
		builtin string
	}{
		{testDomain + "-512", "S-1-5-32-544"},
		{testDomain + "-513", "S-1-5-32-545"},
		{testDomain + "-514", "S-1-5-32-546"},
		{testDomain + "-501", "S-1-5-32-546"},
		{testMember + "-501", "S-1-5-32-546"},
		{testMember + "-514", "S-1-5-32-546"},
	}
	for _, test := range tests {
		values := userValues("1105", "512", []string{test.group}, []string{testDomain + "-513"})
		values["primaryGroupID"] = [][]byte{[]byte("1105")}
		got := token(values, nil, nil, true, testDomain, testMember, []string{test.builtin}, nil)
		if got.Sure == nil || got.Absent[test.builtin] {
			t.Errorf("%s does not make %s possible", test.group, test.builtin)
		}
		without := token(userValues("1105", "512", []string{testDomain + "-2001"}, []string{testDomain + "-2001"}), nil, nil, true, testDomain, testMember, []string{test.builtin}, nil)
		if test.builtin != "S-1-5-32-545" && !without.Absent[test.builtin] {
			t.Errorf("%s is possible without %s", test.builtin, test.group)
		}
	}
}

func TestTokenEmpty(t *testing.T) {
	groups := []string{testDomain + "-513"}
	tests := map[string]map[string][][]byte{
		"disabled":         userValues("1105", "514", groups, groups),
		"outside domain":   userValues("1105", "512", groups, groups),
		"bad group":        userValues("1105", "512", groups, groups),
		"no primary group": userValues("1105", "512", groups, groups),
		"expired":          userValues("1105", "512", groups, groups),
	}
	tests["outside domain"]["objectSid"] = [][]byte{sidBytes("S-1-5-21-9-9-9-1105")}
	tests["bad group"]["tokenGroups"] = append(tests["bad group"]["tokenGroups"], []byte{1})
	delete(tests["no primary group"], "primaryGroupID")
	tests["expired"]["accountExpires"] = [][]byte{[]byte("130000000000000000")}
	for name, values := range tests {
		got := token(values, nil, nil, true, testDomain, testMember, nil, nil)
		if got.Sure != nil || got.Absent != nil {
			t.Errorf("%s: token is not empty", name)
		}
	}
}

func TestTokenSizeLimit(t *testing.T) {
	values := userValues("1105", "512", []string{testDomain + "-513"}, []string{testDomain + "-513"})
	_, base, _ := bases(values, testDomain, testMember)
	for count, empty := range map[int]bool{1015: false, 1016: true} {
		var aliases []string
		for i := len(base); i < count; i++ {
			aliases = append(aliases, fmt.Sprintf("%s-%d", testMember, 5000+i))
		}
		got := token(values, nil, aliases, true, testDomain, testMember, nil, nil)
		if (got.Sure == nil) != empty {
			t.Errorf("%d possible sids: empty = %v, want %v", count, got.Sure == nil, empty)
		}
	}
}

func TestTokenGrants(t *testing.T) {
	values := userValues("1105", "512", []string{testDomain + "-513", testDomain + "-2001"}, []string{testDomain + "-513"})
	sd := descriptor(nil, ace(1, 0, 0x1, testDomain+"-2002"), ace(0, 0, 0x1200a9, testDomain+"-513"))
	denied := core.DeniedSIDs([][]byte{sd})
	if !core.Grants(token(values, nil, nil, true, testDomain, testMember, denied, map[string]bool{testDomain + "-2002": true}), sd) {
		t.Error("a provably absent deny group blocks the read")
	}
	if core.Grants(token(values, nil, nil, true, testDomain, testMember, denied, map[string]bool{}), sd) {
		t.Error("a deny group that is not provable lets the read through")
	}
}

func ace(kind, flags byte, mask uint32, sid string) []byte {
	raw := sidBytes(sid)
	item := []byte{kind, flags, 0, 0}
	binary.LittleEndian.PutUint16(item[2:], uint16(8+len(raw)))
	item = binary.LittleEndian.AppendUint32(item, mask)
	return append(item, raw...)
}

func descriptor(owner []byte, aces ...[]byte) []byte {
	acl := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	for _, item := range aces {
		acl = append(acl, item...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	sd := make([]byte, 20)
	sd[0] = 1
	binary.LittleEndian.PutUint16(sd[2:], 0x8004)
	if owner != nil {
		binary.LittleEndian.PutUint32(sd[4:], 20)
		binary.LittleEndian.PutUint32(sd[8:], 20)
		sd = append(sd, owner...)
	}
	binary.LittleEndian.PutUint32(sd[16:], uint32(len(sd)))
	return append(sd, acl...)
}

func TestWithOwner(t *testing.T) {
	everyone := ace(0, 0, 0x1200a9, "S-1-1-0")
	deny := ace(1, 0, 0x1, testDomain+"-1105")
	without := descriptor(nil, deny, everyone)
	rebuilt, err := withOwner(without)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := core.SIDString(rebuilt[binary.LittleEndian.Uint32(rebuilt[4:]):])
	group, _, _ := core.SIDString(rebuilt[binary.LittleEndian.Uint32(rebuilt[8:]):])
	if owner != "S-1-5-32-544" || group != "S-1-5-32-544" || binary.LittleEndian.Uint16(rebuilt[2:]) != 0x8004 {
		t.Fatalf("owner %s group %s control %#x", owner, group, binary.LittleEndian.Uint16(rebuilt[2:]))
	}
	if !bytes.Equal(rebuilt[binary.LittleEndian.Uint32(rebuilt[16:]):], without[20:]) {
		t.Fatal("dacl bytes changed")
	}
	full := descriptor(sidBytes("S-1-5-32-544"), everyone)
	if same, _ := withOwner(full); !bytes.Equal(same, full) {
		t.Fatal("a descriptor with owner and group was rebuilt")
	}
	user := core.Token{Sure: map[string]bool{"S-1-1-0": true}, Absent: map[string]bool{testDomain + "-1105": true}}
	for _, sd := range [][]byte{without, descriptor(nil, everyone), descriptor(nil, ace(0, 0, 0x10000000, "S-1-1-0")), descriptor(nil, ace(0, 0, 0x1, "S-1-5-4"))} {
		rebuilt, err := withOwner(sd)
		if err != nil {
			t.Fatal(err)
		}
		if core.Grants(user, rebuilt) != core.Grants(user, sd) || !slices.Equal(core.DeniedSIDs([][]byte{rebuilt}), core.DeniedSIDs([][]byte{sd})) {
			t.Errorf("rebuilding changed the decision for %x", sd)
		}
	}
	noDACL := descriptor(nil, everyone)
	binary.LittleEndian.PutUint16(noDACL[2:], 0x8000)
	rebuilt, err = withOwner(noDACL)
	if err != nil || core.Grants(core.Token{Sure: map[string]bool{"S-1-1-0": true}}, rebuilt) {
		t.Fatal("a descriptor without dacl grants after rebuilding")
	}
	if _, err := withOwner(without[:30]); err == nil {
		t.Fatal("a truncated descriptor was accepted")
	}
}

func TestAnnounced(t *testing.T) {
	info := func(versionType uint32) *srvsvc.GetInfoResponse {
		return &srvsvc.GetInfoResponse{Level: 101, Info: &srvsvc.ServerInfo{Value: &srvsvc.ServerInfo_101{ServerInfo101: &dtyp.ServerInfo101{VersionType: versionType}}}}
	}
	if err := announced(info(0x800|0x2|0x8000), nil); err != nil {
		t.Fatal(err)
	}
	refused := info(0x800)
	refused.Return = 5
	for name, err := range map[string]error{
		"windows":    announced(info(0x2|0x8000), nil),
		"return":     announced(refused, errors.New("access denied")),
		"no answer":  announced(nil, errors.New("timeout")),
		"empty info": announced(&srvsvc.GetInfoResponse{}, nil),
	} {
		if !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestShareDescriptor(t *testing.T) {
	answer := func(code uint32, sd []byte) *srvsvc.ShareGetInfoResponse {
		return &srvsvc.ShareGetInfoResponse{Level: 502, Return: code, Info: &srvsvc.ShareInfo{Value: &srvsvc.ShareInfo_502{ShareInfo502: &srvsvc.ShareInfo502I{SecurityDescriptor: sd}}}}
	}
	transport := errors.New("rpc failure")
	if _, err := shareDescriptor(answer(5, nil), transport); !errors.Is(err, core.ErrDenied) {
		t.Errorf("return 5: %v", err)
	}
	if _, err := shareDescriptor(answer(2310, nil), transport); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("return 2310: %v", err)
	}
	if _, err := shareDescriptor(answer(87, nil), transport); err == nil || errors.Is(err, core.ErrUnavailable) {
		t.Errorf("return 87: %v", err)
	}
	if _, err := shareDescriptor(nil, transport); !errors.Is(err, core.ErrUnavailable) {
		t.Errorf("no answer: %v", err)
	}
	if _, err := shareDescriptor(answer(0, nil), nil); err == nil || errors.Is(err, core.ErrUnavailable) {
		t.Errorf("empty descriptor: %v", err)
	}
	if sd, err := shareDescriptor(answer(0, []byte{1, 2, 3}), nil); err != nil || !bytes.Equal(sd, []byte{1, 2, 3}) {
		t.Errorf("descriptor: %x %v", sd, err)
	}
}

func TestStatusError(t *testing.T) {
	tests := map[uint32]error{
		statusAccessDenied:     core.ErrDenied,
		statusStoppedOnSymlink: core.ErrDenied,
		statusNameNotFound:     core.ErrNotFound,
		statusPathNotFound:     core.ErrNotFound,
		statusNoSuchFile:       core.ErrNotFound,
		statusBadNetworkName:   core.ErrNotFound,
		statusSharingViolation: core.ErrBusy,
		statusFileLockConflict: core.ErrBusy,
		statusLockNotGranted:   core.ErrBusy,
		statusPathNotCovered:   core.ErrUnavailable,
		statusSessionExpired:   core.ErrUnavailable,
		statusSessionDeleted:   core.ErrUnavailable,
		statusNameDeleted:      core.ErrUnavailable,
		statusNotADirectory:    core.ErrDenied,
		statusFileIsADirectory: core.ErrDenied,
	}
	for status, want := range tests {
		if err := statusError(&protocol.ResponseError{Code: status}); !errors.Is(err, want) {
			t.Errorf("%#x: %v", status, err)
		}
		compound := &protocol.CompoundResponseError{Errors: []error{&protocol.ResponseError{Code: status}, &protocol.ResponseError{Code: 0xC0000128}}}
		if err := statusError(fmt.Errorf("open: %w", compound)); !errors.Is(err, want) {
			t.Errorf("compound %#x: %v", status, err)
		}
	}
	if err := statusError(&protocol.ResponseError{Code: statusSessionExpired}); !errors.Is(err, errSessionExpired) {
		t.Errorf("expired session is not retried: %v", err)
	}
	if err := statusError(&protocol.TransportError{Err: io.ErrUnexpectedEOF}); !errors.Is(err, core.ErrUnavailable) {
		t.Errorf("transport: %v", err)
	}
	other := statusError(&protocol.ResponseError{Code: 0xC0000001})
	for _, sentinel := range []error{core.ErrDenied, core.ErrNotFound, core.ErrBusy, core.ErrUnavailable} {
		if errors.Is(other, sentinel) {
			t.Errorf("unknown status maps to %v", sentinel)
		}
	}
}

func TestReadAtSplits(t *testing.T) {
	var calls []string
	content := bytes.Repeat([]byte("0123456789abcdef"), 300000/16)
	file := &linuxFile{read: func(length uint32, offset uint64) ([]byte, error) {
		calls = append(calls, fmt.Sprintf("%d@%d", length, offset))
		if offset >= uint64(len(content)) {
			return nil, io.EOF
		}
		return content[offset:min(offset+uint64(length), uint64(len(content)))], nil
	}}
	buffer := make([]byte, 262144)
	n, err := file.ReadAt(buffer, 1000)
	if err != nil || n != 262144 || !bytes.Equal(buffer, content[1000:1000+262144]) {
		t.Fatalf("read %d %v", n, err)
	}
	if want := []string{"65536@1000", "65536@66536", "65536@132072", "65536@197608"}; !slices.Equal(calls, want) {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	n, err = file.ReadAt(buffer, int64(len(content))-70000)
	if n != 70000 || err != io.EOF {
		t.Fatalf("short read %d %v", n, err)
	}
	if n, err := file.ReadAt(buffer, int64(len(content))); n != 0 || err != io.EOF {
		t.Fatalf("read at end %d %v", n, err)
	}
}

func TestPrincipalPattern(t *testing.T) {
	for principal, want := range map[string]bool{
		"thero-connect@CORP.EXAMPLE":   true,
		"svc@AD.CORP-1.EXAMPLE":        true,
		"thero-connect@corp.example":   false,
		"thero-connect@CORP":           false,
		"@CORP.EXAMPLE":                false,
		"thero connect@CORP.EXAMPLE":   false,
		"a@b@CORP.EXAMPLE":             false,
		"thero-connect@CORP.EXAMPLE.":  false,
		"":                             false,
		"thero-connect@CORP..EXAMPLE":  false,
		"thero-connect@CORP_X.EXAMPLE": false,
	} {
		if principalPattern.MatchString(principal) != want {
			t.Errorf("%q: want %v", principal, want)
		}
	}
	if _, err := newSource(t.TempDir(), "thero-connect@corp.example", nil); err == nil || errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("lower-case realm: %v", err)
	}
	t.Setenv("KRB5_CCACHE", "/tmp/cache")
	if _, err := newSource(t.TempDir(), "thero-connect@CORP.EXAMPLE", nil); !errors.Is(err, core.ErrUnavailable) {
		t.Fatalf("missing keytab: %v", err)
	}
	if _, set := os.LookupEnv("KRB5_CCACHE"); set {
		t.Fatal("KRB5_CCACHE is still set")
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		unc, server, share, rel string
		err                     error
	}{
		{`\\fs01.corp.example\finance`, "fs01.corp.example", "finance", "", nil},
		{`\\fs01.corp.example\finance\a\b.txt`, "fs01.corp.example", "finance", `a\b.txt`, nil},
		{`\\fs01\finance\a`, "", "", "", core.ErrUnavailable},
		{`\\10.0.0.5\finance`, "", "", "", core.ErrUnavailable},
		{`\\fe80::1\finance`, "", "", "", core.ErrUnavailable},
	}
	for _, test := range tests {
		server, share, rel, err := splitPath(test.unc)
		if server != test.server || share != test.share || rel != test.rel || !errors.Is(err, test.err) {
			t.Errorf("%s: %q %q %q %v", test.unc, server, share, rel, err)
		}
	}
	if _, _, _, err := splitPath(`fs01.corp.example\finance`); err == nil {
		t.Error("a path without UNC prefix was accepted")
	}
}

func TestKrb5Config(t *testing.T) {
	want := `[libdefaults]
 default_realm = CORP.EXAMPLE
 dns_lookup_kdc = true
 dns_lookup_realm = false
 udp_preference_limit = 1
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
`
	if got := krb5Config("CORP.EXAMPLE"); got != want {
		t.Fatalf("config:\n%s", got)
	}
}

func TestNoNTLMOrGlobalStore(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"ssp.NTLM", "NTLMCredential", "gssapi.AddMechanism", "gssapi.AddCredential", "NTLMBind"} {
			if bytes.Contains(content, []byte(forbidden)) {
				t.Errorf("%s uses %s", name, forbidden)
			}
		}
	}
}

func acceptorToken(t *testing.T, key types.EncryptionKey, data []byte, sequence uint64, seal bool, rotation int) []byte {
	t.Helper()
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{0x05, 0x04, 0x05, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(header[8:], sequence)
	var body []byte
	if seal {
		header[2] |= 0x02
		_, body, err = etype.EncryptMessage(key.KeyValue, append(slices.Clone(data), header...), 22)
	} else {
		var checksum []byte
		checksum, err = etype.GetChecksumHash(key.KeyValue, append(slices.Clone(data), header...), 22)
		binary.BigEndian.PutUint16(header[4:], uint16(len(checksum)))
		body = append(slices.Clone(data), checksum...)
	}
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(header[6:], uint16(rotation))
	rotation %= len(body)
	return append(header, append(slices.Clone(body[len(body)-rotation:]), body[:len(body)-rotation]...)...)
}

func frame(token []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(token))), token...)
}

func TestUnwrapSealedRotated(t *testing.T) {
	for _, key := range []types.EncryptionKey{aes128, aes256} {
		for _, rotation := range []int{0, 28, 1000} {
			data := []byte("search result entry")
			got, err := unwrap(key, acceptorToken(t, key, data, 41, true, rotation), 41, true)
			if err != nil || !bytes.Equal(got, data) {
				t.Errorf("etype %d rotation %d: %q %v", key.KeyType, rotation, got, err)
			}
		}
	}
}

func TestUnwrapRefuses(t *testing.T) {
	data := []byte("search result entry")
	sealed := acceptorToken(t, aes256, data, 41, true, 28)
	flipped := slices.Clone(sealed)
	flipped[len(flipped)-1] ^= 1
	initiator := slices.Clone(sealed)
	initiator[2] &^= 0x01
	tests := map[string][]byte{
		"unsealed":       acceptorToken(t, aes256, data, 41, false, 0),
		"bad checksum":   flipped,
		"from initiator": initiator,
		"short":          sealed[:10],
	}
	for name, token := range tests {
		if _, err := unwrap(aes256, token, 41, true); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := unwrap(aes256, sealed, 42, true); err == nil {
		t.Error("wrong sequence was accepted")
	}
	if _, err := unwrap(aes128, sealed, 41, true); err == nil {
		t.Error("wrong key was accepted")
	}
}

func TestWrapSealed(t *testing.T) {
	for _, key := range []types.EncryptionKey{aes128, aes256} {
		data := []byte("search request")
		token, err := wrap(key, data, 9, true)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(token[:8], []byte{0x05, 0x04, 0x06, 0xff, 0, 0, 0, 0}) || binary.BigEndian.Uint64(token[8:16]) != 9 {
			t.Fatalf("header %x", token[:16])
		}
		etype, _ := crypto.GetEtype(key.KeyType)
		plain, err := etype.DecryptMessage(key.KeyValue, token[16:], 24)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, append(slices.Clone(data), token[:16]...)) {
			t.Fatalf("plain %x", plain)
		}
	}
}

func TestNegotiateLayer(t *testing.T) {
	for offer, accepted := range map[[4]byte]bool{
		{0x04, 0x00, 0xff, 0xff}: true,
		{0x07, 0x00, 0xff, 0xff}: true,
		{0x02, 0x00, 0xff, 0xff}: false,
		{0x01, 0x00, 0x00, 0x00}: false,
		{0x06, 0x00, 0x00, 0x10}: false,
	} {
		c := &sealedConn{key: aes256, recv: 30, send: 70}
		answer, err := c.NegotiateSaslAuth(acceptorToken(t, aes256, offer[:], 30, false, 0), "")
		if (err == nil) != accepted {
			t.Errorf("offer %x: %v", offer, err)
			continue
		}
		if !accepted {
			if c.DeleteSecContext(); c.on.Load() {
				t.Errorf("offer %x switched sealing on", offer)
			}
			continue
		}
		var reply gssapi.WrapToken
		if err := reply.Unmarshal(answer, false); err != nil {
			t.Fatal(err)
		}
		if ok, err := reply.Verify(aes256, 24); !ok || err != nil {
			t.Fatalf("reply does not verify with key usage 24: %v", err)
		}
		if reply.Flags != 0x04 || reply.SndSeqNum != 70 || !bytes.Equal(reply.Payload, []byte{0x04, 0x01, 0x00, 0x00}) {
			t.Fatalf("reply flags %#x sequence %d payload %x", reply.Flags, reply.SndSeqNum, reply.Payload)
		}
		if c.send != 71 || c.recv != 31 || c.limit != int(offer[1])<<16|int(offer[2])<<8|int(offer[3])-60 {
			t.Fatalf("send %d recv %d limit %d", c.send, c.recv, c.limit)
		}
	}
	c := &sealedConn{key: aes256, recv: 30}
	if _, err := c.NegotiateSaslAuth(acceptorToken(t, aes256, []byte{0x04, 0x00, 0xff, 0xff}, 31, false, 0), ""); err == nil {
		t.Fatal("negotiation with a wrong sequence was accepted")
	}
}

func TestSealedConnFraming(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	c := &sealedConn{Conn: client, key: aes128, recv: 5, send: 12, limit: 8, ready: true}
	go server.Write([]byte("plain bind reply"))
	buffer := make([]byte, 64)
	n, err := c.Read(buffer)
	if err != nil || string(buffer[:n]) != "plain bind reply" {
		t.Fatalf("plain read %q %v", buffer[:n], err)
	}
	result := make(chan string)
	go func() {
		next := make([]byte, 64)
		var got []byte
		for len(got) < len("first wrapped pdu, second") {
			n, err := c.Read(next)
			if err != nil {
				result <- err.Error()
				return
			}
			got = append(got, next[:n]...)
		}
		result <- string(got)
	}()
	time.Sleep(20 * time.Millisecond)
	c.DeleteSecContext()
	go func() {
		wrapped := append(frame(acceptorToken(t, aes128, []byte("first wrapped pdu"), 5, true, 28)), frame(acceptorToken(t, aes128, []byte(", second"), 6, true, 0))...)
		for len(wrapped) > 0 {
			n, _ := server.Write(wrapped[:min(len(wrapped), 7)])
			wrapped = wrapped[n:]
		}
	}()
	if got := <-result; got != "first wrapped pdu, second" {
		t.Fatalf("wrapped read %q", got)
	}
	written := make(chan []byte)
	go func() {
		var all []byte
		for range 2 {
			size := make([]byte, 4)
			io.ReadFull(server, size)
			token := make([]byte, binary.BigEndian.Uint32(size))
			io.ReadFull(server, token)
			all = append(all, frame(token)...)
		}
		written <- all
	}()
	if n, err := c.Write([]byte("0123456789ab")); n != 12 || err != nil {
		t.Fatalf("write %d %v", n, err)
	}
	all := <-written
	etype, _ := crypto.GetEtype(aes128.KeyType)
	var plain []byte
	for sequence := uint64(12); len(all) > 0; sequence++ {
		token := all[4 : 4+binary.BigEndian.Uint32(all)]
		all = all[4+len(token):]
		if token[2] != 0x06 || binary.BigEndian.Uint64(token[8:16]) != sequence {
			t.Fatalf("token flags %#x sequence %d", token[2], binary.BigEndian.Uint64(token[8:16]))
		}
		decrypted, err := etype.DecryptMessage(aes128.KeyValue, token[16:], 24)
		if err != nil {
			t.Fatal(err)
		}
		plain = append(plain, decrypted[:len(decrypted)-16]...)
	}
	if string(plain) != "0123456789ab" || c.send != 14 {
		t.Fatalf("written %q send %d", plain, c.send)
	}
}

func TestSealedConnRefusesAfterSwitch(t *testing.T) {
	data := []byte("result")
	huge := binary.BigEndian.AppendUint32(nil, 16<<20+1)
	flipped := acceptorToken(t, aes256, data, 3, true, 28)
	flipped[20] ^= 1
	tests := map[string][]byte{
		"unsealed":       frame(acceptorToken(t, aes256, data, 3, false, 0)),
		"bad checksum":   frame(flipped),
		"wrong sequence": frame(acceptorToken(t, aes256, data, 4, true, 28)),
		"too large":      huge,
	}
	for name, wire := range tests {
		client, server := net.Pipe()
		c := &sealedConn{Conn: client, key: aes256, recv: 3, ready: true}
		c.DeleteSecContext()
		go server.Write(wire)
		if _, err := c.Read(make([]byte, 64)); err == nil {
			t.Errorf("%s was accepted", name)
		}
		server.Close()
		client.Close()
	}
}

func TestAPRep(t *testing.T) {
	authenticator, err := types.NewAuthenticator("CORP.EXAMPLE", types.NewPrincipalName(1, "thero-connect"))
	if err != nil {
		t.Fatal(err)
	}
	authenticator.SubKey = aes128
	reply := func(part messages.EncAPRepPart, tokenID []byte) []byte {
		rep, err := messages.NewAPRep(aes256, part)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := rep.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		framed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: append(append(slices.Clone(kerberosOID), tokenID...), encoded...)})
		if err != nil {
			t.Fatal(err)
		}
		return framed
	}
	good := messages.EncAPRepPart{CTime: authenticator.CTime, Cusec: authenticator.Cusec, Subkey: aes256, SequenceNumber: 77}
	c := &sealedConn{session: aes256, authenticator: authenticator}
	if out, more, err := c.InitSecContextWithOptions("ldap/dc1.corp.example/corp.example", reply(good, []byte{0x02, 0x00}), nil); out != nil || more || err != nil {
		t.Fatalf("good AP-REP: %x %v %v", out, more, err)
	}
	if !bytes.Equal(c.key.KeyValue, aes256.KeyValue) || c.recv != 77 || c.send != uint64(authenticator.SeqNumber) {
		t.Fatalf("key %x recv %d send %d", c.key.KeyValue, c.recv, c.send)
	}
	stale := good
	stale.Cusec = (good.Cusec + 1) % 1000000
	noSubkey := good
	noSubkey.Subkey = types.EncryptionKey{}
	for name, token := range map[string][]byte{
		"time":      reply(stale, []byte{0x02, 0x00}),
		"no subkey": reply(noSubkey, []byte{0x02, 0x00}),
		"error":     reply(good, []byte{0x03, 0x00}),
		"garbage":   []byte{0x60, 0x01, 0x00},
	} {
		c := &sealedConn{session: aes256, authenticator: authenticator}
		if _, _, err := c.InitSecContextWithOptions("ldap/dc1.corp.example/corp.example", token, nil); err == nil || c.key.KeyValue != nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestBindRequiresSealing(t *testing.T) {
	raw, err := hex.DecodeString(strings.Replace(testdata.CCACHE_TEST, "59665b8e59665bce5967044e5967ad08", "00000001000000017ffffff07ffffff0", 1))
	if err != nil {
		t.Fatal(err)
	}
	var cache credentials.CCache
	if err := cache.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	krb, err := client.NewFromCCacheOptionalTGT(&cache, config.New())
	if err != nil {
		t.Fatal(err)
	}
	ticketKey, _ := hex.DecodeString("fd325da3f905d743894e828de41b21af7876b6281b66d9e4bb2eefd64078b476")
	session := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: ticketKey}
	for name, sealing := range map[string]bool{"success after AP-REP": false, "sealing negotiated": true} {
		clientSide, serverSide := net.Pipe()
		go func() {
			defer serverSide.Close()
			respond := func(request *ber.Packet, code int64, token []byte) {
				response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value, ""))
				bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "")
				bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
				bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
				bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
				if token != nil {
					bind.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 7, string(token), ""))
				}
				response.AppendChild(bind)
				serverSide.Write(response.Bytes())
			}
			request, err := ber.ReadPacket(serverSide)
			if err != nil {
				return
			}
			var framed asn1.RawValue
			asn1.Unmarshal(request.Children[1].Children[2].Children[1].Data.Bytes(), &framed)
			var apReq messages.APReq
			if apReq.Unmarshal(framed.Bytes[len(kerberosOID)+2:]) != nil || apReq.DecryptAuthenticator(session) != nil {
				return
			}
			reply, _ := messages.NewAPRep(session, messages.EncAPRepPart{CTime: apReq.Authenticator.CTime, Cusec: apReq.Authenticator.Cusec, Subkey: aes256, SequenceNumber: 9})
			encoded, _ := reply.Marshal()
			token, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: append(append(slices.Clone(kerberosOID), 0x02, 0x00), encoded...)})
			respond(request, 14, token)
			if request, err = ber.ReadPacket(serverSide); err != nil {
				return
			}
			if !sealing {
				respond(request, 0, nil)
				return
			}
			respond(request, 14, acceptorToken(t, aes256, []byte{0x04, 0x00, 0xff, 0xff}, 9, false, 0))
			if request, err = ber.ReadPacket(serverSide); err != nil {
				return
			}
			respond(request, 0, nil)
		}()
		conn, err := (&linuxSource{ldap: krb}).bind(clientSide, "HTTP/host.test.gokrb5")
		if sealing != (err == nil) || !sealing && !strings.Contains(fmt.Sprint(err), "without a sealed security layer") {
			t.Errorf("%s: %v", name, err)
		}
		if conn != nil {
			conn.Close()
		}
	}
}

func offline() *linuxSource {
	return &linuxSource{domain: "corp.example", smb: &auth.KerberosCredential{}, dialing: map[string]*sync.Mutex{}, connections: map[string]*connection{}, down: map[string]time.Time{}}
}

func TestDFSLink(t *testing.T) {
	directory, reparse := uint32(wire.FILE_ATTRIBUTE_DIRECTORY), uint32(wire.FILE_ATTRIBUTE_REPARSE_POINT)
	tests := []struct {
		attributes, tag uint32
		want            bool
	}{
		{directory | reparse, wire.IO_REPARSE_TAG_DFS, true},
		{directory | reparse | wire.FILE_ATTRIBUTE_READONLY | wire.FILE_ATTRIBUTE_ARCHIVE, wire.IO_REPARSE_TAG_DFS, true},
		{directory | reparse, wire.IO_REPARSE_TAG_SYMLINK, false},
		{directory | reparse, wire.IO_REPARSE_TAG_MOUNT_POINT, false},
		{directory | reparse, 0, false},
		{reparse, wire.IO_REPARSE_TAG_DFS, false},
		{directory, wire.IO_REPARSE_TAG_DFS, false},
		{0, wire.IO_REPARSE_TAG_DFS, false},
		{directory | reparse | wire.FILE_ATTRIBUTE_OFFLINE, wire.IO_REPARSE_TAG_DFS, false},
		{directory | reparse | attributeRecallOnOpen, wire.IO_REPARSE_TAG_DFS, false},
		{directory | reparse | attributeRecallOnAccess, wire.IO_REPARSE_TAG_DFS, false},
	}
	for _, test := range tests {
		if got := dfsLink(test.attributes, test.tag); got != test.want {
			t.Errorf("attributes %#x tag %#x: %v", test.attributes, test.tag, got)
		}
	}
}

func TestDomainRefused(t *testing.T) {
	s := offline()
	ctx := context.Background()
	for _, unc := range []string{`\\corp.example\ns`, `\\CORP.Example\ns\docs`} {
		if _, _, err := s.tree(ctx, unc); !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("tree %s: %v", unc, err)
		}
		if _, err := s.List(unc); !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("list %s: %v", unc, err)
		}
		if _, _, err := s.Descriptor(unc + `\a.txt`); !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("descriptor %s: %v", unc, err)
		}
		if _, err := s.Open(unc, "a.txt"); !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("open %s: %v", unc, err)
		}
		if _, err := s.Share(unc); !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("share %s: %v", unc, err)
		}
	}
	for _, server := range []string{"corp.example", "CORP.EXAMPLE"} {
		if _, _, err := s.pipe(ctx, server, "srvsvc"); !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("pipe %s: %v", server, err)
		}
		for _, sids := range [][]string{nil, {testMember + "-1001"}} {
			if _, err := s.Allowed(server, sids, [][]byte{{1}}); !errors.Is(err, core.ErrUnavailable) {
				t.Errorf("allowed %s %v: %v", server, sids, err)
			}
		}
	}
	if len(s.down) != 0 || len(s.connections) != 0 || len(s.dialing) != 0 {
		t.Errorf("the domain name was dialed: down %v connections %v dialing %v", s.down, s.connections, s.dialing)
	}
}

func TestDeadHostMemo(t *testing.T) {
	s := offline()
	unc := `\\dead.corp.example\share`
	if _, err := s.List(unc); !errors.Is(err, core.ErrUnavailable) || strings.Contains(err.Error(), "unreachable since") {
		t.Fatalf("first dial: %v", err)
	}
	failed := s.down["dead.corp.example"]
	if failed.IsZero() {
		t.Fatal("a failed dial is not remembered")
	}
	for _, path := range []string{unc, `\\DEAD.corp.example\other\x`} {
		if _, err := s.List(path); !errors.Is(err, core.ErrUnavailable) || !strings.Contains(err.Error(), "unreachable since") {
			t.Errorf("remembered host %s: %v", path, err)
		}
	}
	if _, err := s.Referral(unc); !errors.Is(err, core.ErrUnavailable) || errors.Is(err, core.ErrNotFound) || !strings.Contains(err.Error(), "unreachable since") {
		t.Errorf("referral to a remembered host: %v", err)
	}
	if !s.down["dead.corp.example"].Equal(failed) {
		t.Error("a remembered host was dialed again")
	}
	s.down["dead.corp.example"] = time.Now().Add(-downTime - time.Second)
	if _, err := s.List(unc); !errors.Is(err, core.ErrUnavailable) || strings.Contains(err.Error(), "unreachable since") {
		t.Errorf("dial after the memo expired: %v", err)
	}
	if time.Since(s.down["dead.corp.example"]) > time.Minute {
		t.Error("an expired memo is not renewed by a failed dial")
	}
	if _, err := s.List(`\\other.corp.example\share`); err == nil || strings.Contains(err.Error(), "unreachable since") {
		t.Errorf("another host is refused by the memo: %v", err)
	}
	if len(s.down) != 2 {
		t.Errorf("memo %v", s.down)
	}
}

func TestReferralRefusals(t *testing.T) {
	s := offline()
	for _, unc := range []string{`\\fs1\ns`, `\\10.0.0.5\ns`, `\\dead.corp.example\ns\docs`} {
		if _, err := s.Referral(unc); !errors.Is(err, core.ErrUnavailable) || errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrDenied) {
			t.Errorf("%s: %v", unc, err)
		}
	}
	s.domain = "corp.invalid"
	if _, err := s.Referral(`\\CORP.invalid\ns`); !errors.Is(err, core.ErrUnavailable) || errors.Is(err, core.ErrNotFound) {
		t.Errorf("domain without domain controllers: %v", err)
	}
	if _, ok := s.down["corp.invalid"]; ok || len(s.connections) != 0 {
		t.Errorf("the domain name was dialed: %v", s.down)
	}
}

package core

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oiweiwei/gokrb5.fork/v9/client"
	krbconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

func sidBytes(sid string) []byte {
	parts := strings.Split(sid, "-")
	authority, _ := strconv.ParseUint(parts[2], 10, 64)
	b := []byte{1, byte(len(parts) - 3), 0, 0, 0, 0, 0, 0}
	for i := range 6 {
		b[2+i] = byte(authority >> (8 * (5 - i)))
	}
	for _, part := range parts[3:] {
		value, _ := strconv.ParseUint(part, 10, 32)
		b = binary.LittleEndian.AppendUint32(b, uint32(value))
	}
	return b
}

func aceBytes(kind, flags byte, mask uint32, sid string) []byte {
	body := append(binary.LittleEndian.AppendUint32(nil, mask), sidBytes(sid)...)
	header := []byte{kind, flags, 0, 0}
	binary.LittleEndian.PutUint16(header[2:], uint16(4+len(body)))
	return append(header, body...)
}

func aclBytes(aces ...[]byte) []byte {
	b := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[4:], uint16(len(aces)))
	for _, item := range aces {
		b = append(b, item...)
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func descriptorBytes(owner string, dacl, sacl []byte) []byte {
	control := uint16(0x8000)
	b := make([]byte, 20)
	b[0] = 1
	if owner != "" {
		binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
		b = append(b, sidBytes(owner)...)
	}
	if sacl != nil {
		control |= 0x10
		binary.LittleEndian.PutUint32(b[12:], uint32(len(b)))
		b = append(b, sacl...)
	}
	if dacl != nil {
		control |= 0x4
		binary.LittleEndian.PutUint32(b[16:], uint32(len(b)))
		b = append(b, dacl...)
	}
	binary.LittleEndian.PutUint16(b[2:], control)
	return b
}

func readable(sids ...string) []byte {
	var aces [][]byte
	for _, sid := range sids {
		aces = append(aces, aceBytes(0, 0, 0x1200a9, sid))
	}
	return descriptorBytes("S-1-5-32-544", aclBytes(aces...), nil)
}

func TestValidPath(t *testing.T) {
	accepted := map[string]string{
		"a.txt":                  "a.txt",
		"Reports/2026/q1.pdf":    `Reports\2026\q1.pdf`,
		"Überblick/日本語 file.md":  `Überblick\日本語 file.md`,
		"console/connection.txt": `console\connection.txt`,
	}
	for input, want := range accepted {
		got, err := validPath(input)
		if err != nil || got != want {
			t.Errorf("validPath(%q) = %q, %v", input, got, err)
		}
	}
	rejected := []string{"", "..", "a/../b", ".", "a/./b", "a//b", "/a", "a/", `a\b`, "a:b", "x::$DATA", "CON", "dir/com1.txt", "Lpt9", "nul.tar.gz", "name.", "name ", "a\x01b", "a*b", "a?b", `a"b`, "a<b", "a|b", strings.Repeat("a", 1025)}
	for _, input := range rejected {
		if _, err := validPath(input); err == nil {
			t.Errorf("validPath(%q) accepted", input)
		}
	}
	if _, err := validPath(strings.Repeat("a", 1024)); err != nil {
		t.Errorf("1024 characters rejected: %v", err)
	}
}

func TestSplitUNC(t *testing.T) {
	cases := []struct {
		input, server, share string
		ok                   bool
	}{
		{`\\fs01.corp.example\finance`, "fs01.corp.example", "finance", true},
		{`\\fs01\finance\sub\dir`, "fs01", "finance", true},
		{`\\fs01`, "", "", false},
		{`\\fs01\`, "", "", false},
		{`\\\finance`, "", "", false},
		{`C:\finance`, "", "", false},
		{`//fs01/finance`, "", "", false},
	}
	for _, c := range cases {
		server, share, err := SplitUNC(c.input)
		if (err == nil) != c.ok || server != c.server || share != c.share {
			t.Errorf("splitUNC(%q) = %q, %q, %v", c.input, server, share, err)
		}
	}
}

func TestExcluded(t *testing.T) {
	patterns := []string{"~$*", "*.tmp", "Archive/Old"}
	cases := map[string]bool{
		"Reports/~$draft.docx":     true,
		"a/b/cache.tmp":            true,
		"Archive/Old":              true,
		"Archive/Old/2019/x.pdf":   true,
		"archive/OLD/deep/file.md": true,
		"Archive/Older/x.pdf":      false,
		"Reports/q1.pdf":           false,
		"Old/Archive/x.pdf":        false,
	}
	for input, want := range cases {
		if got := excluded(patterns, input); got != want {
			t.Errorf("excluded(%q) = %v", input, got)
		}
	}
}

func TestSupported(t *testing.T) {
	domainUser := "S-1-5-21-1-2-3-1104"
	effective := func(aces ...[]byte) []byte { return descriptorBytes("S-1-5-32-544", aclBytes(aces...), nil) }
	nullDACL := descriptorBytes("S-1-5-32-544", nil, nil)
	binary.LittleEndian.PutUint16(nullDACL[2:], 0x8004)
	notRelative := readable(domainUser)
	binary.LittleEndian.PutUint16(notRelative[2:], 0x0004)
	label := func(mask uint32) []byte {
		return descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(0, 0, 0x1200a9, domainUser)), aclBytes(aceBytes(0x11, 0, mask, "S-1-16-8192")))
	}
	full := readable(domainUser)
	ok := map[string][]byte{
		"allow and deny":              effective(aceBytes(1, 0, 0x1200a9, "S-1-5-21-1-2-3-1105"), aceBytes(0, 0, 0x1200a9, domainUser)),
		"deny everyone":               effective(aceBytes(1, 0, 0x1, "S-1-1-0")),
		"deny authenticated users":    effective(aceBytes(1, 0, 0x1, "S-1-5-11")),
		"deny builtin":                effective(aceBytes(1, 0, 0x1, "S-1-5-32-545")),
		"deny anonymous":              effective(aceBytes(1, 0, 0x1, "S-1-5-7")),
		"empty dacl":                  effective(),
		"label no write up":           label(0x1),
		"generic bit on inherit-only": effective(aceBytes(0, 0x08|0x01, 0x10000000, domainUser)),
		"object ace inherit-only":     effective(aceBytes(5, 0x08, 0x1, domainUser)),
	}
	for name, sd := range ok {
		if err := supported(sd); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	rejected := map[string][]byte{
		"null dacl":         nullDACL,
		"missing dacl":      descriptorBytes("S-1-5-32-544", nil, nil),
		"not self-relative": notRelative,
		"object ace":        effective(aceBytes(5, 0, 0x1, domainUser)),
		"callback ace":      effective(aceBytes(9, 0, 0x1, domainUser)),
		"generic bit":       effective(aceBytes(0, 0, 0x80000000, domainUser)),
		"deny network":      effective(aceBytes(1, 0, 0x1, "S-1-5-2")),
		"deny organization": effective(aceBytes(1, 0, 0x1, "S-1-5-15")),
		"deny ntlm":         effective(aceBytes(1, 0, 0x1, "S-1-5-64-10")),
		"deny asserted":     effective(aceBytes(1, 0, 0x1, "S-1-18-1")),
		"allow interactive": effective(aceBytes(0, 0, 0x1200a9, "S-1-5-4")),
		"scope ace":         descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(0, 0, 0x1, domainUser)), aclBytes(aceBytes(0x13, 0, 0, "S-1-17-1"))),
		"label no read up":  label(0x2),
		"truncated header":  full[:12],
		"truncated acl":     full[:len(full)-4],
		"empty":             nil,
	}
	rejected["sid past ace"] = func() []byte {
		sd := readable(domainUser)
		offset := binary.LittleEndian.Uint32(sd[16:])
		sd[offset+8+8+1] = 15
		return sd
	}()
	rejected["ace size past acl"] = func() []byte {
		sd := readable(domainUser)
		offset := binary.LittleEndian.Uint32(sd[16:])
		binary.LittleEndian.PutUint16(sd[offset+8+2:], 200)
		return sd
	}()
	for name, sd := range rejected {
		if err := supported(sd); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestClassOf(t *testing.T) {
	alice := "S-1-5-21-1-2-3-1104"
	a := descriptorBytes("S-1-5-21-1-2-3-500", aclBytes(aceBytes(0, 0, 0x1200a9, alice)), nil)
	b := descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(0, 0, 0x1200a9, alice)), nil)
	if classOf("finance", a) != classOf("finance", b) {
		t.Error("same dacl with another owner changed the class")
	}
	if classOf("finance", a) == classOf("hr", a) {
		t.Error("another root kept the class")
	}
	if len(classOf("finance", a)) != 32 {
		t.Error("class is not 32 hex characters")
	}
	ownerRights := aclBytes(aceBytes(0, 0, 0x1200a9, alice), aceBytes(0, 0, 0x1200a9, "S-1-3-4"))
	c := descriptorBytes("S-1-5-21-1-2-3-500", ownerRights, nil)
	d := descriptorBytes("S-1-5-32-544", ownerRights, nil)
	if classOf("finance", c) == classOf("finance", d) {
		t.Error("owner ignored with OWNER RIGHTS")
	}
	inherited := aclBytes(aceBytes(0, 0, 0x1200a9, alice), aceBytes(0, 0x08, 0x1200a9, "S-1-3-4"))
	if classOf("finance", descriptorBytes("S-1-5-21-1-2-3-500", inherited, nil)) != classOf("finance", descriptorBytes("S-1-5-32-544", inherited, nil)) {
		t.Error("inherit-only OWNER RIGHTS made the owner count")
	}
}

func TestClassOfGolden(t *testing.T) {
	alice := "S-1-5-21-1-2-3-1104"
	plain := aclBytes(aceBytes(0, 0, 0x1200a9, alice))
	ownerRights := aclBytes(aceBytes(0, 0, 0x1200a9, alice), aceBytes(0, 0, 0x1200a9, "S-1-3-4"))
	inheritOnly := aclBytes(aceBytes(0, 0, 0x1200a9, alice), aceBytes(0, 0x08, 0x1200a9, "S-1-3-4"))
	cases := map[string]struct {
		dacl []byte
		want string
	}{
		"plain":                     {plain, "e2ae8734bfae01204a67599125089422"},
		"owner rights":              {ownerRights, "8b9c7bc1e6d0d44027b6b5e93a087f94"},
		"inherit-only owner rights": {inheritOnly, "71e9b25061498f40f4afb5771881dc0f"},
	}
	for name, c := range cases {
		if got := classOf("finance", descriptorBytes("S-1-5-21-1-2-3-500", c.dacl, nil)); got != c.want {
			t.Errorf("%s: classOf = %s, want %s", name, got, c.want)
		}
	}
}

func TestFiletime(t *testing.T) {
	checks := []struct {
		value int64
		want  time.Time
	}{
		{0, time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)},
		{116444736000000000, time.Unix(0, 0)},
		{116444736000000000 + 17000000000000001, time.Unix(1700000000, 100)},
		{116444736000000000 - 1, time.Unix(0, -100)},
	}
	for _, check := range checks {
		if got := Filetime(check.value); !got.Equal(check.want) {
			t.Errorf("Filetime(%d) = %v, want %v", check.value, got, check.want)
		}
	}
	if got := max(0, Filetime(0).UnixMilli()); got != 0 {
		t.Errorf("clamped zero filetime = %d, want 0", got)
	}
}

func TestAccountOf(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	future := strconv.FormatInt(now.Add(time.Hour).UnixNano()/100+116444736000000000, 10)
	past := strconv.FormatInt(now.Add(-time.Hour).UnixNano()/100+116444736000000000, 10)
	guid := []byte{0x3a, 0x2b, 0x1c, 0x6f, 0x5e, 0x4d, 0x60, 0x4f, 0x81, 0x72, 0x93, 0xa4, 0xb5, 0xc6, 0xd0, 0x01}
	base := func(extra map[string]string) map[string][][]byte {
		values := map[string][][]byte{
			"objectSid":          {sidBytes("S-1-5-21-1-2-3-1104")},
			"objectGUID":         {guid},
			"userPrincipalName":  {[]byte("alice@corp.example")},
			"mail":               {[]byte("alice@example.com")},
			"proxyAddresses":     {[]byte("SMTP:Alice@Example.com"), []byte("smtp:a@example.com"), []byte("x500:/o=corp"), []byte("smtp:")},
			"userAccountControl": {[]byte("512")},
		}
		for name, value := range extra {
			if value == "" {
				delete(values, name)
				continue
			}
			values[name] = [][]byte{[]byte(value)}
		}
		return values
	}
	got, ok := AccountOf(base(nil), now)
	want := Account{SID: "S-1-5-21-1-2-3-1104", GUID: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d001", UPN: "alice@corp.example", Mail: "alice@example.com", Proxies: []string{"alice@example.com", "a@example.com"}, Enabled: true}
	if !ok || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("AccountOf = %+v, %v", got, ok)
	}
	enabled := map[string]struct {
		extra map[string]string
		want  bool
	}{
		"no expiry attribute":   {nil, true},
		"expires never zero":    {map[string]string{"accountExpires": "0"}, true},
		"expires never max":     {map[string]string{"accountExpires": "9223372036854775807"}, true},
		"expires in the future": {map[string]string{"accountExpires": future}, true},
		"expired":               {map[string]string{"accountExpires": past}, false},
		"expiry not a number":   {map[string]string{"accountExpires": "soon"}, false},
		"disabled":              {map[string]string{"userAccountControl": "514"}, false},
		"control missing":       {map[string]string{"userAccountControl": ""}, false},
		"control not a number":  {map[string]string{"userAccountControl": "x"}, false},
	}
	for name, c := range enabled {
		got, ok := AccountOf(base(c.extra), now)
		if !ok || got.Enabled != c.want {
			t.Errorf("%s: enabled = %v, %v", name, got.Enabled, ok)
		}
	}
	for name, values := range map[string]map[string][][]byte{
		"no sid":     base(map[string]string{"objectSid": ""}),
		"bad sid":    base(map[string]string{"objectSid": "x"}),
		"no guid":    base(map[string]string{"objectGUID": ""}),
		"short guid": base(map[string]string{"objectGUID": "short"}),
	} {
		if _, ok := AccountOf(values, now); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLDAPFilter(t *testing.T) {
	got := ldapFilter([]string{"a@x.com", `b*(c)\d@x.com` + "\x00"})
	want := `(&(objectCategory=person)(objectClass=user)(|(mail=a@x.com)(userPrincipalName=a@x.com)(proxyAddresses=smtp:a@x.com)(mail=b\2a\28c\29\5cd@x.com\00)(userPrincipalName=b\2a\28c\29\5cd@x.com\00)(proxyAddresses=smtp:b\2a\28c\29\5cd@x.com\00)))`
	if got != want {
		t.Errorf("ldapFilter = %s", got)
	}
}

func TestMatchAccounts(t *testing.T) {
	accounts := []Account{
		{SID: "S-1-5-21-1-1", GUID: "g1", UPN: "alice@corp.example", Mail: "alice@example.com", Enabled: true},
		{SID: "S-1-5-21-1-2", GUID: "g2", UPN: "bob@corp.example", Proxies: []string{"BOB@example.com"}, Enabled: true},
		{SID: "S-1-5-21-1-3", GUID: "g3", UPN: "carol@corp.example", Mail: "shared@example.com"},
		{SID: "S-1-5-21-1-4", GUID: "g4", UPN: "dave@corp.example", Mail: "shared@example.com"},
		{SID: "S-1-5-21-1-5", GUID: "g5", UPN: "erin@example.com", Mail: "erin.alias@example.com"},
		{SID: "S-1-5-21-1-1", GUID: "g1", UPN: "alice@corp.example", Mail: "alice@example.com", Enabled: true},
	}
	users := matchAccounts([]string{"alice@example.com", "bob@example.com", "shared@example.com", "erin@example.com", "erin.alias@example.com", "nobody@example.com"}, accounts)
	got := map[string]bool{}
	for _, u := range users {
		got[u.Email+" "+u.SID] = u.Ambiguous
	}
	want := map[string]bool{
		"alice@example.com S-1-5-21-1-1":      false,
		"bob@example.com S-1-5-21-1-2":        false,
		"shared@example.com S-1-5-21-1-3":     true,
		"shared@example.com S-1-5-21-1-4":     true,
		"erin@example.com S-1-5-21-1-5":       true,
		"erin.alias@example.com S-1-5-21-1-5": true,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("matchAccounts = %v", got)
	}
	if users[0].GUID != "g1" || users[0].UPN != "alice@corp.example" || !users[0].Enabled || users[1].Mail != "" {
		t.Errorf("fields not copied: %+v", users[:2])
	}
}

func TestCodeOf(t *testing.T) {
	cases := map[error]string{
		ErrDenied:                              "denied",
		fmt.Errorf("open: %w", ErrNotFound):    "not_found",
		ErrBusy:                                "busy",
		fmt.Errorf("ldap: %w", ErrUnavailable): "unavailable",
		errors.New("anything else"):            "failed",
	}
	for err, want := range cases {
		if got := codeOf(err); got != want {
			t.Errorf("codeOf(%v) = %s", err, got)
		}
	}
}

func TestGrants(t *testing.T) {
	user, domainUsers, group, local, other := "S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-1200", "S-1-5-21-1-2-3-1300", "S-1-5-21-1-2-3-1999"
	sure := func(extra ...string) map[string]bool {
		set := map[string]bool{user: true, domainUsers: true, "S-1-1-0": true, "S-1-5-2": true, "S-1-5-11": true}
		for _, sid := range extra {
			set[sid] = true
		}
		return set
	}
	read := uint32(0x1200a9)
	everyone := aceBytes(0, 0, read, "S-1-1-0")
	plain := func(aces ...[]byte) []byte { return descriptorBytes("S-1-5-32-544", aclBytes(aces...), nil) }
	cases := []struct {
		name    string
		sd      []byte
		token   Token
		windows bool
		want    bool
	}{
		{"allow everyone", plain(everyone), Token{Sure: map[string]bool{"S-1-1-0": true}}, true, true},
		{"allow domain users", plain(aceBytes(0, 0, read, domainUsers)), Token{Sure: sure()}, true, true},
		{"empty dacl", plain(), Token{Sure: sure()}, false, false},
		{"null dacl", descriptorBytes("S-1-5-32-544", nil, nil), Token{Sure: sure()}, true, false},
		{"deny user before allow", plain(aceBytes(1, 0, read, user), everyone), Token{Sure: sure()}, false, false},
		{"deny user after allow", plain(everyone, aceBytes(1, 0, read, user)), Token{Sure: sure()}, true, false},
		{"deny absent group", plain(aceBytes(1, 0, read, group), everyone), Token{Sure: sure(), Absent: map[string]bool{group: true}}, true, true},
		{"deny group not proven absent", plain(aceBytes(1, 0, read, group), everyone), Token{Sure: sure()}, true, false},
		{"allow interactive", plain(aceBytes(0, 0, read, "S-1-5-4")), Token{Sure: sure()}, false, false},
		{"allow inherit only", plain(aceBytes(0, 0x09, read, "S-1-1-0")), Token{Sure: sure()}, false, false},
		{"allow generic read", plain(aceBytes(0, 0, 0x80000000, "S-1-1-0")), Token{Sure: sure()}, false, false},
		{"owner rights, owner sure", descriptorBytes(user, aclBytes(aceBytes(0, 0, read, "S-1-3-4")), nil), Token{Sure: sure()}, true, true},
		{"owner rights, owner absent", descriptorBytes(other, aclBytes(aceBytes(0, 0, read, "S-1-3-4")), nil), Token{Sure: sure()}, false, false},
		{"creator owner effective", descriptorBytes(user, aclBytes(aceBytes(0, 0, read, "S-1-3-0")), nil), Token{Sure: sure()}, false, false},
		{"read attributes only", plain(aceBytes(0, 0, 0x80, "S-1-1-0")), Token{Sure: sure()}, false, false},
		{"builtin users, samr", plain(aceBytes(0, 0, read, "S-1-5-32-545")), Token{Sure: sure("S-1-5-32-545")}, true, true},
		{"builtin users, samr failed", plain(aceBytes(0, 0, read, "S-1-5-32-545")), Token{Sure: sure()}, true, false},
		{"callback ace", plain(aceBytes(9, 0, read, "S-1-1-0")), Token{Sure: sure()}, false, false},
		{"label no read up", descriptorBytes("S-1-5-32-544", aclBytes(everyone), aclBytes(aceBytes(0x11, 0, 0x2, "S-1-16-12288"))), Token{Sure: sure()}, false, false},
		{"scoped policy", descriptorBytes("S-1-5-32-544", aclBytes(everyone), aclBytes(aceBytes(0x13, 0, 0, "S-1-17-1"))), Token{Sure: sure()}, false, false},
		{"deny anonymous", plain(aceBytes(1, 0, read, "S-1-5-7"), everyone), Token{Sure: sure(), Absent: map[string]bool{"S-1-5-7": true}}, true, true},
		{"deny write only", plain(aceBytes(1, 0, 0x2, "S-1-1-0"), everyone), Token{Sure: sure()}, true, true},
		{"domain local on member", plain(aceBytes(0, 0, read, local)), Token{Sure: sure()}, true, false},
		{"share denies user", plain(aceBytes(1, 0, 0x1f01ff, user), everyone), Token{Sure: sure()}, false, false},
		{"deny this organization", plain(aceBytes(1, 0, read, "S-1-5-15"), everyone), Token{Sure: sure(), Absent: map[string]bool{"S-1-5-15": true}}, false, false},
		{"owner rights, owner only possible", descriptorBytes(local, aclBytes(aceBytes(0, 0, read, "S-1-3-4")), nil), Token{Sure: sure()}, false, false},
		{"deny builtin users not absent", plain(aceBytes(1, 0, read, "S-1-5-32-545"), everyone), Token{Sure: sure()}, false, false},
		{"deny old domain sid", plain(aceBytes(1, 0, read, "S-1-5-21-9-9-9-1105"), everyone), Token{Sure: sure()}, false, false},
		{"deny domain local with foreign member", plain(aceBytes(1, 0, read, local), everyone), Token{Sure: sure()}, false, false},
		{"empty token", plain(everyone), Token{}, false, false},
	}
	for _, c := range cases {
		got := Grants(c.token, c.sd)
		if got != c.want {
			t.Errorf("%s: Grants = %v, want %v", c.name, got, c.want)
		}
		if c.want && !c.windows {
			t.Errorf("%s: grants where Windows refuses", c.name)
		}
	}
	if len(cases) != 30 {
		t.Fatalf("%d cases", len(cases))
	}
}

func TestDeniedSIDs(t *testing.T) {
	first := descriptorBytes("S-1-5-32-544", aclBytes(
		aceBytes(1, 0, 0x1, "S-1-5-21-1-2-3-1105"),
		aceBytes(1, 0, 0x1, "S-1-5-21-1-2-3-1104"),
		aceBytes(1, 0x08, 0x1, "S-1-5-21-1-2-3-1106"),
		aceBytes(0, 0, 0x1200a9, "S-1-5-21-1-2-3-1107"),
	), nil)
	second := descriptorBytes("S-1-5-32-544", aclBytes(
		aceBytes(1, 0, 0x2, "S-1-5-21-1-2-3-1104"),
		aceBytes(1, 0, 0x1, "S-1-5-32-545"),
	), nil)
	got := DeniedSIDs([][]byte{first, second, descriptorBytes("S-1-5-32-544", nil, nil)})
	want := []string{"S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1105", "S-1-5-32-545"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("DeniedSIDs = %v, want %v", got, want)
	}
	if got := DeniedSIDs(nil); len(got) != 0 {
		t.Fatalf("DeniedSIDs(nil) = %v", got)
	}
}

func TestInDomain(t *testing.T) {
	domain := "S-1-5-21-1-2-3"
	cases := map[string]struct {
		sid, domain string
		want        bool
	}{
		"user":             {"S-1-5-21-1-2-3-1104", domain, true},
		"group":            {"S-1-5-21-1-2-3-513", domain, true},
		"domain itself":    {domain, domain, false},
		"trailing dash":    {domain + "-", domain, false},
		"nested":           {"S-1-5-21-1-2-3-1104-5", domain, false},
		"other domain":     {"S-1-5-21-1-2-4-1104", domain, false},
		"longer prefix":    {"S-1-5-21-1-2-33-1104", domain, false},
		"builtin":          {"S-1-5-32-544", domain, false},
		"well known":       {"S-1-1-0", domain, false},
		"empty domain":     {"S-1-5-21-1-2-3-1104", "", false},
		"empty sid":        {"", domain, false},
		"lower case":       {"s-1-5-21-1-2-3-1104", domain, false},
		"suffix only":      {"x" + domain + "-1104", domain, false},
		"child domain sid": {"S-1-5-21-9-8-7-1104", domain, false},
	}
	for name, c := range cases {
		if got := InDomain(c.sid, c.domain); got != c.want {
			t.Errorf("%s: InDomain(%q, %q) = %v", name, c.sid, c.domain, got)
		}
	}
}

func TestMemberOf(t *testing.T) {
	domain := "S-1-5-21-1-2-3"
	base := func() map[string][][]byte {
		return map[string][][]byte{
			"objectSid":      {sidBytes("S-1-5-21-1-2-3-1104")},
			"objectClass":    {[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("user")},
			"sAMAccountName": {[]byte("Alice")},
			"tokenGroups":    {sidBytes("S-1-5-21-1-2-3-513"), sidBytes("S-1-5-32-545"), sidBytes("S-1-5-21-9-8-7-1200")},
		}
	}
	got, ok := MemberOf(base(), domain, "CORP")
	want := Member{Login: `i:0#.w|corp\alice`, SID: "s-1-5-21-1-2-3-1104", SIDs: []string{"s-1-5-21-1-2-3-1104", "s-1-5-21-1-2-3-513", "s-1-5-32-545", "s-1-5-21-9-8-7-1200"}}
	if !ok || got.Login != want.Login || got.SID != want.SID || !slices.Equal(got.SIDs, want.SIDs) {
		t.Fatalf("MemberOf = %+v, %v", got, ok)
	}
	if got, ok := MemberOf(base(), domain, "Corp"); !ok || got.Login != `i:0#.w|corp\alice` {
		t.Errorf("mixed case netbios: %+v, %v", got, ok)
	}
	upper := base()
	upper["objectClass"] = [][]byte{[]byte("USER")}
	if _, ok := MemberOf(upper, domain, "CORP"); !ok {
		t.Error("upper case user class refused")
	}
	change := func(name string, values ...[]byte) map[string][][]byte {
		changed := base()
		if values == nil {
			delete(changed, name)
			return changed
		}
		changed[name] = values
		return changed
	}
	refused := map[string]struct {
		values          map[string][][]byte
		domain, netbios string
	}{
		"no sid":                {change("objectSid"), domain, "CORP"},
		"bad sid":               {change("objectSid", []byte("x")), domain, "CORP"},
		"sid with trailing":     {change("objectSid", append(sidBytes("S-1-5-21-1-2-3-1104"), 0)), domain, "CORP"},
		"two sids":              {change("objectSid", sidBytes("S-1-5-21-1-2-3-1104"), sidBytes("S-1-5-21-1-2-3-1105")), domain, "CORP"},
		"foreign domain":        {change("objectSid", sidBytes("S-1-5-21-9-8-7-1104")), domain, "CORP"},
		"domain sid":            {change("objectSid", sidBytes(domain)), domain, "CORP"},
		"builtin sid":           {change("objectSid", sidBytes("S-1-5-32-544")), domain, "CORP"},
		"empty domain":          {base(), "", "CORP"},
		"no class":              {change("objectClass"), domain, "CORP"},
		"group":                 {change("objectClass", []byte("top"), []byte("group")), domain, "CORP"},
		"foreign principal":     {change("objectClass", []byte("top"), []byte("foreignSecurityPrincipal")), domain, "CORP"},
		"computer":              {change("objectClass", []byte("top"), []byte("person"), []byte("user"), []byte("computer")), domain, "CORP"},
		"no account name":       {change("sAMAccountName"), domain, "CORP"},
		"empty account name":    {change("sAMAccountName", []byte("")), domain, "CORP"},
		"two account names":     {change("sAMAccountName", []byte("alice"), []byte("bob")), domain, "CORP"},
		"empty netbios":         {base(), domain, ""},
		"no token groups":       {change("tokenGroups"), domain, "CORP"},
		"empty token groups":    {change("tokenGroups", [][]byte{}...), domain, "CORP"},
		"bad token group":       {change("tokenGroups", sidBytes("S-1-5-21-1-2-3-513"), []byte("x")), domain, "CORP"},
		"token group trailing":  {change("tokenGroups", append(sidBytes("S-1-5-21-1-2-3-513"), 1)), domain, "CORP"},
		"lower case domain sid": {base(), "s-1-5-21-1-2-3", "CORP"},
	}
	for name, c := range refused {
		if got, ok := MemberOf(c.values, c.domain, c.netbios); ok || got.Login != "" || got.SID != "" || got.SIDs != nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}

func TestKerberosToken(t *testing.T) {
	cl := client.NewWithPassword("alice", "CORP.EXAMPLE", "secret", krbconfig.New())
	ticket := messages.Ticket{
		TktVNO:  5,
		Realm:   "CORP.EXAMPLE",
		SName:   types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/intranet.corp.example"),
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 2, Cipher: []byte{1, 2, 3, 4}},
	}
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	init, err := spnego.NewNegTokenInitKRB5(cl, ticket, key)
	if err != nil {
		t.Fatal(err)
	}
	genuine, err := (&spnego.SPNEGOToken{Init: true, NegTokenInit: init}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	kerberos := asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	msKerberos := asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
	ntlm := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	application := func(oid asn1.ObjectIdentifier, rest ...[]byte) []byte {
		header, _ := asn1.Marshal(oid)
		token, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: slices.Concat(append([][]byte{header}, rest...)...)})
		return token
	}
	negotiation := func(outer asn1.ObjectIdentifier, mechTypes []asn1.ObjectIdentifier, mechToken []byte) []byte {
		body, _ := asn1.MarshalWithParams(negTokenInit{MechTypes: mechTypes, MechToken: mechToken}, "explicit,tag:0")
		return application(outer, body)
	}
	spnegoOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	inner := init.MechTokenBytes
	var wrapped asn1.RawValue
	var oid asn1.ObjectIdentifier
	asn1.Unmarshal(inner, &wrapped)
	request, _ := asn1.Unmarshal(wrapped.Bytes, &oid)
	apReq := request[2:]
	apRep, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 15, IsCompound: true, Bytes: []byte{0x30, 0x00}})
	ntlmssp := []byte("NTLMSSP\x00\x01\x00\x00\x00\x07\x82\x08\xa2")
	if rebuilt := negotiation(spnegoOID, []asn1.ObjectIdentifier{kerberos}, inner); !slices.Equal(rebuilt, genuine) {
		t.Fatalf("rebuilt token differs:\n%x\n%x", rebuilt, genuine)
	}
	accepted := map[string][]byte{
		"kerberos":                 genuine,
		"microsoft kerberos first": negotiation(spnegoOID, []asn1.ObjectIdentifier{msKerberos, kerberos}, inner),
		"microsoft inner oid":      negotiation(spnegoOID, []asn1.ObjectIdentifier{msKerberos}, application(msKerberos, []byte{1, 0}, apReq)),
		"ntlm listed later":        negotiation(spnegoOID, []asn1.ObjectIdentifier{kerberos, ntlm}, inner),
	}
	for name, token := range accepted {
		if err := KerberosToken(token); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	negTokenResp, _ := (&spnego.SPNEGOToken{Resp: true, NegTokenResp: spnego.NegTokenResp{NegState: 1, ResponseToken: inner}}).Marshal()
	only := []asn1.ObjectIdentifier{kerberos}
	refused := map[string][]byte{
		"empty":                {},
		"garbage":              []byte("not a token"),
		"raw ntlmssp":          ntlmssp,
		"raw kerberos token":   inner,
		"ntlm negotiation":     negotiation(spnegoOID, []asn1.ObjectIdentifier{ntlm}, ntlmssp),
		"ntlm first":           negotiation(spnegoOID, []asn1.ObjectIdentifier{ntlm, kerberos}, inner),
		"no mech types":        negotiation(spnegoOID, []asn1.ObjectIdentifier{}, inner),
		"missing mech token":   negotiation(spnegoOID, only, nil),
		"ntlmssp mech token":   negotiation(spnegoOID, only, ntlmssp),
		"ntlm inner oid":       negotiation(spnegoOID, only, application(ntlm, []byte{1, 0}, apReq)),
		"ap-rep token id":      negotiation(spnegoOID, only, application(kerberos, []byte{2, 0}, apReq)),
		"error token id":       negotiation(spnegoOID, only, application(kerberos, []byte{3, 0}, apReq)),
		"ap-rep body":          negotiation(spnegoOID, only, application(kerberos, []byte{1, 0}, apRep)),
		"no request":           negotiation(spnegoOID, only, application(kerberos, []byte{1, 0})),
		"short token id":       negotiation(spnegoOID, only, application(kerberos, []byte{1})),
		"request trailing":     negotiation(spnegoOID, only, application(kerberos, []byte{1, 0}, apReq, []byte{0})),
		"mech token trailing":  negotiation(spnegoOID, only, append(slices.Clone(inner), 0)),
		"token trailing":       append(slices.Clone(genuine), 0),
		"truncated":            genuine[:40],
		"negotiation response": negTokenResp,
		"kerberos outer oid":   negotiation(kerberos, only, inner),
		"ntlm outer oid":       negotiation(ntlm, only, inner),
	}
	for name, token := range refused {
		if err := KerberosToken(token); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "not a Kerberos token") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
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
		server, share, err := splitUNC(c.input)
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

func TestLDAPFilter(t *testing.T) {
	got := ldapFilter([]string{"a@x.com", `b*(c)\d@x.com` + "\x00"})
	want := `(&(objectCategory=person)(objectClass=user)(|(mail=a@x.com)(userPrincipalName=a@x.com)(proxyAddresses=smtp:a@x.com)(mail=b\2a\28c\29\5cd@x.com\00)(userPrincipalName=b\2a\28c\29\5cd@x.com\00)(proxyAddresses=smtp:b\2a\28c\29\5cd@x.com\00)))`
	if got != want {
		t.Errorf("ldapFilter = %s", got)
	}
}

func TestMatchAccounts(t *testing.T) {
	accounts := []account{
		{sid: "S-1-5-21-1-1", guid: "g1", upn: "alice@corp.example", mail: "alice@example.com", enabled: true},
		{sid: "S-1-5-21-1-2", guid: "g2", upn: "bob@corp.example", proxies: []string{"BOB@example.com"}, enabled: true},
		{sid: "S-1-5-21-1-3", guid: "g3", upn: "carol@corp.example", mail: "shared@example.com"},
		{sid: "S-1-5-21-1-4", guid: "g4", upn: "dave@corp.example", mail: "shared@example.com"},
		{sid: "S-1-5-21-1-5", guid: "g5", upn: "erin@example.com", mail: "erin.alias@example.com"},
		{sid: "S-1-5-21-1-1", guid: "g1", upn: "alice@corp.example", mail: "alice@example.com", enabled: true},
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
		errDenied:                              "denied",
		fmt.Errorf("open: %w", errNotFound):    "not_found",
		errBusy:                                "busy",
		fmt.Errorf("ldap: %w", errUnavailable): "unavailable",
		errors.New("anything else"):            "failed",
	}
	for err, want := range cases {
		if got := codeOf(err); got != want {
			t.Errorf("codeOf(%v) = %s", err, got)
		}
	}
}

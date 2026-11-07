package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestValidHost(t *testing.T) {
	cases := map[string]bool{
		"fs1.corp.example":                        true,
		"FS-01.Corp.Example":                      true,
		"a.b":                                     true,
		"x1.2b":                                   true,
		strings.Repeat("a", 63) + ".corp":         true,
		strings.Repeat("a", 64) + ".corp":         false,
		strings.Repeat("abcdefg.", 31) + "ab":     true,
		strings.Repeat("abcdefg.", 31) + "abcdef": false,
		"single":                                  false,
		"":                                        false,
		"fs1.corp.":                               false,
		".corp":                                   false,
		"fs1..corp":                               false,
		"-fs1.corp":                               false,
		"fs1-.corp":                               false,
		"fs1.-corp":                               false,
		"10.0.0.1":                                false,
		"fs1.123":                                 false,
		"::1":                                     false,
		"fe80::1.corp":                            false,
		"fs1.corp@SSL@443":                        false,
		"fs1.corp:445":                            false,
		"fs_1.corp":                               false,
		"fs 1.corp":                               false,
		"fs1.cörp":                                false,
		"fs1.corp\x00":                            false,
	}
	for host, want := range cases {
		if got := validHost(host); got != want {
			t.Errorf("validHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestShareOfBindScope(t *testing.T) {
	shares := map[string]string{
		`\\FS2.Corp\Docs`:         `\\fs2.corp\docs`,
		`\\fs2.corp\docs\Sub\Dir`: `\\fs2.corp\docs`,
		`\\fs2.corp`:              "",
		`fs2.corp\docs`:           "",
		"":                        "",
	}
	for unc, want := range shares {
		if got := shareOf(unc); got != want {
			t.Errorf("shareOf(%q) = %q, want %q", unc, got, want)
		}
	}
	if bind("") != 0 || bind(`\\fs2.corp\docs`) != 0x54216a4ac85adc58 || bind(`\\fs3.corp\docs`) == bind(`\\fs2.corp\docs`) {
		t.Fatalf("bind %016x %016x", bind(`\\fs2.corp\docs`), bind(`\\fs3.corp\docs`))
	}
	if scope("ns", "") != "ns" || scope("ns", `\\fs2.corp\docs`) != "ns\x00\\\\fs2.corp\\docs" {
		t.Fatalf("scope %q", scope("ns", `\\fs2.corp\docs`))
	}
	sd := readable("S-1-5-21-1-2-3-1104")
	if classOf(scope("ns", ""), sd) != classOf("ns", sd) || classOf(scope("ns", `\\fs2.corp\docs`), sd) == classOf(scope("ns", `\\fs3.corp\docs`), sd) {
		t.Fatal("scope does not separate targets or changes plain roots")
	}
}

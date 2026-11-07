package core

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Entry struct {
	Name     string
	Dir      bool
	ID       uint64
	Size     int64
	Created  time.Time
	Modified time.Time
	Changed  time.Time
}

type Account struct {
	SID     string
	GUID    string
	UPN     string
	Mail    string
	Proxies []string
	Enabled bool
}

type FileInfo struct {
	ID       uint64
	Size     int64
	Modified time.Time
}

type File interface {
	io.ReaderAt
	io.Closer
	Info() (FileInfo, error)
}

type Source interface {
	List(dir string) ([]Entry, error)
	Descriptor(path string) ([]byte, uint64, error)
	Share(root string) ([]byte, error)
	Accounts(filter string) ([]Account, error)
	Allowed(server string, sids []string, descriptors [][]byte) ([][]bool, error)
	Open(root, rel string) (File, error)
}

type Token struct {
	Sure   map[string]bool
	Absent map[string]bool
}

var (
	ErrDenied      = errors.New("denied")
	ErrNotFound    = errors.New("not found")
	ErrBusy        = errors.New("busy")
	ErrUnavailable = errors.New("unavailable")
)

var deviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func validPath(rel string) (string, error) {
	if rel == "" || utf8.RuneCountInString(rel) > 1024 {
		return "", errors.New("invalid path length")
	}
	if strings.ContainsAny(rel, "\\:*?\"<>|") {
		return "", errors.New("invalid path character")
	}
	for _, r := range rel {
		if r < 0x20 {
			return "", errors.New("invalid path character")
		}
	}
	segments := strings.Split(rel, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", errors.New("invalid path segment")
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return "", errors.New("invalid path segment")
		}
		base, _, _ := strings.Cut(segment, ".")
		if deviceNames[strings.ToUpper(base)] {
			return "", errors.New("device name in path")
		}
	}
	return strings.Join(segments, `\`), nil
}

func SplitUNC(unc string) (string, string, error) {
	rest, ok := strings.CutPrefix(unc, `\\`)
	if !ok {
		return "", "", fmt.Errorf("%q is not a UNC path", unc)
	}
	parts := strings.Split(rest, `\`)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%q is not a UNC path", unc)
	}
	return parts[0], parts[1], nil
}

func excluded(patterns []string, rel string) bool {
	segments := strings.Split(strings.ToLower(rel), "/")
	for _, pattern := range patterns {
		pattern = strings.ToLower(pattern)
		for i, segment := range segments {
			prefix := strings.Join(segments[:i+1], "/")
			if matched, _ := path.Match(pattern, segment); matched {
				return true
			}
			if matched, _ := path.Match(pattern, prefix); matched {
				return true
			}
		}
	}
	return false
}

func SIDString(b []byte) (string, int, error) {
	if len(b) < 8 || b[0] != 1 || b[1] > 15 {
		return "", 0, errors.New("invalid sid")
	}
	size := 8 + 4*int(b[1])
	if len(b) < size {
		return "", 0, errors.New("truncated sid")
	}
	var authority uint64
	for _, v := range b[2:8] {
		authority = authority<<8 | uint64(v)
	}
	sid := "S-1-" + strconv.FormatUint(authority, 10)
	for i := 8; i < size; i += 4 {
		sid += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[i:])), 10)
	}
	return sid, size, nil
}

func Filetime(value int64) time.Time {
	since := value - 116444736000000000
	return time.Unix(since/10000000, since%10000000*100)
}

var AccountAttributes = []string{"objectSid", "objectGUID", "userPrincipalName", "mail", "proxyAddresses", "userAccountControl", "accountExpires"}

func AccountOf(values map[string][][]byte, now time.Time) (Account, bool) {
	first := func(name string) string {
		if list := values[name]; len(list) > 0 {
			return string(list[0])
		}
		return ""
	}
	sid, _, err := SIDString([]byte(first("objectSid")))
	guid := []byte(first("objectGUID"))
	if err != nil || len(guid) != 16 {
		return Account{}, false
	}
	var proxies []string
	for _, proxy := range values["proxyAddresses"] {
		if len(proxy) > 5 && strings.EqualFold(string(proxy[:5]), "smtp:") {
			proxies = append(proxies, strings.ToLower(string(proxy[5:])))
		}
	}
	control, err := strconv.ParseUint(first("userAccountControl"), 10, 32)
	enabled := err == nil && control&2 == 0
	if value := first("accountExpires"); value != "" {
		expires, err := strconv.ParseInt(value, 10, 64)
		enabled = enabled && err == nil && (expires == 0 || expires == math.MaxInt64 || expires > now.UnixNano()/100+116444736000000000)
	}
	return Account{
		SID:     sid,
		GUID:    fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(guid[0:4]), binary.LittleEndian.Uint16(guid[4:6]), binary.LittleEndian.Uint16(guid[6:8]), guid[8:10], guid[10:16]),
		UPN:     first("userPrincipalName"),
		Mail:    first("mail"),
		Proxies: proxies,
		Enabled: enabled,
	}, true
}

type ace struct {
	kind  byte
	flags byte
	mask  uint32
	sid   string
}

func readACL(sd []byte, offset uint32) ([]ace, []byte, error) {
	if int(offset)+8 > len(sd) {
		return nil, nil, errors.New("acl outside descriptor")
	}
	size := int(binary.LittleEndian.Uint16(sd[offset+2:]))
	count := int(binary.LittleEndian.Uint16(sd[offset+4:]))
	if size < 8 || int(offset)+size > len(sd) {
		return nil, nil, errors.New("acl outside descriptor")
	}
	acl := sd[offset : int(offset)+size]
	aces := make([]ace, 0, count)
	position := 8
	for range count {
		if position+4 > len(acl) {
			return nil, nil, errors.New("ace outside acl")
		}
		aceSize := int(binary.LittleEndian.Uint16(acl[position+2:]))
		if aceSize < 4 || position+aceSize > len(acl) {
			return nil, nil, errors.New("ace outside acl")
		}
		raw := acl[position : position+aceSize]
		item := ace{kind: raw[0], flags: raw[1]}
		if len(raw) >= 8 {
			item.mask = binary.LittleEndian.Uint32(raw[4:])
		}
		if item.kind == 0 || item.kind == 1 {
			if len(raw) < 8 {
				return nil, nil, errors.New("truncated ace")
			}
			sid, _, err := SIDString(raw[8:])
			if err != nil {
				return nil, nil, err
			}
			item.sid = sid
		}
		aces = append(aces, item)
		position += aceSize
	}
	return aces, acl, nil
}

var logonSIDs = map[string]bool{
	"S-1-5-3": true, "S-1-5-4": true, "S-1-5-6": true, "S-1-5-13": true, "S-1-5-14": true, "S-1-2-0": true, "S-1-2-1": true,
}

func supported(sd []byte) error {
	if len(sd) < 20 || sd[0] != 1 {
		return errors.New("invalid descriptor")
	}
	control := binary.LittleEndian.Uint16(sd[2:])
	if control&0x8000 == 0 {
		return errors.New("descriptor is not self-relative")
	}
	daclOffset := binary.LittleEndian.Uint32(sd[16:])
	if control&0x4 == 0 || daclOffset == 0 {
		return errors.New("descriptor has no dacl")
	}
	dacl, _, err := readACL(sd, daclOffset)
	if err != nil {
		return err
	}
	for _, item := range dacl {
		if item.flags&0x08 != 0 {
			continue
		}
		if item.kind != 0 && item.kind != 1 {
			return fmt.Errorf("unsupported ace type %d", item.kind)
		}
		if item.mask&0xF0000000 != 0 {
			return errors.New("generic access bits in ace")
		}
		denyAllowed := item.sid == "S-1-1-0" || item.sid == "S-1-5-7" || item.sid == "S-1-5-11" || strings.HasPrefix(item.sid, "S-1-5-32-") || strings.HasPrefix(item.sid, "S-1-5-21-")
		if item.kind == 1 && !denyAllowed {
			return fmt.Errorf("unsupported deny ace for %s", item.sid)
		}
		if item.kind == 0 && logonSIDs[item.sid] {
			return fmt.Errorf("unsupported allow ace for %s", item.sid)
		}
	}
	saclOffset := binary.LittleEndian.Uint32(sd[12:])
	if control&0x10 == 0 || saclOffset == 0 {
		return nil
	}
	sacl, _, err := readACL(sd, saclOffset)
	if err != nil {
		return err
	}
	for _, item := range sacl {
		if item.kind == 0x13 {
			return errors.New("scoped policy ace")
		}
		if item.kind == 0x11 && item.mask&0x2 != 0 {
			return errors.New("mandatory label with no read up")
		}
	}
	return nil
}

func classOf(root string, sd []byte) string {
	hash := sha256.New()
	hash.Write([]byte("thero-connect/1\x00" + root + "\x00"))
	dacl, raw, _ := readACL(sd, binary.LittleEndian.Uint32(sd[16:]))
	hash.Write(raw)
	for _, item := range dacl {
		if item.flags&0x08 != 0 || item.sid != "S-1-3-4" {
			continue
		}
		hash.Write([]byte{0})
		ownerOffset := int(binary.LittleEndian.Uint32(sd[4:]))
		if ownerOffset > 0 && ownerOffset < len(sd) {
			if _, size, err := SIDString(sd[ownerOffset:]); err == nil {
				hash.Write(sd[ownerOffset : ownerOffset+size])
			}
		}
		break
	}
	return hex.EncodeToString(hash.Sum(nil))[:32]
}

const readData = 0x1

func Grants(t Token, sd []byte) bool {
	if supported(sd) != nil {
		return false
	}
	owner := ""
	if offset := binary.LittleEndian.Uint32(sd[4:]); offset != 0 && int(offset) < len(sd) {
		owner, _, _ = SIDString(sd[offset:])
	}
	dacl, _, err := readACL(sd, binary.LittleEndian.Uint32(sd[16:]))
	if err != nil {
		return false
	}
	granted := false
	for _, item := range dacl {
		if item.flags&0x08 != 0 || item.mask&readData == 0 {
			continue
		}
		if item.kind == 1 && !t.Absent[item.sid] {
			return false
		}
		if item.kind == 0 && (t.Sure[item.sid] || item.sid == "S-1-3-4" && owner != "" && t.Sure[owner]) {
			granted = true
		}
	}
	return granted
}

func DeniedSIDs(descriptors [][]byte) []string {
	unique := map[string]bool{}
	for _, sd := range descriptors {
		if supported(sd) != nil {
			continue
		}
		dacl, _, _ := readACL(sd, binary.LittleEndian.Uint32(sd[16:]))
		for _, item := range dacl {
			if item.kind == 1 && item.flags&0x08 == 0 {
				unique[item.sid] = true
			}
		}
	}
	sids := make([]string, 0, len(unique))
	for sid := range unique {
		sids = append(sids, sid)
	}
	slices.Sort(sids)
	return sids
}

func ldapFilter(emails []string) string {
	escape := strings.NewReplacer(`\`, `\5c`, "*", `\2a`, "(", `\28`, ")", `\29`, "\x00", `\00`)
	var filter strings.Builder
	filter.WriteString("(&(objectCategory=person)(objectClass=user)(|")
	for _, email := range emails {
		value := escape.Replace(email)
		filter.WriteString("(mail=" + value + ")(userPrincipalName=" + value + ")(proxyAddresses=smtp:" + value + ")")
	}
	filter.WriteString("))")
	return filter.String()
}

func matchAccounts(emails []string, accounts []Account) []user {
	known := map[string]bool{}
	byAddress := map[string][]Account{}
	for _, candidate := range accounts {
		if known[candidate.SID] {
			continue
		}
		known[candidate.SID] = true
		addresses := map[string]bool{}
		for _, address := range append([]string{candidate.Mail, candidate.UPN}, candidate.Proxies...) {
			address = strings.ToLower(address)
			if address != "" && !addresses[address] {
				addresses[address] = true
				byAddress[address] = append(byAddress[address], candidate)
			}
		}
	}
	users := []user{}
	perEmail := map[string]int{}
	perSID := map[string]int{}
	for _, email := range emails {
		email = strings.ToLower(email)
		for _, candidate := range byAddress[email] {
			users = append(users, user{Email: email, SID: candidate.SID, GUID: candidate.GUID, UPN: candidate.UPN, Mail: candidate.Mail, Enabled: candidate.Enabled})
			perEmail[email]++
			perSID[candidate.SID]++
		}
	}
	for i := range users {
		users[i].Ambiguous = perEmail[users[i].Email] > 1 || perSID[users[i].SID] > 1
	}
	return users
}

func codeOf(err error) string {
	switch {
	case errors.Is(err, ErrDenied):
		return "denied"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrBusy):
		return "busy"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	}
	return "failed"
}

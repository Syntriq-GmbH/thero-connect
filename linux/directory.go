//go:build !windows

package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Syntriq-GmbH/thero-connect/core"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

const (
	maxSealed      = 16 << 20
	sealOverhead   = 60
	globalSecurity = 0x80000002
	localSecurity  = 0x80000004
)

var (
	kerberosOID      = []byte{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	userAttributes   = []string{"objectSid", "objectGUID", "primaryGroupID", "userAccountControl", "accountExpires", "tokenGroups", "tokenGroupsGlobalAndUniversal"}
	networkLogonSIDs = []string{"S-1-5-15", "S-1-5-1000", "S-1-5-64-10", "S-1-5-64-14", "S-1-5-64-21", "S-1-18-1", "S-1-18-2", "S-1-18-3", "S-1-18-4", "S-1-18-5", "S-1-18-6"}
)

type sealedConn struct {
	net.Conn
	client        *client.Client
	session       types.EncryptionKey
	authenticator types.Authenticator
	key           types.EncryptionKey
	send          uint64
	recv          uint64
	limit         int
	ready         bool
	on            atomic.Bool
	mu            sync.Mutex
	raw           []byte
	plain         []byte
}

func wrap(key types.EncryptionKey, data []byte, sequence uint64, seal bool) ([]byte, error) {
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	header := []byte{0x05, 0x04, 0x04, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(header[8:], sequence)
	if seal {
		header[2] |= 0x02
		_, sealed, err := etype.EncryptMessage(key.KeyValue, append(slices.Clone(data), header...), keyusage.GSSAPI_INITIATOR_SEAL)
		if err != nil {
			return nil, err
		}
		return append(header, sealed...), nil
	}
	checksum, err := etype.GetChecksumHash(key.KeyValue, append(slices.Clone(data), header...), keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(header[4:], uint16(len(checksum)))
	return append(append(header, data...), checksum...), nil
}

func unwrap(key types.EncryptionKey, token []byte, sequence uint64, sealed bool) ([]byte, error) {
	if len(token) < 16 || token[0] != 0x05 || token[1] != 0x04 || token[3] != 0xff {
		return nil, errors.New("ldap: invalid wrap token")
	}
	if token[2]&0x01 == 0 || token[2]&0x04 == 0 {
		return nil, errors.New("ldap: wrap token is not from the acceptor subkey")
	}
	if sealed && token[2]&0x02 == 0 {
		return nil, errors.New("ldap: unsealed message after sealing was negotiated")
	}
	if binary.BigEndian.Uint64(token[8:]) != sequence {
		return nil, errors.New("ldap: unexpected sequence number")
	}
	filler := int(binary.BigEndian.Uint16(token[4:]))
	body := token[16:]
	if len(body) > 0 {
		rotation := int(binary.BigEndian.Uint16(token[6:])) % len(body)
		body = append(slices.Clone(body[rotation:]), body[:rotation]...)
	}
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	if token[2]&0x02 != 0 {
		plain, err := etype.DecryptMessage(key.KeyValue, body, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return nil, fmt.Errorf("ldap: %w", err)
		}
		header := slices.Clone(token[:16])
		header[6], header[7] = 0, 0
		if len(plain) < filler+16 || !bytes.Equal(plain[len(plain)-16:], header) {
			return nil, errors.New("ldap: wrap token header mismatch")
		}
		return plain[:len(plain)-16-filler], nil
	}
	if len(body) < filler {
		return nil, errors.New("ldap: truncated wrap token")
	}
	header := slices.Clone(token[:16])
	clear(header[4:8])
	data := body[:len(body)-filler]
	if !etype.VerifyChecksum(key.KeyValue, append(slices.Clone(data), header...), body[len(body)-filler:], keyusage.GSSAPI_ACCEPTOR_SEAL) {
		return nil, errors.New("ldap: wrap token checksum mismatch")
	}
	return data, nil
}

func (c *sealedConn) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, nil)
}

func (c *sealedConn) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	if len(token) == 0 {
		ticket, key, err := c.client.GetServiceTicket(target)
		if err != nil {
			return nil, false, fmt.Errorf("%w: ticket %s: %v", core.ErrUnavailable, target, err)
		}
		authenticator, err := types.NewAuthenticator(c.client.Credentials.Domain(), c.client.Credentials.CName())
		if err != nil {
			return nil, false, err
		}
		etype, err := crypto.GetEtype(key.KeyType)
		if err != nil {
			return nil, false, err
		}
		if authenticator.SubKey, err = types.GenerateEncryptionKey(etype); err != nil {
			return nil, false, err
		}
		checksum := make([]byte, 24)
		binary.LittleEndian.PutUint32(checksum, 16)
		binary.LittleEndian.PutUint32(checksum[20:], 0x02|0x10|0x20)
		authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
		request, err := messages.NewAPReq(ticket, key, authenticator)
		if err != nil {
			return nil, false, err
		}
		types.SetFlag(&request.APOptions, flags.APOptionMutualRequired)
		encoded, err := request.Marshal()
		if err != nil {
			return nil, false, err
		}
		c.session, c.authenticator = key, authenticator
		framed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: append(append(slices.Clone(kerberosOID), 0x01, 0x00), encoded...)})
		return framed, true, err
	}
	var framed asn1.RawValue
	if _, err := asn1.Unmarshal(token, &framed); err != nil || framed.Class != asn1.ClassApplication || framed.Tag != 0 || !bytes.HasPrefix(framed.Bytes, append(slices.Clone(kerberosOID), 0x02, 0x00)) {
		return nil, false, errors.New("ldap: no kerberos AP-REP from the domain controller")
	}
	var reply messages.APRep
	if err := reply.Unmarshal(framed.Bytes[len(kerberosOID)+2:]); err != nil {
		return nil, false, err
	}
	if reply.DecryptEncPart(c.session) != nil && reply.DecryptEncPart(c.authenticator.SubKey) != nil {
		return nil, false, errors.New("ldap: AP-REP does not decrypt")
	}
	part := reply.DecryptedEncPart
	if part.CTime.Unix() != c.authenticator.CTime.Unix() || part.Cusec != c.authenticator.Cusec {
		return nil, false, errors.New("ldap: AP-REP time does not match the authenticator")
	}
	if len(part.Subkey.KeyValue) == 0 {
		return nil, false, errors.New("ldap: AP-REP has no acceptor subkey")
	}
	c.key = part.Subkey
	c.send = uint64(uint32(c.authenticator.SeqNumber))
	c.recv = uint64(uint32(part.SequenceNumber))
	return nil, false, nil
}

func (c *sealedConn) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	offer, err := unwrap(c.key, token, c.recv, false)
	if err != nil {
		return nil, err
	}
	if len(offer) != 4 || offer[0]&0x04 == 0 {
		return nil, errors.New("domain controller offers no LDAP sealing")
	}
	if c.limit = int(offer[1])<<16 | int(offer[2])<<8 | int(offer[3]) - sealOverhead; c.limit < 1 {
		return nil, errors.New("domain controller offers no usable LDAP buffer")
	}
	answer, err := wrap(c.key, []byte{0x04, 0x01, 0x00, 0x00}, c.send, false)
	if err != nil {
		return nil, err
	}
	c.send++
	c.recv++
	c.ready = true
	return answer, nil
}

func (c *sealedConn) DeleteSecContext() error {
	if c.ready {
		c.on.Store(true)
	}
	return nil
}

func (c *sealedConn) Write(p []byte) (int, error) {
	if !c.on.Load() {
		return c.Conn.Write(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for written := 0; written < len(p); {
		n := min(len(p)-written, c.limit)
		token, err := wrap(c.key, p[written:written+n], c.send, true)
		if err != nil {
			return written, err
		}
		c.send++
		if _, err := c.Conn.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(token))), token...)); err != nil {
			return written, err
		}
		written += n
	}
	return len(p), nil
}

func (c *sealedConn) Read(p []byte) (int, error) {
	fill := func(size int) error {
		if len(c.raw) >= size {
			return nil
		}
		more := make([]byte, size-len(c.raw))
		_, err := io.ReadFull(c.Conn, more)
		c.raw = append(c.raw, more...)
		return err
	}
	for len(c.plain) == 0 {
		if len(c.raw) == 0 {
			n, err := c.Conn.Read(p)
			if !c.on.Load() || n == 0 {
				return n, err
			}
			c.raw = append(c.raw, p[:n]...)
		}
		if err := fill(4); err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint32(c.raw))
		if size > maxSealed {
			return 0, errors.New("ldap: sealed message too large")
		}
		if err := fill(4 + size); err != nil {
			return 0, err
		}
		plain, err := unwrap(c.key, c.raw[4:4+size], c.recv, true)
		c.raw = c.raw[4+size:]
		if err != nil {
			return 0, err
		}
		c.recv++
		c.plain = plain
	}
	n := copy(p, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

func (s *linuxSource) bind(raw net.Conn, spn string) (*ldap.Conn, error) {
	sealed := &sealedConn{Conn: raw, client: s.ldap}
	conn := ldap.NewConn(sealed, false)
	conn.Start()
	conn.SetTimeout(30 * time.Second)
	err := conn.GSSAPIBind(sealed, spn, "")
	if err == nil && !sealed.on.Load() {
		err = errors.New("ldap: bind finished without a sealed security layer")
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *linuxSource) directory() (*ldap.Conn, string, error) {
	_, targets, err := net.LookupSRV("ldap", "tcp", "dc._msdcs."+s.domain)
	if err != nil {
		return nil, "", fmt.Errorf("%w: ldap: %v", core.ErrUnavailable, err)
	}
	var failures []error
	for _, target := range targets {
		name := strings.TrimSuffix(target.Target, ".")
		raw, err := net.DialTimeout("tcp", net.JoinHostPort(name, "389"), 10*time.Second)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		conn, err := s.bind(raw, "ldap/"+name+"/"+s.domain)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			continue
		}
		root, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil))
		if err != nil || len(root.Entries) != 1 || root.Entries[0].GetAttributeValue("defaultNamingContext") == "" {
			conn.Close()
			failures = append(failures, fmt.Errorf("%s: no default naming context: %v", name, err))
			continue
		}
		return conn, root.Entries[0].GetAttributeValue("defaultNamingContext"), nil
	}
	return nil, "", fmt.Errorf("%w: ldap: %v", core.ErrUnavailable, errors.Join(failures...))
}

func valuesOf(entry *ldap.Entry, names []string) map[string][][]byte {
	values := map[string][][]byte{}
	for _, name := range names {
		values[name] = entry.GetEqualFoldRawAttributeValues(name)
	}
	return values
}

func (s *linuxSource) Accounts(filter string) ([]core.Account, error) {
	conn, base, err := s.directory()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	result, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, filter, core.AccountAttributes, nil))
	if err != nil {
		return nil, fmt.Errorf("%w: ldap search: %v", core.ErrUnavailable, err)
	}
	now := time.Now()
	var found []core.Account
	for _, entry := range result.Entries {
		if account, ok := core.AccountOf(valuesOf(entry, core.AccountAttributes), now); ok {
			found = append(found, account)
		}
	}
	return found, nil
}

func (s *linuxSource) ownSID() (string, error) {
	s.mu.Lock()
	own := s.own
	s.mu.Unlock()
	if own != "" {
		return own, nil
	}
	conn, base, err := s.directory()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	result, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 30, false, "(sAMAccountName="+ldap.EscapeFilter(s.user)+")", []string{"objectSid"}, nil))
	if err != nil || len(result.Entries) != 1 {
		return "", fmt.Errorf("%w: own account %s not found: %v", core.ErrUnavailable, s.user, err)
	}
	own, _, err = core.SIDString(result.Entries[0].GetEqualFoldRawAttributeValue("objectSid"))
	if err != nil {
		return "", fmt.Errorf("%w: own account %s: %v", core.ErrUnavailable, s.user, err)
	}
	s.mu.Lock()
	s.own = own
	s.mu.Unlock()
	return own, nil
}

func (s *linuxSource) Members(sids []string) ([]core.Member, error) {
	conn, base, err := s.directory()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return s.members(conn, base, sids)
}

func (s *linuxSource) members(conn *ldap.Conn, base string, sids []string) ([]core.Member, error) {
	unavailable := func(err error) ([]core.Member, error) {
		return nil, fmt.Errorf("%w: ldap: %v", core.ErrUnavailable, err)
	}
	s.mu.Lock()
	domain, netbios := s.domainSID, s.netbios
	s.mu.Unlock()
	if domain == "" || netbios == "" {
		result, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", []string{"objectSid"}, nil))
		if err != nil || len(result.Entries) != 1 {
			return unavailable(fmt.Errorf("domain sid: %v", err))
		}
		if domain, _, err = core.SIDString(result.Entries[0].GetEqualFoldRawAttributeValue("objectSid")); err != nil {
			return unavailable(fmt.Errorf("domain sid: %v", err))
		}
		root, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", []string{"configurationNamingContext"}, nil))
		if err != nil || len(root.Entries) != 1 || root.Entries[0].GetAttributeValue("configurationNamingContext") == "" {
			return unavailable(fmt.Errorf("configuration naming context: %v", err))
		}
		partitions := "CN=Partitions," + root.Entries[0].GetAttributeValue("configurationNamingContext")
		found, err := conn.Search(ldap.NewSearchRequest(partitions, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 30, false, "(&(objectClass=crossRef)(nCName="+ldap.EscapeFilter(base)+"))", []string{"nETBIOSName"}, nil))
		if err != nil || len(found.Entries) != 1 || found.Entries[0].GetAttributeValue("nETBIOSName") == "" {
			return unavailable(fmt.Errorf("netbios name: %v", err))
		}
		netbios = found.Entries[0].GetAttributeValue("nETBIOSName")
		s.mu.Lock()
		s.domainSID, s.netbios = domain, netbios
		s.mu.Unlock()
	}
	members := make([]core.Member, len(sids))
	for k, sid := range sids {
		if !core.InDomain(sid, domain) || strings.ContainsFunc(sid[len(domain)+1:], func(r rune) bool { return r < '0' || r > '9' }) {
			continue
		}
		result, err := conn.Search(ldap.NewSearchRequest("<SID="+sid+">", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", core.MemberAttributes, nil))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			continue
		}
		if err != nil {
			return unavailable(fmt.Errorf("member %s: %v", sid, err))
		}
		if len(result.Entries) != 1 {
			continue
		}
		if member, ok := core.MemberOf(valuesOf(result.Entries[0], core.MemberAttributes), domain, netbios); ok && member.SID == strings.ToLower(sid) {
			members[k] = member
		}
	}
	return members, nil
}

func (s *linuxSource) facts(checked, denied []string) (string, []map[string][][]byte, map[string]bool, error) {
	unavailable := func(err error) (string, []map[string][][]byte, map[string]bool, error) {
		return "", nil, nil, fmt.Errorf("%w: ldap: %v", core.ErrUnavailable, err)
	}
	conn, base, err := s.directory()
	if err != nil {
		return "", nil, nil, err
	}
	defer conn.Close()
	result, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", []string{"objectSid"}, nil))
	if err != nil || len(result.Entries) != 1 {
		return unavailable(fmt.Errorf("domain sid: %v", err))
	}
	domain, _, err := core.SIDString(result.Entries[0].GetEqualFoldRawAttributeValue("objectSid"))
	if err != nil {
		return unavailable(fmt.Errorf("domain sid: %v", err))
	}
	users := make([]map[string][][]byte, len(checked))
	for k, sid := range checked {
		if !core.InDomain(sid, domain) {
			continue
		}
		result, err := conn.Search(ldap.NewSearchRequest("<SID="+sid+">", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 30, false, "(objectClass=*)", userAttributes, nil))
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			continue
		}
		if err != nil || len(result.Entries) != 1 {
			return unavailable(fmt.Errorf("user %s: %v", sid, err))
		}
		values := valuesOf(result.Entries[0], userAttributes)
		if len(values["tokenGroups"]) == 0 || len(values["tokenGroupsGlobalAndUniversal"]) == 0 {
			return unavailable(fmt.Errorf("user %s: tokenGroups not readable", sid))
		}
		users[k] = values
	}
	var candidates []string
	for _, sid := range denied {
		if core.InDomain(sid, domain) {
			candidates = append(candidates, sid)
		}
	}
	provable := map[string]bool{}
	for start := 0; start < len(candidates); start += 50 {
		var filter strings.Builder
		filter.WriteString("(|")
		for _, sid := range candidates[start:min(start+50, len(candidates))] {
			parts := strings.Split(sid, "-")
			authority, _ := strconv.ParseUint(parts[2], 10, 32)
			raw := binary.BigEndian.AppendUint32([]byte{1, byte(len(parts) - 3), 0, 0}, uint32(authority))
			for _, part := range parts[3:] {
				value, _ := strconv.ParseUint(part, 10, 32)
				raw = binary.LittleEndian.AppendUint32(raw, uint32(value))
			}
			filter.WriteString("(objectSid=")
			for _, b := range raw {
				fmt.Fprintf(&filter, `\%02x`, b)
			}
			filter.WriteString(")")
		}
		filter.WriteString(")")
		found, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, filter.String(), []string{"objectSid", "objectClass", "groupType", "distinguishedName"}, nil))
		if err != nil {
			return unavailable(fmt.Errorf("deny groups: %v", err))
		}
		for _, entry := range found.Entries {
			sid, _, err := core.SIDString(entry.GetEqualFoldRawAttributeValue("objectSid"))
			if err != nil {
				continue
			}
			value := entry.GetEqualFoldAttributeValue("groupType")
			groupType, err := strconv.ParseInt(value, 10, 32)
			isGroup := value != "" && err == nil
			classes := entry.GetEqualFoldAttributeValues("objectClass")
			switch {
			case value == "" && slices.ContainsFunc(classes, func(class string) bool { return strings.EqualFold(class, "user") }):
				provable[sid] = true
			case isGroup && uint32(groupType)&globalSecurity == globalSecurity:
				provable[sid] = true
			case isGroup && uint32(groupType)&localSecurity == localSecurity:
				members, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false, "(&(objectClass=foreignSecurityPrincipal)(memberOf:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(entry.DN)+"))", []string{"objectSid"}, nil))
				if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
					return unavailable(fmt.Errorf("deny group members: %v", err))
				}
				provable[sid] = err == nil && len(members.Entries) == 0
			}
		}
	}
	return domain, users, provable, nil
}

func bases(values map[string][][]byte, domain, account string) (map[string]bool, map[string]bool, bool) {
	objectSid, primary := values["objectSid"], values["primaryGroupID"]
	if len(objectSid) == 0 || len(primary) == 0 {
		return nil, nil, false
	}
	user, _, err := core.SIDString(objectSid[0])
	group, groupErr := strconv.ParseUint(string(primary[0]), 10, 32)
	if err != nil || groupErr != nil {
		return nil, nil, false
	}
	sure := map[string]bool{user: true, domain + "-" + strconv.FormatUint(group, 10): true, "S-1-1-0": true, "S-1-5-2": true, "S-1-5-11": true}
	possible := map[string]bool{}
	for _, sid := range networkLogonSIDs {
		possible[sid] = true
	}
	for _, set := range []struct {
		name   string
		target map[string]bool
	}{{"tokenGroupsGlobalAndUniversal", sure}, {"tokenGroups", possible}} {
		for _, raw := range values[set.name] {
			sid, _, err := core.SIDString(raw)
			if err != nil {
				return nil, nil, false
			}
			set.target[sid] = true
		}
	}
	for sid := range sure {
		possible[sid] = true
	}
	if possible[domain+"-512"] {
		possible["S-1-5-32-544"] = true
	}
	if possible[domain+"-513"] {
		possible["S-1-5-32-545"] = true
	}
	if possible[domain+"-514"] || possible[domain+"-501"] || possible[account+"-501"] || possible[account+"-514"] {
		possible["S-1-5-32-546"] = true
	}
	return sure, possible, true
}

func token(values map[string][][]byte, aliasesSure, aliasesPossible []string, samrOK bool, domain, account string, denied []string, provable map[string]bool) core.Token {
	user, ok := core.AccountOf(values, time.Now())
	sure, possible, parsed := bases(values, domain, account)
	if !ok || !parsed || !user.Enabled || !core.InDomain(user.SID, domain) {
		return core.Token{}
	}
	if samrOK {
		for _, sid := range append(slices.Clone(aliasesSure), aliasesPossible...) {
			possible[sid] = true
		}
		for _, sid := range aliasesSure {
			sure[sid] = true
		}
	}
	if len(possible) > 1015 {
		return core.Token{}
	}
	historyUnknown := false
	for _, raw := range values["tokenGroups"] {
		sid, _, _ := core.SIDString(raw)
		historyUnknown = historyUnknown || strings.HasPrefix(sid, "S-1-5-21-") && !core.InDomain(sid, domain)
	}
	absent := map[string]bool{}
	for _, sid := range denied {
		switch {
		case sid == "S-1-5-7":
			absent[sid] = true
		case strings.HasPrefix(sid, "S-1-5-32-") || account != domain && core.InDomain(sid, account):
			absent[sid] = samrOK && !possible[sid]
		case core.InDomain(sid, domain):
			absent[sid] = !historyUnknown && provable[sid] && !possible[sid]
		}
	}
	return core.Token{Sure: sure, Absent: absent}
}

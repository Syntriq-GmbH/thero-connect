//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Syntriq-GmbH/thero-connect/core"
	ldap "github.com/go-ldap/ldap/v3"
	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dcetypes"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	authzr "github.com/oiweiwei/go-msrpc/msrpc/raa/authzr/v0"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	pipes "github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/oiweiwei/gokrb5.fork/v9/keytab"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

const (
	statusAccessDenied       = 0xC0000022
	statusStoppedOnSymlink   = 0x8000002D
	statusNameNotFound       = 0xC0000034
	statusPathNotFound       = 0xC000003A
	statusNoSuchFile         = 0xC000000F
	statusBadNetworkName     = 0xC00000CC
	statusSharingViolation   = 0xC0000043
	statusFileLockConflict   = 0xC0000054
	statusLockNotGranted     = 0xC0000055
	statusNotADirectory      = 0xC0000103
	statusFileIsADirectory   = 0xC00000BA
	statusPathNotCovered     = 0xC0000257
	statusSessionExpired     = 0xC000035C
	statusSessionDeleted     = 0xC0000203
	statusNameDeleted        = 0xC00000C9
	statusNoMoreFiles        = 0x80000006
	statusEndOfFile          = 0xC0000011
	statusNotFound           = 0xC0000225
	statusFSDriverRequired   = 0xC000019C
	statusNotSupported       = 0xC00000BB
	statusInvalidDevice      = 0xC0000010
	attributeRecallOnOpen    = 0x40000
	attributeRecallOnAccess  = 0x400000
	callTimeout              = 60 * time.Second
	closeTimeout             = 10 * time.Second
	dialTimeout              = 10 * time.Second
	downTime                 = 2 * time.Minute
	readSize                 = 65536
	descriptorLimit          = 131228
	maximumAllowed           = 0x02000000
	serverTypeUnix           = 0x800
	directoryLookupAndAlias  = 0x280
	serverLookupAndEnumerate = 0x30
)

var (
	errSessionExpired = errors.New("smb session expired")
	errRetry          = errors.New("smb connection lost")
	principalPattern  = regexp.MustCompile(`^[^@\s]+@[A-Z0-9-]+(\.[A-Z0-9-]+)+$`)
	raaObject, _      = uuid.Parse("5fc860e0-6f6e-4fc2-83cd-46324f25e90b")
)

type linuxSource struct {
	user        string
	realm       string
	domain      string
	samba       map[string]bool
	smb         *auth.KerberosCredential
	krb         *krb5.Config
	ldap        *client.Client
	mu          sync.Mutex
	dialing     map[string]*sync.Mutex
	connections map[string]*connection
	down        map[string]time.Time
	own         string
	domainSID   string
	netbios     string
}

type connection struct {
	session *smb2.Session
	shares  map[string]*smb2.Share
}

type tree struct {
	source     *linuxSource
	server     string
	connection *connection
	share      *smb2.Share
	reused     bool
}

type dialer struct {
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

type linuxFile struct {
	tree tree
	id   wire.FileId
	read func(length uint32, offset uint64) ([]byte, error)
}

func krb5Config(realm string) string {
	return "[libdefaults]\n" +
		" default_realm = " + realm + "\n" +
		" dns_lookup_kdc = true\n" +
		" dns_lookup_realm = false\n" +
		" udp_preference_limit = 1\n" +
		" default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n" +
		" default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n" +
		" permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n"
}

func newSource(dir, principal string, samba map[string]bool) (core.Source, error) {
	os.Unsetenv("KRB5_CCACHE")
	if !principalPattern.MatchString(principal) {
		return nil, fmt.Errorf("principal %q must be user@REALM with an upper-case realm that contains a dot", principal)
	}
	user, realm, _ := strings.Cut(principal, "@")
	text := krb5Config(realm)
	parsed, err := config.NewFromString(text)
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp("", "thero-connect-krb5-*.conf")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(text)
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	keytabPath := filepath.Join(dir, "krb5.keytab")
	smbCredential, err := auth.NewKerberosCredential(auth.KerberosKeytab{ConfigFile: file.Name(), User: user, Realm: realm, File: keytabPath})
	if err != nil {
		return nil, fmt.Errorf("%w: kerberos: %v", core.ErrUnavailable, err)
	}
	keys, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("%w: kerberos: %v", core.ErrUnavailable, err)
	}
	ldapClient := client.NewWithKeytab(user, realm, keys, parsed, client.DisablePAFXFAST(true))
	if err := ldapClient.Login(); err != nil {
		return nil, fmt.Errorf("%w: kerberos: %v", core.ErrUnavailable, err)
	}
	return &linuxSource{
		user:        user,
		realm:       realm,
		domain:      strings.ToLower(realm),
		samba:       samba,
		smb:         smbCredential,
		krb:         &krb5.Config{KRB5Config: parsed, DCEStyle: true, DisablePAFXFAST: true},
		ldap:        ldapClient,
		dialing:     map[string]*sync.Mutex{},
		connections: map[string]*connection{},
		down:        map[string]time.Time{},
	}, nil
}

func splitPath(unc string) (string, string, string, error) {
	server, share, err := core.SplitUNC(unc)
	if err != nil {
		return "", "", "", err
	}
	if net.ParseIP(server) != nil || !strings.Contains(server, ".") {
		return "", "", "", fmt.Errorf("%w: %s: use the file server's fully qualified name", core.ErrUnavailable, server)
	}
	return server, share, strings.Join(strings.Split(unc, `\`)[4:], `\`), nil
}

func code(err error) uint32 {
	var response *protocol.ResponseError
	if errors.As(err, &response) {
		return response.Code
	}
	return 0
}

func statusError(err error) error {
	switch code(err) {
	case statusSessionExpired:
		return fmt.Errorf("%w: %w", core.ErrUnavailable, errSessionExpired)
	case 0, statusPathNotCovered, statusSessionDeleted, statusNameDeleted:
		return fmt.Errorf("%w: %v", core.ErrUnavailable, err)
	case statusAccessDenied, statusStoppedOnSymlink, statusNotADirectory, statusFileIsADirectory:
		return core.ErrDenied
	case statusNameNotFound, statusPathNotFound, statusNoSuchFile, statusBadNetworkName:
		return core.ErrNotFound
	case statusSharingViolation, statusFileLockConflict, statusLockNotGranted:
		return core.ErrBusy
	}
	return err
}

func dfsLink(attributes, tag uint32) bool {
	kind := attributes & (wire.FILE_ATTRIBUTE_DIRECTORY | wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_OFFLINE | attributeRecallOnOpen | attributeRecallOnAccess)
	return kind == wire.FILE_ATTRIBUTE_DIRECTORY|wire.FILE_ATTRIBUTE_REPARSE_POINT && tag == wire.IO_REPARSE_TAG_DFS
}

func filetime(value wire.FiletimeDecoder) time.Time {
	return core.Filetime(int64(uint64(value.HighDateTime())<<32 | uint64(value.LowDateTime())))
}

func (s *linuxSource) tree(ctx context.Context, unc string) (tree, string, error) {
	server, name, rel, err := splitPath(unc)
	if err != nil {
		return tree{}, "", err
	}
	if strings.EqualFold(server, s.domain) {
		return tree{}, "", fmt.Errorf("%w: smb %s: the domain name is never a file server", core.ErrUnavailable, server)
	}
	server, name = strings.ToLower(server), strings.ToLower(name)
	s.mu.Lock()
	if c := s.connections[server]; c != nil && c.shares[name] != nil {
		s.mu.Unlock()
		return tree{source: s, server: server, connection: c, share: c.shares[name], reused: true}, rel, nil
	}
	lock := s.dialing[server]
	if lock == nil {
		lock = &sync.Mutex{}
		s.dialing[server] = lock
	}
	s.mu.Unlock()
	lock.Lock()
	defer lock.Unlock()
	s.mu.Lock()
	c := s.connections[server]
	s.mu.Unlock()
	reused := c != nil
	if c == nil {
		dialer := smb2.Dialer{Credentials: s.smb, RequireMessageSigning: true, DisableAAPLExtension: true, SpecifiedDialects: []smb2.Dialect{smb2.SMB311, smb2.SMB302, smb2.SMB300}}
		session, err := dialer.Dial(ctx, server)
		if err != nil {
			return tree{}, "", fmt.Errorf("%w: smb %s: %v", core.ErrUnavailable, server, err)
		}
		c = &connection{session: session, shares: map[string]*smb2.Share{}}
		s.mu.Lock()
		s.connections[server] = c
		s.mu.Unlock()
	}
	t := tree{source: s, server: server, connection: c, reused: reused}
	s.mu.Lock()
	t.share = c.shares[name]
	s.mu.Unlock()
	if t.share != nil {
		return t, rel, nil
	}
	if t.share, err = c.session.Mount(ctx, name); err != nil {
		return tree{}, "", t.fail(err)
	}
	s.mu.Lock()
	c.shares[name] = t.share
	s.mu.Unlock()
	return t, rel, nil
}

func (t tree) fail(err error) error {
	status := code(err)
	err = statusError(err)
	if !errors.Is(err, core.ErrUnavailable) || status == statusPathNotCovered {
		return err
	}
	t.source.mu.Lock()
	if t.source.connections[t.server] == t.connection {
		delete(t.source.connections, t.server)
	}
	t.source.mu.Unlock()
	t.connection.session.Abort()
	if t.reused && status != statusSessionExpired {
		return fmt.Errorf("%w: %w", err, errRetry)
	}
	return err
}

func (t tree) create(ctx context.Context, name string, access, shareAccess, options uint32) (wire.FileId, uint32, error) {
	res, err := t.share.Request().Append(&wire.CreateRequest{
		ImpersonationLevel: wire.Impersonation,
		DesiredAccess:      access,
		ShareAccess:        shareAccess,
		CreateDisposition:  wire.FILE_OPEN,
		CreateOptions:      options,
		Name:               name,
	}).Do(ctx)
	if err != nil {
		return wire.FileId{}, 0, t.fail(err)
	}
	defer res.Close()
	created, err := res.Create(0)
	if err != nil {
		return wire.FileId{}, 0, err
	}
	return created.FileId().Decode(), created.FileAttributes(), nil
}

func (t tree) close(ctx context.Context, id wire.FileId) {
	if res, err := t.share.Request().WithFileID(id).Close().Do(ctx); err == nil {
		res.Close()
	}
}

func (t tree) hold(ctx context.Context, rel string) (func(), error) {
	var held []wire.FileId
	release := func() {
		for _, id := range held {
			t.close(ctx, id)
		}
	}
	if rel == "" {
		return release, nil
	}
	current := ""
	for _, part := range strings.Split(rel, `\`) {
		id, attributes, err := t.create(ctx, current, wire.FILE_READ_ATTRIBUTES|wire.SYNCHRONIZE, wire.FILE_SHARE_READ|wire.FILE_SHARE_WRITE, wire.FILE_DIRECTORY_FILE|wire.FILE_OPEN_REPARSE_POINT)
		if err != nil {
			release()
			return nil, err
		}
		held = append(held, id)
		if attributes&wire.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			release()
			return nil, core.ErrDenied
		}
		if attributes&wire.FILE_ATTRIBUTE_DIRECTORY == 0 {
			release()
			return nil, core.ErrNotFound
		}
		current = strings.TrimPrefix(current+`\`+part, `\`)
	}
	return release, nil
}

func (t tree) open(ctx context.Context, rel string, access, shareAccess, options uint32, directory bool) (wire.FileId, error) {
	release, err := t.hold(ctx, rel)
	if err != nil {
		return wire.FileId{}, err
	}
	defer release()
	id, attributes, err := t.create(ctx, rel, access, shareAccess, options|wire.FILE_OPEN_REPARSE_POINT)
	if err != nil {
		return wire.FileId{}, err
	}
	if attributes&wire.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (attributes&wire.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		t.close(ctx, id)
		return wire.FileId{}, core.ErrDenied
	}
	return id, nil
}

func (s *linuxSource) List(dir string) ([]core.Entry, error) {
	entries, err := s.list(dir)
	if errors.Is(err, errSessionExpired) || errors.Is(err, errRetry) {
		return s.list(dir)
	}
	return entries, err
}

func (s *linuxSource) list(dir string) ([]core.Entry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	t, rel, err := s.tree(ctx, dir)
	if err != nil {
		return nil, err
	}
	id, err := t.open(ctx, rel, wire.FILE_LIST_DIRECTORY|wire.FILE_READ_ATTRIBUTES|wire.SYNCHRONIZE, wire.FILE_SHARE_READ|wire.FILE_SHARE_WRITE|wire.FILE_SHARE_DELETE, wire.FILE_DIRECTORY_FILE, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		t.close(ctx, id)
	}()
	skipped := uint32(wire.FILE_ATTRIBUTE_REPARSE_POINT | wire.FILE_ATTRIBUTE_OFFLINE | attributeRecallOnOpen | attributeRecallOnAccess)
	var entries []core.Entry
	for {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		res, err := t.share.Request().WithFileID(id).QueryDir(wire.FileIdBothDirectoryInformation, "*", readSize).Do(ctx)
		cancel()
		if status := code(err); status == statusNoMoreFiles || status == statusNoSuchFile {
			return entries, nil
		}
		if err != nil {
			return nil, t.fail(err)
		}
		query, err := res.QueryDir(0)
		var items []wire.FileIdBothDirectoryInformationDecoder
		if err == nil {
			items, err = query.FileIdBothDirectoryInformation()
		}
		for _, item := range items {
			name := item.FileName()
			link := dfsLink(item.FileAttributes(), item.EaSize())
			if name == "." || name == ".." || item.FileAttributes()&skipped != 0 && !link {
				continue
			}
			entries = append(entries, core.Entry{
				Name:     name,
				Dir:      item.FileAttributes()&wire.FILE_ATTRIBUTE_DIRECTORY != 0,
				Link:     link,
				ID:       item.FileId(),
				Size:     item.EndOfFile(),
				Created:  filetime(item.CreationTime()),
				Modified: filetime(item.LastWriteTime()),
				Changed:  filetime(item.ChangeTime()),
			})
		}
		res.Close()
		if err != nil {
			return nil, err
		}
	}
}

func (s *linuxSource) Descriptor(path string) ([]byte, uint64, error) {
	sd, id, err := s.descriptor(path)
	if errors.Is(err, errSessionExpired) || errors.Is(err, errRetry) {
		return s.descriptor(path)
	}
	return sd, id, err
}

func (s *linuxSource) descriptor(path string) ([]byte, uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	t, rel, err := s.tree(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	release, err := t.hold(ctx, rel)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	request := t.share.Request().Append(&wire.CreateRequest{
		ImpersonationLevel: wire.Impersonation,
		DesiredAccess:      wire.READ_CONTROL | wire.FILE_READ_ATTRIBUTES,
		ShareAccess:        wire.FILE_SHARE_READ | wire.FILE_SHARE_WRITE | wire.FILE_SHARE_DELETE,
		CreateDisposition:  wire.FILE_OPEN,
		CreateOptions:      wire.FILE_OPEN_REPARSE_POINT | wire.FILE_NON_DIRECTORY_FILE,
		Name:               rel,
	}).WithFileID(wire.RelatedFileId).
		QueryInfo(wire.SMB2_0_INFO_SECURITY, 0, 0x01|0x02|0x04|0x10|0x40, readSize).
		QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileInternalInformation, 0, 8).
		Close()
	res, err := request.Do(ctx)
	if length, ok := protocol.RequiredBufferLength(err, 1); ok {
		request.Get(1).(*wire.QueryInfoRequest).OutputBufferLength = uint32(min(length, descriptorLimit))
		res, err = request.Do(ctx)
	}
	if err != nil {
		return nil, 0, t.fail(err)
	}
	defer res.Close()
	created, err := res.Create(0)
	if err != nil {
		return nil, 0, err
	}
	if created.FileAttributes()&wire.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, 0, core.ErrDenied
	}
	security, err := res.QueryInfo(1)
	if err != nil {
		return nil, 0, err
	}
	internal, err := res.QueryInfo(2)
	if err != nil {
		return nil, 0, err
	}
	id := wire.FileInternalInformationDecoder(internal.Output())
	if id.IsInvalid() {
		return nil, 0, errors.New("invalid file internal information")
	}
	return bytes.Clone(security.Output()), uint64(id.IndexNumber()), nil
}

func (s *linuxSource) Negotiate(spn string) (string, error) {
	fail := func(err error) (string, error) {
		return "", fmt.Errorf("%w: kerberos %s: %v", core.ErrUnavailable, spn, err)
	}
	if err := s.ldap.AffirmLogin(); err != nil {
		return fail(err)
	}
	request, err := spnego.SPNEGOClient(s.ldap, spn).InitSecContext()
	if err != nil {
		return fail(err)
	}
	token, err := request.Marshal()
	if err != nil {
		return fail(err)
	}
	if err := core.KerberosToken(token); err != nil {
		return fail(err)
	}
	return base64.StdEncoding.EncodeToString(token), nil
}

func (s *linuxSource) Open(root, rel string) (core.File, error) {
	file, err := s.open(root, rel)
	if errors.Is(err, errSessionExpired) || errors.Is(err, errRetry) {
		return s.open(root, rel)
	}
	return file, err
}

func (s *linuxSource) Referral(unc string) (core.Referral, error) {
	referral, err := s.referral(unc)
	if errors.Is(err, errSessionExpired) || errors.Is(err, errRetry) {
		return s.referral(unc)
	}
	return referral, err
}

func (s *linuxSource) referral(unc string) (core.Referral, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	host, share, _, err := splitPath(unc)
	if err != nil {
		return core.Referral{}, err
	}
	domain := strings.EqualFold(host, s.domain)
	request, servers := unc, []string{host}
	if domain {
		request = `\\` + host + `\` + share
		_, records, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+s.domain)
		if err != nil {
			return core.Referral{}, fmt.Errorf("%w: domain controllers of %s: %v", core.ErrUnavailable, s.domain, err)
		}
		conn, base, err := s.directory()
		if err != nil {
			return core.Referral{}, err
		}
		result, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", []string{"dNSHostName"}, nil))
		conn.Close()
		if err != nil {
			return core.Referral{}, fmt.Errorf("%w: domain controllers of %s: %v", core.ErrUnavailable, s.domain, err)
		}
		servers = nil
		for _, record := range records {
			name := strings.TrimSuffix(record.Target, ".")
			if slices.ContainsFunc(result.Entries, func(entry *ldap.Entry) bool { return strings.EqualFold(entry.GetAttributeValue("dNSHostName"), name) }) {
				servers = append(servers, name)
			}
		}
		if len(servers) == 0 {
			return core.Referral{}, fmt.Errorf("%w: no domain controller of %s is listed in the directory", core.ErrUnavailable, s.domain)
		}
	}
	var failures []error
	for _, server := range servers {
		key := strings.ToLower(server)
		s.mu.Lock()
		failed := s.down[key]
		s.mu.Unlock()
		if time.Since(failed) < downTime {
			failures = append(failures, fmt.Errorf("%w: smb %s: unreachable since %s", core.ErrUnavailable, server, failed.Format(time.RFC3339)))
			continue
		}
		dialing, cancel := context.WithTimeout(ctx, dialTimeout)
		t, _, err := s.tree(dialing, `\\`+server+`\IPC$`)
		cancel()
		if errors.Is(err, errSessionExpired) || errors.Is(err, errRetry) {
			return core.Referral{}, err
		}
		s.mu.Lock()
		if errors.Is(err, core.ErrUnavailable) {
			s.down[key] = time.Now()
		} else {
			delete(s.down, key)
		}
		s.mu.Unlock()
		if err != nil && !domain && !errors.Is(err, core.ErrUnavailable) {
			return core.Referral{}, core.ErrNotFound
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		res, err := dfs.NewClient(t.share).GetReferrals(ctx, request)
		switch status := code(err); status {
		case statusAccessDenied, statusNotFound, statusFSDriverRequired, statusNotSupported, statusInvalidDevice, statusPathNotFound:
			if domain {
				return core.Referral{}, fmt.Errorf("%w: referral %s: %v", core.ErrUnavailable, unc, err)
			}
			if status == statusAccessDenied {
				return core.Referral{}, core.ErrDenied
			}
			return core.Referral{}, core.ErrNotFound
		}
		if err != nil {
			err = t.fail(err)
			if errors.Is(err, errSessionExpired) || errors.Is(err, errRetry) {
				return core.Referral{}, err
			}
			failures = append(failures, fmt.Errorf("%s: %w", server, err))
			continue
		}
		if len(res.Entries) == 0 || slices.ContainsFunc(res.Entries, func(entry dfs.ReferralEntry) bool { return entry.Flags&dfs.FlagNameList != 0 }) {
			return core.Referral{}, fmt.Errorf("%w: referral %s: no usable target", core.ErrUnavailable, unc)
		}
		referral := core.Referral{Consumed: `\\` + strings.Trim(res.Prefix, `\`)}
		for i, entry := range res.Entries {
			if i == 0 || entry.Flags&dfs.FlagTargetSetBoundary != 0 {
				referral.Sets = append(referral.Sets, nil)
			}
			target := `\\` + strings.Trim(entry.NetworkAddress, `\`)
			if domain && strings.EqualFold(target, referral.Consumed) {
				return core.Referral{}, fmt.Errorf("%w: referral %s: the domain refers to itself", core.ErrUnavailable, unc)
			}
			referral.Sets[len(referral.Sets)-1] = append(referral.Sets[len(referral.Sets)-1], target)
		}
		return referral, nil
	}
	return core.Referral{}, fmt.Errorf("%w: referral %s: %v", core.ErrUnavailable, unc, errors.Join(failures...))
}

func (s *linuxSource) open(root, rel string) (core.File, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	t, rel, err := s.tree(ctx, root+`\`+rel)
	if err != nil {
		return nil, err
	}
	id, err := t.open(ctx, rel, wire.FILE_READ_DATA|wire.FILE_READ_ATTRIBUTES|wire.SYNCHRONIZE, wire.FILE_SHARE_READ|wire.FILE_SHARE_DELETE, wire.FILE_NON_DIRECTORY_FILE|wire.FILE_SEQUENTIAL_ONLY, false)
	if err != nil {
		return nil, err
	}
	read := func(length uint32, offset uint64) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		res, err := t.share.Request().WithFileID(id).Read(length, offset).Do(ctx)
		if code(err) == statusEndOfFile {
			return nil, io.EOF
		}
		if err != nil {
			return nil, t.fail(err)
		}
		defer res.Close()
		data, err := res.Read(0)
		if err != nil {
			return nil, err
		}
		return bytes.Clone(data.Data()), nil
	}
	return &linuxFile{tree: t, id: id, read: read}, nil
}

func (f *linuxFile) ReadAt(p []byte, off int64) (int, error) {
	done := 0
	for done < len(p) {
		length := min(len(p)-done, readSize)
		data, err := f.read(uint32(length), uint64(off)+uint64(done))
		done += copy(p[done:done+length], data)
		if err != nil {
			return done, err
		}
		if len(data) < length {
			return done, io.EOF
		}
	}
	return done, nil
}

func (f *linuxFile) Info() (core.FileInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	res, err := f.tree.share.Request().WithFileID(f.id).QueryInfo(wire.SMB2_0_INFO_FILE, wire.FileAllInformation, 0, readSize).Do(ctx)
	if err != nil {
		return core.FileInfo{}, f.tree.fail(err)
	}
	defer res.Close()
	query, err := res.QueryInfo(0)
	if err != nil {
		return core.FileInfo{}, err
	}
	all := wire.FileAllInformationDecoder(query.Output())
	if all.IsInvalid() {
		return core.FileInfo{}, errors.New("invalid file information")
	}
	return core.FileInfo{
		ID:       uint64(all.InternalInformation().IndexNumber()),
		Size:     all.StandardInformation().EndOfFile(),
		Modified: filetime(all.BasicInformation().LastWriteTime()),
	}, nil
}

func (f *linuxFile) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	f.tree.close(ctx, f.id)
	return nil
}

func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: callTimeout}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	d.conns = append(d.conns, conn)
	return conn, nil
}

func (d *dialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, conn := range d.conns {
		conn.Close()
	}
}

func (s *linuxSource) ticket(target string) (credential.CCache, error) {
	ticket, key, err := s.ldap.GetServiceTicket(target)
	if err != nil {
		return nil, fmt.Errorf("%w: kerberos %s: %v", core.ErrUnavailable, target, err)
	}
	raw, err := ticket.Marshal()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	client := credentials.Principal{Realm: s.realm, PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, s.user)}
	cache := &credentials.CCache{
		Version:          4,
		DefaultPrincipal: client,
		Credentials: []*credentials.Credential{{
			Client:    client,
			Server:    credentials.Principal{Realm: ticket.Realm, PrincipalName: ticket.SName},
			Key:       key,
			AuthTime:  now,
			StartTime: now.Add(-time.Minute),
			EndTime:   now.Add(time.Hour),
			Ticket:    raw,
		}},
	}
	return credential.NewFromCCache(s.user+"@"+s.realm, cache), nil
}

func (s *linuxSource) dial(ctx context.Context, address, target string, options ...dcerpc.Option) (dcerpc.Conn, func(), error) {
	cache, err := s.ticket(target)
	if err != nil {
		return nil, nil, err
	}
	network := &dialer{}
	context.AfterFunc(ctx, network.close)
	conn, err := dcerpc.Dial(ctx, address, append(options, dcerpc.WithDialer(network), dcerpc.WithTimeout(callTimeout), dcerpc.WithCredentials(cache), dcerpc.WithMechanism(ssp.SPNEGO), dcerpc.WithMechanism(ssp.KRB5, s.krb))...)
	if err != nil {
		network.close()
		return nil, nil, err
	}
	release := func() {
		timer := time.AfterFunc(closeTimeout, network.close)
		conn.Close(ctx)
		timer.Stop()
		network.close()
	}
	return conn, release, nil
}

func (s *linuxSource) pipe(ctx context.Context, server, name string) (dcerpc.Conn, func(), error) {
	if strings.EqualFold(server, s.domain) {
		return nil, nil, fmt.Errorf("%w: %s is the domain name, not a server", core.ErrUnavailable, server)
	}
	cache, err := s.ticket("cifs/" + server)
	if err != nil {
		return nil, nil, err
	}
	smb := pipes.NewDialer(pipes.WithSign(), pipes.WithSecurity(gssapi.WithCredential(cache), gssapi.WithMechanismFactory(ssp.SPNEGO), gssapi.WithMechanismFactory(ssp.KRB5, s.krb), gssapi.WithTargetName("cifs/"+server)))
	return s.dial(ctx, "ncacn_np:"+server+"["+name+"]", "cifs/"+server, dcerpc.WithSMBDialer(smb))
}

func (s *linuxSource) srvsvc(ctx context.Context, server string) (srvsvc.SrvsvcClient, func(), error) {
	conn, release, err := s.pipe(ctx, server, "srvsvc")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: srvsvc %s: %v", core.ErrUnavailable, server, err)
	}
	client, err := srvsvc.NewSrvsvcClient(ctx, conn, dcerpc.WithSeal(), dcerpc.WithTargetName("cifs/"+server))
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("%w: srvsvc %s: %v", core.ErrUnavailable, server, err)
	}
	return client, release, nil
}

func shareDescriptor(response *srvsvc.ShareGetInfoResponse, err error) ([]byte, error) {
	if response != nil && response.Return == 5 {
		return nil, core.ErrDenied
	}
	if response != nil && response.Return == 2310 {
		return nil, core.ErrNotFound
	}
	if response != nil && response.Return != 0 {
		return nil, fmt.Errorf("share info: error %d", response.Return)
	}
	if err != nil || response == nil {
		return nil, fmt.Errorf("%w: share info: %v", core.ErrUnavailable, err)
	}
	info, ok := response.Info.GetValue().(*srvsvc.ShareInfo502I)
	if !ok || info == nil || len(info.SecurityDescriptor) == 0 {
		return nil, errors.New("share has no security descriptor")
	}
	return bytes.Clone(info.SecurityDescriptor), nil
}

func withOwner(sd []byte) ([]byte, error) {
	if len(sd) < 20 || sd[0] != 1 || binary.LittleEndian.Uint16(sd[2:])&0x8000 == 0 {
		return nil, errors.New("invalid share descriptor")
	}
	if binary.LittleEndian.Uint32(sd[4:]) != 0 && binary.LittleEndian.Uint32(sd[8:]) != 0 {
		return sd, nil
	}
	administrators := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0}
	rebuilt := make([]byte, 20, 20+2*len(administrators))
	rebuilt[0] = 1
	binary.LittleEndian.PutUint16(rebuilt[2:], 0x8004)
	binary.LittleEndian.PutUint32(rebuilt[4:], 20)
	binary.LittleEndian.PutUint32(rebuilt[8:], 36)
	rebuilt = append(append(rebuilt, administrators...), administrators...)
	offset := int(binary.LittleEndian.Uint32(sd[16:]))
	if binary.LittleEndian.Uint16(sd[2:])&0x4 == 0 || offset == 0 {
		return rebuilt, nil
	}
	if offset+8 > len(sd) || offset+int(binary.LittleEndian.Uint16(sd[offset+2:])) > len(sd) {
		return nil, errors.New("acl outside share descriptor")
	}
	binary.LittleEndian.PutUint32(rebuilt[16:], uint32(len(rebuilt)))
	return append(rebuilt, sd[offset:offset+int(binary.LittleEndian.Uint16(sd[offset+2:]))]...), nil
}

func (s *linuxSource) Share(root string) ([]byte, error) {
	server, name, _, err := splitPath(root)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	client, release, err := s.srvsvc(ctx, server)
	if err != nil {
		return nil, err
	}
	defer release()
	sd, err := shareDescriptor(client.ShareGetInfo(ctx, &srvsvc.ShareGetInfoRequest{ServerName: server, NetName: name, Level: 502}))
	if err != nil {
		return nil, err
	}
	return withOwner(sd)
}

func announced(response *srvsvc.GetInfoResponse, err error) error {
	if response != nil && response.Return == 0 && err == nil {
		if info, ok := response.Info.GetValue().(*dtyp.ServerInfo101); ok && info != nil && info.VersionType&serverTypeUnix != 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: server: samba, but the server does not announce Samba (%v)", core.ErrUnavailable, err)
}

func (s *linuxSource) Allowed(server string, sids []string, descriptors [][]byte) ([][]bool, error) {
	if strings.EqualFold(server, s.domain) {
		return nil, fmt.Errorf("%w: %s is the domain name, not a server", core.ErrUnavailable, server)
	}
	checked := sids
	if len(sids) == 0 {
		own, err := s.ownSID()
		if err != nil {
			return nil, err
		}
		checked = []string{own}
	}
	evaluate := s.authz
	if s.samba[strings.ToLower(server)] {
		evaluate = s.evaluate
	}
	matrix, err := evaluate(server, checked, descriptors)
	if err != nil {
		return nil, err
	}
	return matrix[:len(sids)], nil
}

func (s *linuxSource) authz(server string, checked []string, descriptors [][]byte) ([][]bool, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unavailable := func(err error) error {
		return fmt.Errorf("%w: authz %s: %v", core.ErrUnavailable, server, err)
	}
	mapperConn, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+server+"[135]", dcerpc.WithTimeout(callTimeout))
	if err != nil {
		return nil, unavailable(err)
	}
	mapper, err := epm.NewEpmClient(ctx, mapperConn, dcerpc.WithInsecure())
	var found *epm.LookupResponse
	if err == nil {
		found, err = mapper.Lookup(ctx, &epm.LookupRequest{
			InquiryType: 1,
			VersOption:  3,
			InterfaceID: &dcetypes.InterfaceID{UUID: dtyp.GUIDFromUUID(authzr.AuthzrSyntaxUUID)},
			MaxEntries:  500,
		})
	}
	mapperConn.Close(ctx)
	if err != nil {
		return nil, unavailable(err)
	}
	endpoint := ""
	for _, entry := range found.Entries {
		if entry != nil && entry.Tower != nil && entry.Tower.Binding().StringBinding.ProtocolSequence == dcerpc.ProtocolSequenceIPTCP {
			endpoint = entry.Tower.Binding().StringBinding.Endpoint
			break
		}
	}
	if endpoint == "" {
		return nil, unavailable(errors.New("no tcp endpoint for the authz interface"))
	}
	conn, release, err := s.dial(ctx, "ncacn_ip_tcp:"+server+"["+endpoint+"]", "host/"+server)
	if err != nil {
		return nil, unavailable(err)
	}
	defer release()
	client, err := authzr.NewAuthzrClient(ctx, conn, dcerpc.WithSeal(), dcerpc.WithTargetName("host/"+server))
	if err != nil {
		return nil, unavailable(err)
	}
	matrix := make([][]bool, len(checked))
	for i, value := range checked {
		matrix[i] = make([]bool, len(descriptors))
		sid, err := dtyp.ParseSID(value)
		if err != nil {
			continue
		}
		handle, err := client.InitializeContextFromSID(ctx, &authzr.InitializeContextFromSIDRequest{SID: sid, ID: &dtyp.LUID{}}, dcerpc.WithObjectUUID(raaObject))
		if handle != nil && handle.Return == 5 {
			return nil, core.ErrDenied
		}
		if handle != nil && handle.Return != 0 {
			continue
		}
		if err != nil || handle == nil {
			return nil, unavailable(err)
		}
		for j, sd := range descriptors {
			if len(sd) == 0 {
				continue
			}
			check, err := client.AccessCheck(ctx, &authzr.AccessCheckRequest{
				ContextHandle:           handle.ContextHandle,
				Request:                 &authzr.AccessRequest{DesiredAccess: maximumAllowed},
				SecurityDescriptorCount: 1,
				SecurityDescriptors:     []*authzr.SelfRelativeSecurityDescriptor{{Length: uint32(len(sd)), SelfRelativeSecurityDescriptor: sd}},
				Reply:                   &authzr.AccessReply{ResultListLength: 1},
			}, dcerpc.WithObjectUUID(raaObject))
			if check != nil && check.Return == 5 {
				return nil, core.ErrDenied
			}
			if check == nil {
				return nil, unavailable(err)
			}
			reply := check.Reply
			matrix[i][j] = check.Return == 0 && reply != nil && len(reply.Error) == 1 && reply.Error[0] == 0 && len(reply.GrantedAccessMask) == 1 && reply.GrantedAccessMask[0]&0x1 != 0
		}
		client.FreeContext(ctx, &authzr.FreeContextRequest{ContextHandle: handle.ContextHandle}, dcerpc.WithObjectUUID(raaObject))
	}
	return matrix, nil
}

func (s *linuxSource) evaluate(server string, checked []string, descriptors [][]byte) ([][]bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	client, release, err := s.srvsvc(ctx, server)
	if err != nil {
		return nil, err
	}
	err = announced(client.GetInfo(ctx, &srvsvc.GetInfoRequest{ServerName: server, Level: 101}))
	release()
	if err != nil {
		return nil, err
	}
	denied := core.DeniedSIDs(descriptors)
	domain, users, provable, err := s.facts(checked, denied)
	if err != nil {
		return nil, err
	}
	account, aliasesSure, aliasesPossible, samrOK := s.aliases(ctx, server, domain, users)
	matrix := make([][]bool, len(checked))
	for k := range checked {
		matrix[k] = make([]bool, len(descriptors))
		if users[k] == nil {
			continue
		}
		t := token(users[k], aliasesSure[k], aliasesPossible[k], samrOK, domain, account, denied, provable)
		for j, sd := range descriptors {
			matrix[k][j] = core.Grants(t, sd)
		}
	}
	return matrix, nil
}

func (s *linuxSource) aliases(ctx context.Context, server, domain string, users []map[string][][]byte) (string, [][]string, [][]string, bool) {
	sure := make([][]string, len(users))
	possible := make([][]string, len(users))
	refused := func(step string, err error) (string, [][]string, [][]string, bool) {
		slog.Warn("samr refused, local and builtin groups unknown", "server", server, "step", step, "error", err)
		return "", sure, possible, false
	}
	conn, release, err := s.pipe(ctx, server, "samr")
	if err != nil {
		return refused("dial", err)
	}
	defer release()
	client, err := samr.NewSamrClient(ctx, conn, dcerpc.WithSeal(), dcerpc.WithTargetName("cifs/"+server))
	if err != nil {
		return refused("bind", err)
	}
	connected, err := client.Connect5(ctx, &samr.Connect5Request{ServerName: server, DesiredAccess: serverLookupAndEnumerate, InVersion: 1, InRevisionInfo: &samr.RevisionInfo{Value: &samr.RevisionInfo_V1{V1: &samr.RevisionInfoV1{Revision: 3}}}})
	if err != nil {
		return refused("connect", err)
	}
	listed, err := client.EnumerateDomainsInSAMServer(ctx, &samr.EnumerateDomainsInSAMServerRequest{Server: connected.Server, PreferredMaximumLength: 0xffff})
	if err != nil || listed.Buffer == nil {
		return refused("enumerate", err)
	}
	var name *dtyp.UnicodeString
	for _, entry := range listed.Buffer.Buffer {
		if entry != nil && entry.Name != nil && !strings.EqualFold(entry.Name.Buffer, "Builtin") {
			name = entry.Name
		}
	}
	if name == nil {
		return refused("enumerate", errors.New("no account domain"))
	}
	found, err := client.LookupDomainInSAMServer(ctx, &samr.LookupDomainInSAMServerRequest{Server: connected.Server, Name: name})
	if err != nil || found.DomainID == nil {
		return refused("lookup", err)
	}
	account := found.DomainID.String()
	builtin, _ := dtyp.ParseSID("S-1-5-32")
	var handles []*samr.Handle
	for _, id := range []*dtyp.SID{found.DomainID, builtin} {
		opened, err := client.OpenDomain(ctx, &samr.OpenDomainRequest{Server: connected.Server, DesiredAccess: directoryLookupAndAlias, DomainID: id})
		if err != nil {
			return refused("open", err)
		}
		handles = append(handles, opened.Domain)
	}
	for k, values := range users {
		if values == nil {
			continue
		}
		sureBase, possibleBase, ok := bases(values, domain, account)
		if !ok || len(possibleBase) > 1015 {
			continue
		}
		for _, set := range []struct {
			base   map[string]bool
			target *[]string
		}{{sureBase, &sure[k]}, {possibleBase, &possible[k]}} {
			var array samr.SIDArray
			for sid := range set.base {
				parsed, err := dtyp.ParseSID(sid)
				if err != nil {
					return refused("sid", err)
				}
				array.SIDs = append(array.SIDs, &samr.SIDInformation{SIDPointer: parsed})
			}
			array.Count = uint32(len(array.SIDs))
			for i, prefix := range []string{account, "S-1-5-32"} {
				membership, err := client.GetAliasMembership(ctx, &samr.GetAliasMembershipRequest{Domain: handles[i], SIDArray: &array})
				if err != nil || membership.Membership == nil {
					return refused("aliases", err)
				}
				for _, rid := range membership.Membership.Element {
					sid := fmt.Sprintf("%s-%d", prefix, rid)
					*set.target = append(*set.target, sid)
					parsed, err := dtyp.ParseSID(sid)
					if err != nil {
						return refused("sid", err)
					}
					array.SIDs = append(array.SIDs, &samr.SIDInformation{SIDPointer: parsed})
				}
				array.Count = uint32(len(array.SIDs))
			}
		}
	}
	return account, sure, possible, true
}

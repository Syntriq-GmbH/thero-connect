package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsSource struct{}

type windowsFile struct {
	*os.File
}

type fileIDBothDirInfo struct {
	nextEntryOffset uint32
	fileIndex       uint32
	creationTime    int64
	lastAccessTime  int64
	lastWriteTime   int64
	changeTime      int64
	endOfFile       int64
	allocationSize  int64
	fileAttributes  uint32
	fileNameLength  uint32
	eaSize          uint32
	shortNameLength uint8
	shortName       [12]uint16
	fileID          int64
	fileName        [1]uint16
}

type shareInfo502 struct {
	netname            *uint16
	shareType          uint32
	remark             *uint16
	permissions        uint32
	maxUses            uint32
	currentUses        uint32
	path               *uint16
	passwd             *uint16
	reserved           uint32
	securityDescriptor *windows.SECURITY_DESCRIPTOR
}

type authzRPCInitInfoClient struct {
	version     uint16
	objectUUID  *uint16
	protSeq     *uint16
	networkAddr *uint16
	endpoint    *uint16
	options     *uint16
	serverSpn   *uint16
}

type authzAccessRequest struct {
	desiredAccess        uint32
	principalSelfSid     *windows.SID
	objectTypeList       uintptr
	objectTypeListLength uint32
	optionalArguments    uintptr
}

type authzAccessReply struct {
	resultListLength      uint32
	grantedAccessMask     *uint32
	saclEvaluationResults *uint32
	errors                *uint32
}

type berval struct {
	length uint32
	value  *byte
}

const (
	ldapOptReferrals       = 0x08
	ldapOptProtocolVersion = 0x11
	ldapOptSign            = 0x95
	ldapOptEncrypt         = 0x96
	ldapAuthNegotiate      = 0x0486
	ldapScopeBase          = 0
	ldapScopeSubtree       = 2
)

var (
	netapi32                                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetShareGetInfo                      = netapi32.NewProc("NetShareGetInfo")
	authz                                    = windows.NewLazySystemDLL("authz.dll")
	procAuthzInitializeRemoteResourceManager = authz.NewProc("AuthzInitializeRemoteResourceManager")
	procAuthzInitializeContextFromSid        = authz.NewProc("AuthzInitializeContextFromSid")
	procAuthzAccessCheck                     = authz.NewProc("AuthzAccessCheck")
	procAuthzFreeContext                     = authz.NewProc("AuthzFreeContext")
	procAuthzFreeResourceManager             = authz.NewProc("AuthzFreeResourceManager")
	wldap32                                  = windows.NewLazySystemDLL("wldap32.dll")
	procLdapInit                             = wldap32.NewProc("ldap_initW")
	procLdapSetOption                        = wldap32.NewProc("ldap_set_optionW")
	procLdapBind                             = wldap32.NewProc("ldap_bind_sW")
	procLdapSearch                           = wldap32.NewProc("ldap_search_sW")
	procLdapFirstEntry                       = wldap32.NewProc("ldap_first_entry")
	procLdapNextEntry                        = wldap32.NewProc("ldap_next_entry")
	procLdapGetValuesLen                     = wldap32.NewProc("ldap_get_values_lenW")
	procLdapCountValuesLen                   = wldap32.NewProc("ldap_count_values_len")
	procLdapValueFreeLen                     = wldap32.NewProc("ldap_value_free_len")
	procLdapMsgFree                          = wldap32.NewProc("ldap_msgfree")
	procLdapUnbind                           = wldap32.NewProc("ldap_unbind")
)

func sentinel(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return errDenied
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND), errors.Is(err, windows.ERROR_BAD_NET_NAME):
		return errNotFound
	case errors.Is(err, windows.ERROR_SHARING_VIOLATION), errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return errBusy
	}
	return err
}

func authzFailure(server string, err error) error {
	switch {
	case errors.Is(err, windows.RPC_S_SERVER_UNAVAILABLE), errors.Is(err, windows.EPT_S_NOT_REGISTERED), errors.Is(err, windows.RPC_S_CALL_FAILED), errors.Is(err, windows.RPC_S_CALL_FAILED_DNE):
		return fmt.Errorf("%w: authz %s: %v", errUnavailable, server, err)
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return errDenied
	}
	return nil
}

func longPath(path string) (*uint16, error) {
	return windows.UTF16PtrFromString(`\\?\UNC\` + strings.TrimPrefix(path, `\\`))
}

func openHandle(path string, access, share, flags uint32) (windows.Handle, error) {
	name, err := longPath(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, sentinel(err)
	}
	return handle, nil
}

func attributesOf(handle windows.Handle) (uint32, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, sentinel(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return 0, errDenied
	}
	return info.FileAttributes, nil
}

func openInShare(path string, access, share, flags uint32, directory bool) (windows.Handle, error) {
	server, name, err := splitUNC(path)
	if err != nil {
		return 0, err
	}
	current := `\\` + server + `\` + name
	var held []windows.Handle
	defer func() {
		for _, handle := range held {
			windows.CloseHandle(handle)
		}
	}()
	for _, part := range strings.Split(path, `\`)[4:] {
		parent, err := openHandle(current, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_FLAG_BACKUP_SEMANTICS)
		if err != nil {
			return 0, err
		}
		held = append(held, parent)
		attributes, err := attributesOf(parent)
		if err != nil {
			return 0, err
		}
		if attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return 0, errNotFound
		}
		current += `\` + part
	}
	handle, err := openHandle(current, access, share, flags)
	if err != nil {
		return 0, err
	}
	attributes, err := attributesOf(handle)
	if err == nil && (attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		err = errDenied
	}
	if err != nil {
		windows.CloseHandle(handle)
		return 0, err
	}
	return handle, nil
}

func filetime(value int64) time.Time {
	since := value - 116444736000000000
	return time.Unix(since/10000000, since%10000000*100)
}

func securityBytes(sd *windows.SECURITY_DESCRIPTOR) []byte {
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length()))
}

func (windowsSource) list(dir string) ([]entry, error) {
	handle, err := openInShare(dir, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_FLAG_BACKUP_SEMANTICS, true)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	skipped := uint32(windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_OFFLINE | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN | windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
	buffer := make([]uint64, 8192)
	var entries []entry
	for {
		err := windows.GetFileInformationByHandleEx(handle, windows.FileIdBothDirectoryInfo, (*byte)(unsafe.Pointer(&buffer[0])), uint32(len(buffer)*8))
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return entries, nil
		}
		if err != nil {
			return nil, sentinel(err)
		}
		for offset := uintptr(0); ; {
			info := (*fileIDBothDirInfo)(unsafe.Add(unsafe.Pointer(&buffer[0]), offset))
			name := windows.UTF16ToString(unsafe.Slice(&info.fileName[0], info.fileNameLength/2))
			if name != "." && name != ".." && info.fileAttributes&skipped == 0 {
				entries = append(entries, entry{
					name:     name,
					dir:      info.fileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0,
					id:       uint64(info.fileID),
					size:     info.endOfFile,
					created:  filetime(info.creationTime),
					modified: filetime(info.lastWriteTime),
					changed:  filetime(info.changeTime),
				})
			}
			if info.nextEntryOffset == 0 {
				break
			}
			offset += uintptr(info.nextEntryOffset)
		}
	}
}

func (windowsSource) descriptor(path string) ([]byte, error) {
	handle, err := openInShare(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_FLAG_BACKUP_SEMANTICS, false)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	var parts windows.SECURITY_INFORMATION = windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.SCOPE_SECURITY_INFORMATION | windows.LABEL_SECURITY_INFORMATION
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, parts)
	if err != nil {
		return nil, sentinel(err)
	}
	return securityBytes(sd), nil
}

func (windowsSource) share(root string) ([]byte, error) {
	server, name, err := splitUNC(root)
	if err != nil {
		return nil, err
	}
	serverName, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return nil, err
	}
	shareName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var info *shareInfo502
	status, _, _ := procNetShareGetInfo.Call(uintptr(unsafe.Pointer(serverName)), uintptr(unsafe.Pointer(shareName)), 502, uintptr(unsafe.Pointer(&info)))
	if status == 5 {
		return nil, errDenied
	}
	if status == 2310 {
		return nil, errNotFound
	}
	if status != 0 {
		return nil, windows.Errno(status)
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(info)))
	sd := info.securityDescriptor
	if sd == nil {
		return nil, errors.New("share has no security descriptor")
	}
	owner, _, _ := sd.Owner()
	group, _, _ := sd.Group()
	if owner != nil && group != nil {
		return securityBytes(sd), nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	rebuilt, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := errors.Join(rebuilt.SetOwner(administrators, false), rebuilt.SetGroup(administrators, false), rebuilt.SetDACL(dacl, true, false)); err != nil {
		return nil, err
	}
	relative, err := rebuilt.ToSelfRelative()
	if err != nil {
		return nil, err
	}
	return securityBytes(relative), nil
}

func (windowsSource) accounts(filter string) ([]account, error) {
	connection, _, err := procLdapInit.Call(0, 389)
	if connection == 0 {
		return nil, fmt.Errorf("%w: ldap init: %v", errUnavailable, err)
	}
	defer procLdapUnbind.Call(connection)
	version, off, on := uint32(3), uint32(0), uint32(1)
	options := []struct {
		option uintptr
		value  *uint32
	}{{ldapOptProtocolVersion, &version}, {ldapOptReferrals, &off}, {ldapOptSign, &on}, {ldapOptEncrypt, &on}}
	for _, item := range options {
		if code, _, _ := procLdapSetOption.Call(connection, item.option, uintptr(unsafe.Pointer(item.value))); code != 0 {
			return nil, fmt.Errorf("%w: ldap option %#x: %d", errUnavailable, item.option, code)
		}
	}
	if code, _, _ := procLdapBind.Call(connection, 0, 0, ldapAuthNegotiate); code != 0 {
		return nil, fmt.Errorf("%w: ldap bind: %d", errUnavailable, code)
	}
	rootDSE, err := ldapSearch(connection, "", ldapScopeBase, "(objectClass=*)", []string{"defaultNamingContext"})
	if err != nil {
		return nil, err
	}
	if len(rootDSE) == 0 || len(rootDSE[0]["defaultNamingContext"]) == 0 {
		return nil, fmt.Errorf("%w: no default naming context", errUnavailable)
	}
	base := string(rootDSE[0]["defaultNamingContext"][0])
	results, err := ldapSearch(connection, base, ldapScopeSubtree, filter, []string{"objectSid", "objectGUID", "userPrincipalName", "mail", "proxyAddresses", "userAccountControl", "accountExpires"})
	if err != nil {
		return nil, err
	}
	first := func(values map[string][][]byte, name string) string {
		if list := values[name]; len(list) > 0 {
			return string(list[0])
		}
		return ""
	}
	now := time.Now().UnixNano()/100 + 116444736000000000
	var found []account
	for _, values := range results {
		sid, _, err := sidString([]byte(first(values, "objectSid")))
		guid := []byte(first(values, "objectGUID"))
		if err != nil || len(guid) != 16 {
			continue
		}
		var proxies []string
		for _, proxy := range values["proxyAddresses"] {
			if len(proxy) > 5 && strings.EqualFold(string(proxy[:5]), "smtp:") {
				proxies = append(proxies, strings.ToLower(string(proxy[5:])))
			}
		}
		control, err := strconv.ParseUint(first(values, "userAccountControl"), 10, 32)
		enabled := err == nil && control&2 == 0
		if value := first(values, "accountExpires"); value != "" {
			expires, err := strconv.ParseInt(value, 10, 64)
			enabled = enabled && err == nil && (expires == 0 || expires == math.MaxInt64 || expires > now)
		}
		found = append(found, account{
			sid:     sid,
			guid:    fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(guid[0:4]), binary.LittleEndian.Uint16(guid[4:6]), binary.LittleEndian.Uint16(guid[6:8]), guid[8:10], guid[10:16]),
			upn:     first(values, "userPrincipalName"),
			mail:    first(values, "mail"),
			proxies: proxies,
			enabled: enabled,
		})
	}
	return found, nil
}

func ldapSearch(connection uintptr, base string, scope uintptr, filter string, attributes []string) ([]map[string][][]byte, error) {
	basePointer, err := windows.UTF16PtrFromString(base)
	if err != nil {
		return nil, err
	}
	filterPointer, err := windows.UTF16PtrFromString(filter)
	if err != nil {
		return nil, err
	}
	names := make([]*uint16, len(attributes)+1)
	for i, attribute := range attributes {
		if names[i], err = windows.UTF16PtrFromString(attribute); err != nil {
			return nil, err
		}
	}
	var result uintptr
	code, _, _ := procLdapSearch.Call(connection, uintptr(unsafe.Pointer(basePointer)), scope, uintptr(unsafe.Pointer(filterPointer)), uintptr(unsafe.Pointer(&names[0])), 0, uintptr(unsafe.Pointer(&result)))
	if result != 0 {
		defer procLdapMsgFree.Call(result)
	}
	if code != 0 {
		return nil, fmt.Errorf("%w: ldap search: %d", errUnavailable, code)
	}
	var results []map[string][][]byte
	for item, _, _ := procLdapFirstEntry.Call(connection, result); item != 0; item, _, _ = procLdapNextEntry.Call(connection, item) {
		values := map[string][][]byte{}
		for i, attribute := range attributes {
			list, _, _ := procLdapGetValuesLen.Call(connection, item, uintptr(unsafe.Pointer(names[i])))
			if list == 0 {
				continue
			}
			count, _, _ := procLdapCountValuesLen.Call(list)
			for _, value := range unsafe.Slice(*(***berval)(unsafe.Pointer(&list)), count) {
				values[attribute] = append(values[attribute], bytes.Clone(unsafe.Slice(value.value, value.length)))
			}
			procLdapValueFreeLen.Call(list)
		}
		results = append(results, values)
	}
	return results, nil
}

func (windowsSource) allowed(server string, sids []string, descriptors [][]byte) ([][]bool, error) {
	uuid, err := windows.UTF16PtrFromString("5fc860e0-6f6e-4fc2-83cd-46324f25e90b")
	if err != nil {
		return nil, err
	}
	protocol, err := windows.UTF16PtrFromString("ncacn_ip_tcp")
	if err != nil {
		return nil, err
	}
	address, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return nil, err
	}
	rpc := authzRPCInitInfoClient{version: 1, objectUUID: uuid, protSeq: protocol, networkAddr: address}
	var manager uintptr
	if ok, _, err := procAuthzInitializeRemoteResourceManager.Call(uintptr(unsafe.Pointer(&rpc)), uintptr(unsafe.Pointer(&manager))); ok == 0 {
		if failure := authzFailure(server, err); failure != nil {
			return nil, failure
		}
		return nil, err
	}
	defer procAuthzFreeResourceManager.Call(manager)
	checked := sids
	if len(sids) == 0 {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, err
		}
		checked = []string{user.User.Sid.String()}
	}
	matrix := make([][]bool, len(checked))
	for i, value := range checked {
		matrix[i] = make([]bool, len(descriptors))
		sid, err := windows.StringToSid(value)
		if err != nil {
			continue
		}
		var context uintptr
		if ok, _, err := procAuthzInitializeContextFromSid.Call(0, uintptr(unsafe.Pointer(sid)), manager, 0, 0, 0, uintptr(unsafe.Pointer(&context))); ok == 0 {
			if failure := authzFailure(server, err); failure != nil {
				return nil, failure
			}
			continue
		}
		for j, sd := range descriptors {
			if len(sd) == 0 {
				continue
			}
			request := authzAccessRequest{desiredAccess: windows.MAXIMUM_ALLOWED}
			var granted, sacl, status uint32
			reply := authzAccessReply{resultListLength: 1, grantedAccessMask: &granted, saclEvaluationResults: &sacl, errors: &status}
			ok, _, err := procAuthzAccessCheck.Call(0, context, uintptr(unsafe.Pointer(&request)), 0, uintptr(unsafe.Pointer(&sd[0])), 0, 0, uintptr(unsafe.Pointer(&reply)), 0)
			if failure := authzFailure(server, err); ok == 0 && failure != nil {
				procAuthzFreeContext.Call(context)
				return nil, failure
			}
			matrix[i][j] = ok != 0 && status == 0 && granted&windows.FILE_READ_DATA != 0
		}
		procAuthzFreeContext.Call(context)
	}
	return matrix[:len(sids)], nil
}

func (windowsSource) open(root, rel string) (file, error) {
	handle, err := openInShare(root+`\`+rel, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, windows.FILE_FLAG_SEQUENTIAL_SCAN, false)
	if err != nil {
		return nil, err
	}
	return windowsFile{os.NewFile(uintptr(handle), rel)}, nil
}

func (f windowsFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.File.ReadAt(p, off)
	return n, sentinel(err)
}

func (f windowsFile) info() (fileInfo, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return fileInfo{}, sentinel(err)
	}
	return fileInfo{
		id:       uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		size:     int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow),
		modified: filetime(int64(info.LastWriteTime.HighDateTime)<<32 | int64(info.LastWriteTime.LowDateTime)),
	}, nil
}

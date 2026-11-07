//go:build windows

package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/Syntriq-GmbH/thero-connect/core"
	"golang.org/x/sys/windows"
)

func TestLayouts(t *testing.T) {
	var directory fileIDBothDirInfo
	var share shareInfo502
	var rpc authzRPCInitInfoClient
	var request authzAccessRequest
	var reply authzAccessReply
	var value berval
	var attributes windows.OBJECT_ATTRIBUTES
	var name windows.NTUnicodeString
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"FILE_ID_BOTH_DIR_INFO.CreationTime", unsafe.Offsetof(directory.creationTime), 8},
		{"FILE_ID_BOTH_DIR_INFO.LastWriteTime", unsafe.Offsetof(directory.lastWriteTime), 24},
		{"FILE_ID_BOTH_DIR_INFO.ChangeTime", unsafe.Offsetof(directory.changeTime), 32},
		{"FILE_ID_BOTH_DIR_INFO.EndOfFile", unsafe.Offsetof(directory.endOfFile), 40},
		{"FILE_ID_BOTH_DIR_INFO.FileAttributes", unsafe.Offsetof(directory.fileAttributes), 56},
		{"FILE_ID_BOTH_DIR_INFO.FileNameLength", unsafe.Offsetof(directory.fileNameLength), 60},
		{"FILE_ID_BOTH_DIR_INFO.ShortName", unsafe.Offsetof(directory.shortName), 70},
		{"FILE_ID_BOTH_DIR_INFO.FileId", unsafe.Offsetof(directory.fileID), 96},
		{"FILE_ID_BOTH_DIR_INFO.FileName", unsafe.Offsetof(directory.fileName), 104},
		{"SHARE_INFO_502.shi502_type", unsafe.Offsetof(share.shareType), 8},
		{"SHARE_INFO_502.shi502_path", unsafe.Offsetof(share.path), 40},
		{"SHARE_INFO_502.shi502_reserved", unsafe.Offsetof(share.reserved), 56},
		{"SHARE_INFO_502.shi502_security_descriptor", unsafe.Offsetof(share.securityDescriptor), 64},
		{"SHARE_INFO_502", unsafe.Sizeof(share), 72},
		{"AUTHZ_RPC_INIT_INFO_CLIENT.ObjectUuid", unsafe.Offsetof(rpc.objectUUID), 8},
		{"AUTHZ_RPC_INIT_INFO_CLIENT.NetworkAddr", unsafe.Offsetof(rpc.networkAddr), 24},
		{"AUTHZ_RPC_INIT_INFO_CLIENT.ServerSpn", unsafe.Offsetof(rpc.serverSpn), 48},
		{"AUTHZ_RPC_INIT_INFO_CLIENT", unsafe.Sizeof(rpc), 56},
		{"AUTHZ_ACCESS_REQUEST.PrincipalSelfSid", unsafe.Offsetof(request.principalSelfSid), 8},
		{"AUTHZ_ACCESS_REQUEST.ObjectTypeListLength", unsafe.Offsetof(request.objectTypeListLength), 24},
		{"AUTHZ_ACCESS_REQUEST.OptionalArguments", unsafe.Offsetof(request.optionalArguments), 32},
		{"AUTHZ_ACCESS_REQUEST", unsafe.Sizeof(request), 40},
		{"AUTHZ_ACCESS_REPLY.GrantedAccessMask", unsafe.Offsetof(reply.grantedAccessMask), 8},
		{"AUTHZ_ACCESS_REPLY.Error", unsafe.Offsetof(reply.errors), 24},
		{"AUTHZ_ACCESS_REPLY", unsafe.Sizeof(reply), 32},
		{"berval.bv_val", unsafe.Offsetof(value.value), 8},
		{"berval", unsafe.Sizeof(value), 16},
		{"LSA_OBJECT_ATTRIBUTES", unsafe.Sizeof(attributes), 48},
		{"LSA_UNICODE_STRING.Buffer", unsafe.Offsetof(name.Buffer), 8},
		{"LSA_UNICODE_STRING", unsafe.Sizeof(name), 16},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.name, check.got, check.want)
		}
	}
}

func TestProcsResolve(t *testing.T) {
	procs := []*windows.LazyProc{
		procNetShareGetInfo,
		procAuthzInitializeRemoteResourceManager,
		procAuthzInitializeContextFromSid,
		procAuthzAccessCheck,
		procAuthzFreeContext,
		procAuthzFreeResourceManager,
		procLdapInit,
		procLdapSetOption,
		procLdapBind,
		procLdapSearch,
		procLdapFirstEntry,
		procLdapNextEntry,
		procLdapGetValuesLen,
		procLdapCountValuesLen,
		procLdapValueFreeLen,
		procLdapMsgFree,
		procLdapUnbind,
		procLsaOpenPolicy,
		procLsaAddAccountRights,
		procLsaClose,
	}
	for _, proc := range procs {
		if err := proc.Find(); err != nil {
			t.Errorf("%s: %v", proc.Name, err)
		}
	}
}

func TestSecur32Exports(t *testing.T) {
	for _, proc := range []*windows.LazyProc{procAcquireCredentialsHandle, procInitializeSecurityContext, procFreeContextBuffer, procDeleteSecurityContext, procFreeCredentialsHandle} {
		if err := proc.Find(); err != nil {
			t.Errorf("%s: %v", proc.Name, err)
		}
	}
}

func TestAuthIdentityLayout(t *testing.T) {
	var identity authIdentity
	var handle secHandle
	var buffer secBuffer
	var description secBufferDesc
	checks := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"SEC_WINNT_AUTH_IDENTITY_EXW.Length", unsafe.Offsetof(identity.length), 4},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.User", unsafe.Offsetof(identity.user), 8},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.UserLength", unsafe.Offsetof(identity.userLength), 16},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.Domain", unsafe.Offsetof(identity.domain), 24},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.DomainLength", unsafe.Offsetof(identity.domainLength), 32},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.Password", unsafe.Offsetof(identity.password), 40},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.PasswordLength", unsafe.Offsetof(identity.passwordLength), 48},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.Flags", unsafe.Offsetof(identity.flags), 52},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.PackageList", unsafe.Offsetof(identity.packageList), 56},
		{"SEC_WINNT_AUTH_IDENTITY_EXW.PackageListLength", unsafe.Offsetof(identity.packageListLength), 64},
		{"SEC_WINNT_AUTH_IDENTITY_EXW", unsafe.Sizeof(identity), 72},
		{"SecHandle.dwUpper", unsafe.Offsetof(handle.upper), 8},
		{"SecHandle", unsafe.Sizeof(handle), 16},
		{"SecBuffer.BufferType", unsafe.Offsetof(buffer.bufferType), 4},
		{"SecBuffer.pvBuffer", unsafe.Offsetof(buffer.buffer), 8},
		{"SecBuffer", unsafe.Sizeof(buffer), 16},
		{"SecBufferDesc.cBuffers", unsafe.Offsetof(description.count), 4},
		{"SecBufferDesc.pBuffers", unsafe.Offsetof(description.buffers), 8},
		{"SecBufferDesc", unsafe.Sizeof(description), 16},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.name, check.got, check.want)
		}
	}
}

func TestNoDelegation(t *testing.T) {
	const iscReqDelegate = 0x1
	if negotiateFlags&iscReqDelegate != 0 || negotiateFlags != 0x900 {
		t.Fatalf("request flags %#x", negotiateFlags)
	}
	checks := []struct {
		status     uint32
		attributes uint32
		ok         bool
	}{
		{secEOK, 0, true},
		{secIContinueNeeded, 0x800, true},
		{secEOK, iscRetDelegate, false},
		{secIContinueNeeded, iscRetDelegate | 0x800, false},
		{0x00090313, 0, false},
		{0x00090314, 0, false},
		{0x8009030e, 0, false},
		{0x80090311, 0, false},
		{0x80090303, 0, false},
	}
	for _, check := range checks {
		err := negotiated(check.status, check.attributes, "HTTP/sp.corp.example")
		if check.ok != (err == nil) {
			t.Errorf("negotiated(%#x, %#x) = %v", check.status, check.attributes, err)
		}
		if err != nil && (!errors.Is(err, core.ErrUnavailable) || !strings.Contains(err.Error(), "HTTP/sp.corp.example")) {
			t.Errorf("negotiated(%#x, %#x) error %q", check.status, check.attributes, err)
		}
	}
	if err := negotiated(0x8009030e, 0, "HTTP/x"); !strings.Contains(err.Error(), "0x8009030e") {
		t.Errorf("status missing from %q", err)
	}
}

func TestNegotiateKerberosOnly(t *testing.T) {
	src := windowsSource{}
	for _, spn := range []string{"HTTP/localhost", "HTTP/nosuch.invalid", "HTTP/a\x00b", ""} {
		token, err := src.Negotiate(spn)
		if token != "" || !errors.Is(err, core.ErrUnavailable) {
			t.Errorf("Negotiate(%q) = %q, %v", spn, token, err)
		}
	}
}

func TestMembersWithoutSIDs(t *testing.T) {
	members, err := windowsSource{}.Members(nil)
	if err != nil || len(members) != 0 {
		t.Fatalf("Members(nil) = %v, %v", members, err)
	}
}

func TestCrossRefFilterValue(t *testing.T) {
	checks := map[string]string{
		"DC=corp,DC=example":    "DC=corp,DC=example",
		`OU=a\,b,DC=corp`:       `OU=a\5c,b,DC=corp`,
		"DC=(x)*,DC=y":          `DC=\28x\29\2a,DC=y`,
		"DC=a\x00b":             `DC=a\00b`,
		"DC=ünïcode,DC=example": "DC=ünïcode,DC=example",
	}
	for value, want := range checks {
		if got := ldapFilterValue.Replace(value); got != want {
			t.Errorf("escape(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestSentinel(t *testing.T) {
	checks := []struct {
		err  error
		want error
	}{
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_LOCK_VIOLATION}, core.ErrBusy},
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_SHARING_VIOLATION}, core.ErrBusy},
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_ACCESS_DENIED}, core.ErrDenied},
		{windows.ERROR_BAD_NET_NAME, core.ErrNotFound},
		{io.EOF, io.EOF},
		{nil, nil},
	}
	for _, check := range checks {
		if got := sentinel(check.err); got != check.want {
			t.Errorf("sentinel(%v) = %v, want %v", check.err, got, check.want)
		}
	}
}

func TestAuthzFailure(t *testing.T) {
	checks := []struct {
		err  error
		want error
	}{
		{windows.RPC_S_SERVER_UNAVAILABLE, core.ErrUnavailable},
		{windows.EPT_S_NOT_REGISTERED, core.ErrUnavailable},
		{windows.RPC_S_CALL_FAILED, core.ErrUnavailable},
		{windows.RPC_S_CALL_FAILED_DNE, core.ErrUnavailable},
		{windows.ERROR_ACCESS_DENIED, core.ErrDenied},
		{windows.ERROR_NONE_MAPPED, nil},
		{windows.ERROR_NO_SUCH_USER, nil},
		{windows.ERROR_INVALID_SID, nil},
	}
	for _, check := range checks {
		got := authzFailure("fs1", check.err)
		if check.want == nil && got != nil || check.want != nil && !errors.Is(got, check.want) {
			t.Errorf("authzFailure(%v) = %v, want %v", check.err, got, check.want)
		}
	}
}

func shareTree(t *testing.T) (string, string) {
	local := t.TempDir()
	volume := filepath.VolumeName(local)
	unc := `\\localhost\` + strings.TrimSuffix(volume, ":") + `$` + strings.TrimPrefix(local, volume)
	if _, err := os.Stat(unc); err != nil {
		t.Fatalf("administrative share unreachable: %v", err)
	}
	for name, content := range map[string]string{`root\inner\a.txt`: "inside", `outside\a.txt`: "secret"} {
		path := filepath.Join(local, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return local, unc + `\root`
}

func TestJunctionSwapIsRefused(t *testing.T) {
	local, root := shareTree(t)
	src := windowsSource{}
	f, err := src.Open(root, `inner\a.txt`)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	inner := filepath.Join(local, "root", "inner")
	if err := os.Rename(inner, filepath.Join(local, "root", "moved")); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", inner, filepath.Join(local, "outside")).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if _, err := src.Open(root, `inner\a.txt`); !errors.Is(err, core.ErrDenied) {
		t.Fatalf("open through a junction: %v", err)
	}
	if _, err := src.List(root + `\inner`); !errors.Is(err, core.ErrDenied) {
		t.Fatalf("list of a junction: %v", err)
	}
	if _, _, err := src.Descriptor(root + `\inner\a.txt`); !errors.Is(err, core.ErrDenied) {
		t.Fatalf("descriptor through a junction: %v", err)
	}
	entries, err := src.List(root)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(entries, func(e core.Entry) bool { return e.Name == "inner" }) {
		t.Fatalf("junction listed: %+v", entries)
	}
}

func TestDescriptorIDMatchesListing(t *testing.T) {
	_, root := shareTree(t)
	src := windowsSource{}
	entries, err := src.List(root + `\inner`)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: %v %+v", err, entries)
	}
	sd, id, err := src.Descriptor(root + `\inner\a.txt`)
	if err != nil || len(sd) == 0 {
		t.Fatalf("descriptor: %v", err)
	}
	f, err := src.Open(root, `inner\a.txt`)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Info()
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 || id != entries[0].ID || id != info.ID {
		t.Fatalf("descriptor id %x, listed %x, open %x", id, entries[0].ID, info.ID)
	}
}

func TestSourceRefusesLinuxSettings(t *testing.T) {
	if _, err := newSource("", "thero-connect@CORP.EXAMPLE", nil); err == nil {
		t.Fatal("principal accepted")
	}
	if _, err := newSource("", "", map[string]bool{"files.corp.example": true}); err == nil {
		t.Fatal("samba host accepted")
	}
	if _, err := newSource("", "", map[string]bool{}); err != nil {
		t.Fatal(err)
	}
}

func TestReadLocksOutWriters(t *testing.T) {
	local, root := shareTree(t)
	src := windowsSource{}
	path := filepath.Join(local, "root", "inner", "a.txt")
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Open(root, `inner\a.txt`); !errors.Is(err, core.ErrBusy) {
		t.Fatalf("open beside a writer: %v", err)
	}
	writer.Close()
	f, err := src.Open(root, `inner\a.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		writer.Close()
		t.Fatal("a writer opened the file during a read")
	}
	f.Close()
}

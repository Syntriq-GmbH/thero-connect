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
	"time"
	"unsafe"

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
		if got := filetime(check.value); !got.Equal(check.want) {
			t.Errorf("filetime(%d) = %v, want %v", check.value, got, check.want)
		}
	}
	if got := max(0, filetime(0).UnixMilli()); got != 0 {
		t.Errorf("clamped zero filetime = %d, want 0", got)
	}
}

func TestSentinel(t *testing.T) {
	checks := []struct {
		err  error
		want error
	}{
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_LOCK_VIOLATION}, errBusy},
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_SHARING_VIOLATION}, errBusy},
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_ACCESS_DENIED}, errDenied},
		{windows.ERROR_BAD_NET_NAME, errNotFound},
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
		{windows.RPC_S_SERVER_UNAVAILABLE, errUnavailable},
		{windows.EPT_S_NOT_REGISTERED, errUnavailable},
		{windows.RPC_S_CALL_FAILED, errUnavailable},
		{windows.RPC_S_CALL_FAILED_DNE, errUnavailable},
		{windows.ERROR_ACCESS_DENIED, errDenied},
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
	if code := codeOf(authzFailure("fs1", windows.RPC_S_SERVER_UNAVAILABLE)); code != "unavailable" {
		t.Errorf("code = %q, want unavailable", code)
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
	f, err := src.open(root, `inner\a.txt`)
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
	if _, err := src.open(root, `inner\a.txt`); !errors.Is(err, errDenied) {
		t.Fatalf("open through a junction: %v", err)
	}
	if _, err := src.list(root + `\inner`); !errors.Is(err, errDenied) {
		t.Fatalf("list of a junction: %v", err)
	}
	if _, err := src.descriptor(root + `\inner\a.txt`); !errors.Is(err, errDenied) {
		t.Fatalf("descriptor through a junction: %v", err)
	}
	entries, err := src.list(root)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(entries, func(e entry) bool { return e.name == "inner" }) {
		t.Fatalf("junction listed: %+v", entries)
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
	if _, err := src.open(root, `inner\a.txt`); !errors.Is(err, errBusy) {
		t.Fatalf("open beside a writer: %v", err)
	}
	writer.Close()
	f, err := src.open(root, `inner\a.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		writer.Close()
		t.Fatal("a writer opened the file during a read")
	}
	f.Close()
}

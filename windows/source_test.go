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
	"unicode/utf16"
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
	var dfs dfsInfo3
	var storage dfsStorageInfo
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
		{"DFS_INFO_3.State", unsafe.Offsetof(dfs.state), 16},
		{"DFS_INFO_3.NumberOfStorages", unsafe.Offsetof(dfs.numberOfStorages), 20},
		{"DFS_INFO_3.Storage", unsafe.Offsetof(dfs.storage), 24},
		{"DFS_INFO_3", unsafe.Sizeof(dfs), 32},
		{"DFS_STORAGE_INFO.ServerName", unsafe.Offsetof(storage.serverName), 8},
		{"DFS_STORAGE_INFO.ShareName", unsafe.Offsetof(storage.shareName), 16},
		{"DFS_STORAGE_INFO", unsafe.Sizeof(storage), 24},
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
		procNetDfsGetClientInfo,
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

func TestSentinel(t *testing.T) {
	checks := []struct {
		err  error
		want error
	}{
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_LOCK_VIOLATION}, core.ErrBusy},
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_SHARING_VIOLATION}, core.ErrBusy},
		{&fs.PathError{Op: "read", Path: "a", Err: windows.ERROR_ACCESS_DENIED}, core.ErrDenied},
		{windows.ERROR_BAD_NET_NAME, core.ErrNotFound},
		{windows.ERROR_BAD_NETPATH, core.ErrUnavailable},
		{&fs.PathError{Op: "open", Path: "a", Err: windows.ERROR_UNEXP_NET_ERR}, core.ErrUnavailable},
		{windows.ERROR_NETNAME_DELETED, core.ErrUnavailable},
		{windows.ERROR_SEM_TIMEOUT, core.ErrUnavailable},
		{windows.ERROR_NETWORK_UNREACHABLE, core.ErrUnavailable},
		{windows.ERROR_HOST_UNREACHABLE, core.ErrUnavailable},
		{windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND},
		{io.EOF, io.EOF},
		{nil, nil},
	}
	for _, check := range checks {
		if got := sentinel(check.err); !errors.Is(got, check.want) {
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
	local, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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

func TestGuard(t *testing.T) {
	_, root := shareTree(t)
	parts := strings.Split(root, `\`)
	share := `\\localhost\` + parts[3]
	for _, path := range []string{share, root, root + `\inner`, root + `\inner\a.txt`} {
		handle, err := openHandle(path, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_FLAG_BACKUP_SEMANTICS)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(guard(handle, path+`x`))
		if err := guard(handle, path); err != nil {
			t.Errorf("guard %s: %v", path, err)
		}
		if err := guard(handle, strings.ToUpper(path)); err != nil {
			t.Errorf("guard upper case %s: %v", path, err)
		}
		for _, other := range []string{path + `x`, path + `\`, `\\127.0.0.1` + strings.TrimPrefix(path, `\\localhost`), `\\localhost\other$` + strings.TrimPrefix(path, share)} {
			if err := guard(handle, other); !errors.Is(err, core.ErrUnavailable) {
				t.Errorf("guard %s as %s: %v", path, other, err)
			}
		}
		windows.CloseHandle(handle)
	}
	src := windowsSource{}
	if _, err := src.List(share); err != nil {
		t.Fatalf("list share root: %v", err)
	}
	if _, err := src.List(root + `\inner`); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, _, err := src.Descriptor(root + `\inner\a.txt`); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	f, err := src.Open(root, `inner\a.txt`)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	f.Close()
}

func TestPhysicalMatches(t *testing.T) {
	path := `\\fs1.corp.example\docs\team\a.txt`
	checks := []struct {
		name string
		want bool
	}{
		{`\\fs1.corp.example\docs\team\a.txt`, true},
		{`\\FS1.CORP.EXAMPLE\Docs\TEAM\A.txt`, true},
		{`\;X:\fs1.corp.example\docs\team\a.txt`, true},
		{`;X:\fs1.corp.example\docs\team\a.txt`, true},
		{`\;Z:000000000003e7a4\fs1.corp.example\docs\team\a.txt`, true},
		{`\;X:\fs2.corp.example\docs\team\a.txt`, false},
		{`\;X:\fs1.corp.example\other\team\a.txt`, false},
		{`\;X:\fs1\docs\team\a.txt`, false},
		{`\;X:fs1.corp.example\docs\team\a.txt`, false},
		{`\;X:`, false},
		{`\;X:\;Y:\fs1.corp.example\docs\team\a.txt`, false},
		{`\\fs2.corp.example\docs\team\a.txt`, false},
		{`\\fs1.corp.example\docs\team\a.txt\`, false},
		{`\\fs1.corp.example\docs\team\a.txt:secret`, false},
		{`\\fs1.corp.example\docs\team`, false},
		{`\\fs1.corp.example\docs\team\b.txt`, false},
		{`\fs1.corp.example\docs\team\a.txt`, false},
		{`\\\fs1.corp.example\docs\team\a.txt`, false},
		{`\\fs1.corp.example\docs\team\a.txt` + "\x00", false},
		{``, false},
	}
	for _, check := range checks {
		if got := physicalMatches(check.name, path); got != check.want {
			t.Errorf("physicalMatches(%q) = %v, want %v", check.name, got, check.want)
		}
	}
}

func TestEntryOf(t *testing.T) {
	directory := uint32(windows.FILE_ATTRIBUTE_DIRECTORY)
	reparse := uint32(windows.FILE_ATTRIBUTE_REPARSE_POINT)
	checks := []struct {
		name       string
		attributes uint32
		tag        uint32
		listed     bool
		dir        bool
		link       bool
	}{
		{"link", directory | reparse, ioReparseTagDFS, true, true, true},
		{"junction", directory | reparse, windows.IO_REPARSE_TAG_MOUNT_POINT, false, false, false},
		{"symlink", directory | reparse, windows.IO_REPARSE_TAG_SYMLINK, false, false, false},
		{"offline", directory | reparse | windows.FILE_ATTRIBUTE_OFFLINE, ioReparseTagDFS, false, false, false},
		{"recall", directory | reparse | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN, ioReparseTagDFS, false, false, false},
		{"data", directory | reparse | windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, ioReparseTagDFS, false, false, false},
		{"file", reparse, ioReparseTagDFS, false, false, false},
		{"folder", directory, 0, true, true, false},
		{"tagged", directory, ioReparseTagDFS, true, true, false},
		{"plain", windows.FILE_ATTRIBUTE_ARCHIVE, ioReparseTagDFS, true, false, false},
		{"stub", windows.FILE_ATTRIBUTE_OFFLINE, 0, false, false, false},
		{".", directory, 0, false, false, false},
		{"..", directory | reparse, ioReparseTagDFS, false, false, false},
	}
	for _, check := range checks {
		buffer := make([]uint64, 32)
		info := (*fileIDBothDirInfo)(unsafe.Pointer(&buffer[0]))
		name := utf16.Encode([]rune(check.name))
		copy(unsafe.Slice(&info.fileName[0], len(name)), name)
		info.fileNameLength = uint32(2 * len(name))
		info.fileAttributes = check.attributes
		info.eaSize = check.tag
		info.fileID = 7
		entry, ok := entryOf(info)
		if ok != check.listed || ok && (entry.Name != check.name || entry.Dir != check.dir || entry.Link != check.link || entry.ID != 7) {
			t.Errorf("%s: %+v %v", check.name, entry, ok)
		}
	}
}

func TestReferralOf(t *testing.T) {
	text := func(value string) *uint16 {
		pointer, err := windows.UTF16PtrFromString(value)
		if err != nil {
			t.Fatal(err)
		}
		return pointer
	}
	storage := func(state uint32, server, share string) dfsStorageInfo {
		return dfsStorageInfo{state: state, serverName: text(server), shareName: text(share)}
	}
	checks := []struct {
		name     string
		unc      string
		entry    string
		storages []dfsStorageInfo
		consumed string
		sets     [][]string
	}{
		{"active first", `\\corp.example\NS\Replica\sub\f.txt`, `\\CORP\ns\replica`, []dfsStorageInfo{storage(0, "fs2.corp.example", "replica"), storage(0x4, "fs1.corp.example", "replica"), storage(0x1, "fs3.corp.example", "replica")}, `\\corp.example\NS\Replica`, [][]string{{`\\fs1.corp.example\replica`}, {`\\fs2.corp.example\replica`}}},
		{"no active", `\\fs1.corp.example\ns\docs`, `\fs1\ns`, []dfsStorageInfo{storage(0x2, "fs1.corp.example", "ns"), storage(0, `\\fs2.corp.example\`, `data\sub\`)}, `\\fs1.corp.example\ns`, [][]string{{`\\fs1.corp.example\ns`, `\\fs2.corp.example\data\sub`}}},
		{"only active", `\\fs1\ns\docs`, `\\fs1\ns\docs`, []dfsStorageInfo{storage(0x4, "fs2", "docs")}, `\\fs1\ns\docs`, [][]string{{`\\fs2\docs`}}},
		{"other component", `\\fs1\ns\docs`, `\\fs1\ns\other`, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"mid component", `\\fs1\ns\docs`, `\\fs1\ns\do`, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"other share", `\\fs1\ns\docs`, `\\fs1\ns2\docs`, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"longer", `\\fs1\ns`, `\\fs1\ns\docs`, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"trailing", `\\fs1\ns\docs`, `\\fs1\ns\`, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"host only", `\\fs1\ns\docs`, `\\fs1`, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"no host", `\\fs1\ns\docs`, `\\\ns\docs`, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"empty", `\\fs1\ns\docs`, ``, []dfsStorageInfo{storage(0, "fs2", "docs")}, "", nil},
		{"all offline", `\\fs1\ns\docs`, `\\fs1\ns\docs`, []dfsStorageInfo{storage(0x1, "fs2", "docs"), storage(0x5, "fs3", "docs")}, "", nil},
		{"no storage", `\\fs1\ns\docs`, `\\fs1\ns\docs`, nil, "", nil},
	}
	for _, check := range checks {
		info := dfsInfo3{entryPath: text(check.entry), numberOfStorages: uint32(len(check.storages))}
		if len(check.storages) > 0 {
			info.storage = &check.storages[0]
		}
		got, err := referralOf(check.unc, &info)
		if check.sets == nil {
			if !errors.Is(err, core.ErrUnavailable) {
				t.Errorf("%s: %+v %v", check.name, got, err)
			}
			continue
		}
		if err != nil || got.Consumed != check.consumed || !slices.EqualFunc(got.Sets, check.sets, slices.Equal) {
			t.Errorf("%s: %+v %v", check.name, got, err)
		}
	}
	if _, err := referralOf(`\\fs1\ns`, &dfsInfo3{numberOfStorages: 1, storage: &dfsStorageInfo{serverName: text("fs2"), shareName: text("ns")}}); !errors.Is(err, core.ErrUnavailable) {
		t.Errorf("nil entry path: %v", err)
	}
}

func TestReferralOfPlainShare(t *testing.T) {
	_, root := shareTree(t)
	src := windowsSource{}
	for _, path := range []string{root, root + `\inner\a.txt`} {
		if _, err := src.Referral(path); !errors.Is(err, core.ErrNotFound) {
			t.Errorf("referral %s: %v", path, err)
		}
	}
	if _, err := src.Referral(root + `\missing`); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("referral of a missing path: %v", err)
	}
	if _, err := src.Referral(`C:\Windows`); !errors.Is(err, core.ErrUnavailable) {
		t.Errorf("referral of a local path: %v", err)
	}
}

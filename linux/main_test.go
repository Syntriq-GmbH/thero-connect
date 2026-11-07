//go:build !windows

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestUnit(t *testing.T) {
	text := unit("thero-connect", "/usr/local/bin/thero-connect", "/etc/thero-connect")
	for _, want := range []string{
		"[Unit]\nDescription=Thero Connect\n",
		"\nUser=thero-connect\nGroup=thero-connect\n",
		"\nExecStart=/usr/local/bin/thero-connect run -dir /etc/thero-connect\n",
		"\nReadWritePaths=/etc/thero-connect/state\n",
		"\nRestart=always\nRestartSec=60\n",
		"\nStartLimitIntervalSec=0\n",
		"\nProtectSystem=strict\n",
		"\nCapabilityBoundingSet=\n",
		"\n[Install]\nWantedBy=multi-user.target\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if strings.Contains(text, "%!") || strings.Count(text, "\n[") != 2 {
		t.Errorf("unit is malformed:\n%s", text)
	}
}

func TestInstallValidation(t *testing.T) {
	for _, c := range []struct{ dir, account, want string }{
		{"/etc/thero-connect", "", "account"},
		{"/etc/thero-connect", "Thero", "account"},
		{"/etc/thero-connect", "1thero", "account"},
		{"/etc/thero-connect", "thero connect", "account"},
		{"/etc/thero-connect", `CORP\thero$`, "account"},
		{"/etc/thero-connect", strings.Repeat("a", 33), "account"},
		{"etc/thero-connect", "thero-connect", "-dir"},
		{"/", "thero-connect", "-dir"},
		{"/etc/thero connect", "thero-connect", "-dir"},
		{"/etc/thero-connect/", "thero-connect", "-dir"},
		{"/etc/../tmp/thero", "thero-connect", "-dir"},
		{"/etc/thero-connect;rm", "thero-connect", "-dir"},
		{"/etc/%h", "thero-connect", "-dir"},
	} {
		err := install(c.dir, c.account)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("install(%q, %q) = %v, want an error about %s", c.dir, c.account, err, c.want)
		}
	}
	if os.Geteuid() == 0 {
		t.Skip("valid arguments would install the service as root")
	}
	for _, account := range []string{"thero-connect", "_thero", strings.Repeat("a", 32)} {
		err := install("/etc/thero-connect", account)
		if err == nil || strings.HasPrefix(err.Error(), "account") || strings.HasPrefix(err.Error(), "-dir") {
			t.Errorf("install(%q) = %v, want it past validation", account, err)
		}
	}
}

func TestRootOwned(t *testing.T) {
	saved := rootUID
	t.Cleanup(func() { rootUID = saved })
	binary := filepath.Join(t.TempDir(), "thero-connect")
	write(t, binary, "binary", 0o755)
	if os.Geteuid() != 0 {
		if err := rootOwned(binary); err == nil || !strings.Contains(err.Error(), "is owned by") {
			t.Errorf("binary owned by a user: %v", err)
		}
	}
	rootUID = os.Geteuid()
	chmod(t, binary, 0o775)
	if err := rootOwned(binary); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("binary writable by group: %v", err)
	}
	chmod(t, binary, 0o755)
	chmod(t, filepath.Dir(binary), 0o777)
	if err := rootOwned(binary); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("folder writable by others: %v", err)
	}
	chmod(t, filepath.Dir(binary), 0o755)
	linked := filepath.Join(t.TempDir(), "linked")
	link(t, binary, linked)
	if err := rootOwned(linked); err == nil || !strings.Contains(err.Error(), "not a link") {
		t.Errorf("binary behind a link: %v", err)
	}
}

func TestPrivateAccount(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nsvc:x:998:997::/nonexistent:/usr/sbin/nologin\n"
	groups := "root:x:0:\nalice:x:1000:\nsvc:x:997:\n"
	cases := []struct {
		name, passwd, groups, account, want string
	}{
		{"private", passwd, groups, "svc", ""},
		{"unknown account", passwd, groups, "thero", "create the account first: useradd --system --user-group"},
		{"group named differently", passwd, "root:x:0:\nservices:x:997:\n", "svc", "shared"},
		{"group with members", passwd, "root:x:0:\nsvc:x:997:alice\n", "svc", "shared"},
		{"group of another user", passwd + "bob:x:1001:997::/home/bob:/bin/bash\n", groups, "svc", "shared"},
		{"second group with the same id", passwd, groups + "other:x:997:\n", "svc", "shared"},
		{"no group entry", passwd, "root:x:0:\n", "svc", "shared"},
		{"root group", "svc:x:998:0::/nonexistent:/usr/sbin/nologin\n", "root:x:0:\nsvc:x:0:\n", "svc", "shared"},
		{"root account", passwd, groups, "root", "root"},
		{"duplicate account", passwd + "svc:x:999:997::/nonexistent:/usr/sbin/nologin\n", groups, "svc", "duplicate"},
	}
	for _, c := range cases {
		uid, gid, err := privateAccount([]byte(c.passwd), []byte(c.groups), c.account)
		if c.want == "" {
			if err != nil || uid != 998 || gid != 997 {
				t.Errorf("%s: %d, %d, %v", c.name, uid, gid, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestSecureDir(t *testing.T) {
	savedUID, savedGID, savedPasswd, savedGroup := rootUID, rootGID, passwdFile, groupFile
	t.Cleanup(func() { rootUID, rootGID, passwdFile, groupFile = savedUID, savedGID, savedPasswd, savedGroup })
	rootUID, rootGID = os.Geteuid(), os.Getegid()
	fixtures := t.TempDir()
	passwdFile = filepath.Join(fixtures, "passwd")
	groupFile = filepath.Join(fixtures, "group")
	svcUID, svcGID := os.Geteuid(), os.Getegid()
	if svcUID == 0 {
		svcUID, svcGID = 4242, 4242
	}
	uid, gid := strconv.Itoa(svcUID), strconv.Itoa(svcGID)
	write(t, passwdFile, "svc:x:"+uid+":"+gid+"::/nonexistent:/usr/sbin/nologin\n", 0o644)
	write(t, groupFile, "svc:x:"+gid+":\n", 0o644)

	tree := func(t *testing.T) string {
		dir := filepath.Join(t.TempDir(), "thero-connect")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dir, "config.yaml"), "roots: []\n", 0o644)
		write(t, filepath.Join(dir, "krb5.keytab"), "keytab", 0o644)
		return dir
	}
	modes := func(t *testing.T, dir string, group int, want map[string]fs.FileMode) {
		for name, mode := range want {
			info, err := os.Lstat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != mode {
				t.Errorf("%s: mode %o, want %o", name, info.Mode().Perm(), mode)
			}
			if got := int(info.Sys().(*syscall.Stat_t).Gid); got != group {
				t.Errorf("%s: group %d, want %d", name, got, group)
			}
		}
	}

	t.Run("enroll then install", func(t *testing.T) {
		dir := tree(t)
		if err := secureDir(dir, ""); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(dir, "state", "identity.bin"), "key", 0o644)
		if err := secureDir(dir, ""); err != nil {
			t.Fatal(err)
		}
		modes(t, dir, rootGID, map[string]fs.FileMode{".": 0o700, "config.yaml": 0o600, "krb5.keytab": 0o600, "state": 0o700, "state/identity.bin": 0o600})
		if err := secureDir(dir, "svc"); err != nil {
			t.Fatal(err)
		}
		modes(t, dir, svcGID, map[string]fs.FileMode{".": 0o750, "config.yaml": 0o640, "krb5.keytab": 0o640, "state": 0o770, "state/identity.bin": 0o600})
		info, err := os.Lstat(filepath.Join(dir, "state", "identity.bin"))
		if err != nil || int(info.Sys().(*syscall.Stat_t).Uid) != svcUID {
			t.Errorf("identity.bin is not owned by the account: %v", err)
		}
		if err := secureDir(dir, ""); err != nil {
			t.Fatal(err)
		}
		modes(t, dir, rootGID, map[string]fs.FileMode{".": 0o700, "config.yaml": 0o600, "krb5.keytab": 0o600, "state": 0o700, "state/identity.bin": 0o600})
	})

	refusals := []struct {
		name, want string
		prepare    func(t *testing.T, dir string)
	}{
		{"missing keytab", "copy the keytab", func(t *testing.T, dir string) {
			remove(t, filepath.Join(dir, "krb5.keytab"))
		}},
		{"config is a link", "not a link", func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "config.yaml")
			write(t, target, "roots: []\n", 0o644)
			remove(t, filepath.Join(dir, "config.yaml"))
			link(t, target, filepath.Join(dir, "config.yaml"))
		}},
		{"keytab is a folder", "not a link", func(t *testing.T, dir string) {
			remove(t, filepath.Join(dir, "krb5.keytab"))
			if err := os.Mkdir(filepath.Join(dir, "krb5.keytab"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"state is a link", "not a link", func(t *testing.T, dir string) {
			link(t, t.TempDir(), filepath.Join(dir, "state"))
		}},
		{"folder writable by others", "writable", func(t *testing.T, dir string) {
			chmod(t, dir, 0o777)
		}},
		{"parent writable by group", "writable", func(t *testing.T, dir string) {
			chmod(t, filepath.Dir(dir), 0o775)
		}},
		{"link in state", "plain file", func(t *testing.T, dir string) {
			mkdir(t, filepath.Join(dir, "state"))
			link(t, filepath.Join(dir, "config.yaml"), filepath.Join(dir, "state", "identity.bin"))
		}},
		{"folder in state", "plain file", func(t *testing.T, dir string) {
			mkdir(t, filepath.Join(dir, "state"))
			mkdir(t, filepath.Join(dir, "state", "identity.bin"))
		}},
		{"hard link in state", "plain file", func(t *testing.T, dir string) {
			mkdir(t, filepath.Join(dir, "state"))
			if err := os.Link(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "state", "identity.bin")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, r := range refusals {
		t.Run(r.name, func(t *testing.T) {
			dir := tree(t)
			r.prepare(t, dir)
			for _, account := range []string{"", "svc"} {
				err := secureDir(dir, account)
				if err == nil || !strings.Contains(err.Error(), r.want) {
					t.Errorf("secureDir(%q) = %v, want %q", account, err, r.want)
				}
			}
		})
	}

	t.Run("shared group", func(t *testing.T) {
		write(t, groupFile, "svc:x:"+gid+":alice\n", 0o644)
		t.Cleanup(func() { write(t, groupFile, "svc:x:"+gid+":\n", 0o644) })
		if err := secureDir(tree(t), "svc"); err == nil || !strings.Contains(err.Error(), "shared") {
			t.Errorf("secureDir = %v, want a shared group refusal", err)
		}
	})

	t.Run("not root", func(t *testing.T) {
		rootUID = os.Geteuid() + 1
		t.Cleanup(func() { rootUID = os.Geteuid() })
		if err := secureDir(tree(t), ""); err == nil || err.Error() != "run as root" {
			t.Errorf("secureDir = %v, want run as root", err)
		}
	})
}

func write(t *testing.T, path, content string, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, path, mode)
}

func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

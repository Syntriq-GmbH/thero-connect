//go:build !windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/Syntriq-GmbH/thero-connect/core"
)

const unitPath = "/etc/systemd/system/thero-connect.service"

const unitTemplate = `[Unit]
Description=Thero Connect
Wants=network-online.target
After=network-online.target time-sync.target
StartLimitIntervalSec=0

[Service]
Type=exec
User=%[1]s
Group=%[1]s
ExecStart=%[2]s run -dir %[3]s
Restart=always
RestartSec=60
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ReadWritePaths=%[3]s/state
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`

var (
	accountPattern   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	pathPattern      = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	rootUID, rootGID = 0, 0
	passwdFile       = "/etc/passwd"
	groupFile        = "/etc/group"
)

func main() {
	core.Main(core.Platform{
		Dir:       "/etc/thero-connect",
		Source:    newSource,
		Protect:   plain,
		Unprotect: plain,
		SecureDir: secureDir,
		Install:   install,
		Uninstall: uninstall,
		Log:       os.Stderr,
	})
}

func plain(data []byte) ([]byte, error) {
	return data, nil
}

func unit(account, executable, dir string) string {
	return fmt.Sprintf(unitTemplate, account, executable, dir)
}

func secureDir(dir, account string) error {
	if os.Geteuid() != rootUID {
		return errors.New("run as root")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	parent := filepath.Dir(dir)
	configFile := filepath.Join(dir, "config.yaml")
	keytab := filepath.Join(dir, "krb5.keytab")
	state := filepath.Join(dir, "state")
	for _, path := range []string{parent, dir, configFile, keytab, state} {
		info, err := os.Lstat(path)
		if path == state && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if path == keytab && errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("copy the keytab to %s first", keytab)
		}
		if err != nil {
			return err
		}
		want := fs.ModeDir
		if path == configFile || path == keytab {
			want = 0
		}
		if info.Mode().Type() != want {
			return fmt.Errorf("%s must be a plain file or folder, not a link", path)
		}
		if owner := info.Sys().(*syscall.Stat_t).Uid; int(owner) != rootUID {
			return fmt.Errorf("%s is owned by %d; recreate it as root", path, owner)
		}
		if (path == parent || path == dir) && info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or others; allow writes by root only", path)
		}
	}
	uid, gid := rootUID, rootGID
	dirMode, fileMode, stateMode := fs.FileMode(0o700), fs.FileMode(0o600), fs.FileMode(0o700)
	if account != "" {
		passwd, err := os.ReadFile(passwdFile)
		if err != nil {
			return err
		}
		groups, err := os.ReadFile(groupFile)
		if err != nil {
			return err
		}
		if uid, gid, err = privateAccount(passwd, groups, account); err != nil {
			return err
		}
		dirMode, fileMode, stateMode = 0o750, 0o640, 0o770
	}
	if err := os.Mkdir(state, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	for _, target := range []struct {
		path string
		mode fs.FileMode
	}{{dir, dirMode}, {configFile, fileMode}, {keytab, fileMode}, {state, stateMode}} {
		if err := os.Lchown(target.path, rootUID, gid); err != nil {
			return err
		}
		if err := os.Chmod(target.path, target.mode); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(state, entry.Name())
		f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("%s must be a plain file: %w", path, err)
		}
		info, err := f.Stat()
		if err == nil && (!info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1) {
			err = fmt.Errorf("%s must be a plain file", path)
		}
		if err == nil {
			err = f.Chown(uid, gid)
		}
		if err == nil {
			err = f.Chmod(0o600)
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func privateAccount(passwd, groups []byte, account string) (int, int, error) {
	uid, gid := -1, ""
	shared := map[string]bool{}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[0] != account {
			shared[fields[3]] = true
			continue
		}
		id, err := strconv.Atoi(fields[2])
		if err != nil || uid >= 0 {
			return 0, 0, fmt.Errorf("%s has an invalid or duplicate entry in %s", account, passwdFile)
		}
		uid, gid = id, fields[3]
	}
	if uid < 0 {
		return 0, 0, fmt.Errorf("create the account first: useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin %s", account)
	}
	if uid == 0 {
		return 0, 0, fmt.Errorf("%s is root; use an unprivileged account", account)
	}
	found := false
	for _, line := range strings.Split(string(groups), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[2] != gid {
			continue
		}
		if fields[0] != account || strings.TrimSpace(fields[3]) != "" {
			shared[gid] = true
		}
		found = true
	}
	id, err := strconv.Atoi(gid)
	if !found || shared[gid] || err != nil || id == 0 {
		return 0, 0, fmt.Errorf("the primary group of %s is shared; use an account created with useradd --system --user-group", account)
	}
	return uid, id, nil
}

func install(dir, account string) error {
	if !accountPattern.MatchString(account) {
		return fmt.Errorf("account %q: use a local user name such as thero-connect", account)
	}
	if !pathPattern.MatchString(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("-dir %q: use an absolute path of letters, digits and . _ / -", dir)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if !pathPattern.MatchString(executable) || filepath.Clean(executable) != executable {
		return fmt.Errorf("%q: move the binary to a path of letters, digits and . _ / -, such as /usr/local/bin/thero-connect", executable)
	}
	if os.Geteuid() != rootUID {
		return errors.New("run as root")
	}
	if err := rootOwned(executable); err != nil {
		return err
	}
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return errors.New("systemd is not running")
	}
	if err := secureDir(dir, account); err != nil {
		return err
	}
	temp := unitPath + ".tmp"
	if err := os.Remove(temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.WriteString(unit(account, executable, dir))
	if err == nil {
		err = f.Chmod(0o644)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, unitPath); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", "thero-connect")
}

func rootOwned(executable string) error {
	for path := executable; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if path == executable && !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a plain file, not a link", path)
		}
		if owner := info.Sys().(*syscall.Stat_t).Uid; int(owner) != rootUID {
			return fmt.Errorf("%s is owned by %d; install the binary as root, such as to /usr/local/bin/thero-connect", path, owner)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or others; allow writes by root only", path)
		}
		if path == "/" {
			return nil
		}
	}
}

func uninstall() error {
	stopped := systemctl("disable", "--now", "thero-connect")
	removed := os.Remove(unitPath)
	if errors.Is(removed, fs.ErrNotExist) {
		removed = nil
	}
	return errors.Join(stopped, removed, systemctl("daemon-reload"))
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "TheroConnect"

var (
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy       = advapi32.NewProc("LsaOpenPolicy")
	procLsaAddAccountRights = advapi32.NewProc("LsaAddAccountRights")
	procLsaClose            = advapi32.NewProc("LsaClose")
)

type serviceHandler struct {
	run func(ctx context.Context) error
	err error
}

type eventWriter struct {
	log *eventlog.Log
}

func newSource() (source, error) {
	return windowsSource{}, nil
}

func protect(data []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(data)), Data: unsafe.SliceData(data)}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

func unprotect(data []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(data)), Data: unsafe.SliceData(data)}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

func isService() bool {
	service, err := svc.IsWindowsService()
	return err == nil && service
}

func runService(run func(ctx context.Context) error) error {
	handler := &serviceHandler{run: run}
	if err := svc.Run(serviceName, handler); err != nil {
		return err
	}
	return handler.err
}

func (h *serviceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil && ctx.Err() == nil {
				h.err = err
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		}
	}
}

func secureDir(dir, account string) error {
	readers, writers := "", ""
	if account != "" {
		sid, _, _, err := windows.LookupSID("", account)
		if err != nil {
			return err
		}
		readers = "(A;OICI;FR;;;" + sid.String() + ")"
		writers = "(A;OICI;0x1301bf;;;" + sid.String() + ")"
	}
	configFile := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "state")
	for _, path := range []string{dir, configFile, state} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if path == state && errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if sd == nil {
			return fmt.Errorf("%s has no security descriptor", path)
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
			return fmt.Errorf("%s is owned by %s; recreate the folder as administrator", path, owner)
		}
	}
	if err := os.Mkdir(state, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	targets := []struct {
		path       string
		dacl       string
		protection windows.SECURITY_INFORMATION
	}{
		{dir, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + readers, windows.PROTECTED_DACL_SECURITY_INFORMATION},
		{configFile, "D:", windows.UNPROTECTED_DACL_SECURITY_INFORMATION},
		{state, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + writers, windows.PROTECTED_DACL_SECURITY_INFORMATION},
	}
	for _, target := range targets {
		sd, err := windows.SecurityDescriptorFromString("O:BA" + target.dacl)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		parts := windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | target.protection
		if err := windows.SetNamedSecurityInfo(target.path, windows.SE_FILE_OBJECT, parts, owner, nil, dacl, nil); err != nil {
			return fmt.Errorf("%s: %w", target.path, err)
		}
	}
	return nil
}

func install(dir, account string) error {
	if err := secureDir(dir, account); err != nil {
		return err
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return err
	}
	var attributes windows.OBJECT_ATTRIBUTES
	var policy uintptr
	if status, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attributes)), 0x10|0x800, uintptr(unsafe.Pointer(&policy))); status != 0 {
		return windows.NTStatus(status)
	}
	defer procLsaClose.Call(policy)
	right, err := windows.NewNTUnicodeString("SeServiceLogonRight")
	if err != nil {
		return err
	}
	if status, _, _ := procLsaAddAccountRights.Call(policy, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(right)), 1); status != 0 {
		return windows.NTStatus(status)
	}
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	settings := mgr.Config{
		DisplayName:      "Thero Connect",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: account,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	service, err := manager.CreateService(serviceName, executable, settings, "run", "-dir", dir)
	if err != nil {
		return err
	}
	defer service.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: time.Minute}
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
		return err
	}
	return service.Start()
}

func uninstall() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return errors.Join(err, eventlog.Remove(serviceName))
	}
	defer service.Close()
	status, err := service.Control(svc.Stop)
	for deadline := time.Now().Add(30 * time.Second); err == nil && status.State != svc.Stopped && time.Now().Before(deadline); {
		time.Sleep(time.Second)
		status, err = service.Query()
	}
	return errors.Join(service.Delete(), eventlog.Remove(serviceName))
}

func logOutput(service bool) io.Writer {
	if !service {
		return os.Stderr
	}
	log, err := eventlog.Open(serviceName)
	if err != nil {
		return os.Stderr
	}
	return eventWriter{log}
}

func (w eventWriter) Write(p []byte) (int, error) {
	var err error
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		switch {
		case strings.Contains(line, "level=ERROR"):
			err = w.log.Error(1, line)
		case strings.Contains(line, "level=WARN"):
			err = w.log.Warning(1, line)
		default:
			err = w.log.Info(1, line)
		}
	}
	return len(p), err
}

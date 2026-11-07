package core

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

var version = "dev"

type config struct {
	Proxy        string   `yaml:"proxy"`
	Principal    string   `yaml:"principal"`
	SambaServers []string `yaml:"samba_servers"`
	Roots        []root   `yaml:"roots"`
	Limits       limits   `yaml:"limits"`
	samba        map[string]bool
}

type root struct {
	ID      string   `yaml:"id"`
	Path    string   `yaml:"path"`
	Exclude []string `yaml:"exclude"`
	Server  string   `yaml:"server"`
}

type limits struct {
	MaxFileMB   int    `yaml:"max_file_mb"`
	MaxGBPerDay int    `yaml:"max_gb_per_day"`
	MaxMbit     int    `yaml:"max_mbit"`
	ReadWindow  string `yaml:"read_window"`
}

var rootPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type Platform struct {
	Dir        string
	Source     func(dir, principal string, samba map[string]bool) (Source, error)
	Protect    func([]byte) ([]byte, error)
	Unprotect  func([]byte) ([]byte, error)
	SecureDir  func(dir, account string) error
	Install    func(dir, account string) error
	Uninstall  func() error
	RunService func(run func(context.Context) error) error
	Log        io.Writer
}

var host Platform

func Main(p Platform) {
	host = p
	slog.SetDefault(slog.New(slog.NewTextHandler(host.Log, nil)))
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: thero-connect enroll|run|install|uninstall|check [flags]")
		os.Exit(2)
	}
	if err := command(os.Args[1], os.Args[2:]); err != nil {
		slog.Error(os.Args[1]+" failed", "error", err)
		os.Exit(1)
	}
}

func command(name string, args []string) error {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	dir := flags.String("dir", host.Dir, "configuration folder")
	switch name {
	case "enroll":
		link := flags.String("url", "", "link address wss://host[:port]")
		pin := flags.String("ca", "", "sha256 of the connect CA certificate")
		token := flags.String("token", "", "one-time enrollment token, read from standard input when empty")
		if err := flags.Parse(args); err != nil {
			return err
		}
		cfg, err := loadConfig(*dir)
		if err != nil {
			return err
		}
		if err := host.SecureDir(*dir, ""); err != nil {
			return err
		}
		if _, err := host.Source(*dir, cfg.Principal, cfg.samba); err != nil {
			return err
		}
		if *token == "" {
			fmt.Fprint(os.Stderr, "Enrollment token: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			*token = strings.TrimSpace(line)
		}
		if *token == "" {
			return errors.New("enter the enrollment token")
		}
		machine, err := enroll(context.Background(), *dir, cfg, *link, *pin, *token)
		if err != nil {
			return err
		}
		fmt.Println("enrolled as", machine)
		return nil
	case "run":
		if err := flags.Parse(args); err != nil {
			return err
		}
		cfg, err := loadConfig(*dir)
		if err != nil {
			return err
		}
		src, err := host.Source(*dir, cfg.Principal, cfg.samba)
		if err != nil {
			return err
		}
		if host.RunService != nil {
			return host.RunService(func(ctx context.Context) error { return serve(ctx, *dir, cfg, src) })
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, *dir, cfg, src)
	case "install":
		account := flags.String("account", "", `service account DOMAIN\name$`)
		if err := flags.Parse(args); err != nil {
			return err
		}
		if *account == "" {
			return errors.New("-account is required")
		}
		cfg, err := loadConfig(*dir)
		if err != nil {
			return err
		}
		if _, err := host.Source(*dir, cfg.Principal, cfg.samba); err != nil {
			return err
		}
		if _, _, err := readIdentity(*dir); err != nil {
			return err
		}
		return host.Install(*dir, *account)
	case "uninstall":
		return host.Uninstall()
	case "check":
		if err := flags.Parse(args); err != nil {
			return err
		}
		return check(*dir)
	}
	return fmt.Errorf("unknown command %q", name)
}

func check(dir string) error {
	failed := false
	report := func(name string, err error) bool {
		if err != nil {
			fmt.Printf("fail %s: %v\n", name, err)
			failed = true
			return false
		}
		fmt.Printf("ok   %s\n", name)
		return true
	}
	cfg, err := loadConfig(dir)
	configured := report("config", err)
	id, cert, err := readIdentity(dir)
	enrolled := report("identity", err)
	if enrolled {
		days := int(time.Until(cert.Leaf.NotAfter).Hours() / 24)
		if days < 0 {
			report("certificate", errors.New("expired, enroll again"))
		} else {
			report(fmt.Sprintf("certificate (%d days left)", days), nil)
		}
	}
	src, err := host.Source(dir, cfg.Principal, cfg.samba)
	if report("source", err) {
		probe := &agent{cfg: cfg, src: src}
		for _, r := range cfg.Roots {
			budget := referralHops
			target, _, err := probe.locate(r.Path, "", map[string]bool{}, &budget)
			if !report("root "+r.ID+" list", err) {
				continue
			}
			if target != r.Path {
				report("root "+r.ID+" target "+target, nil)
			}
			share, err := src.Share(shareOf(target))
			if !report("root "+r.ID+" share", err) || !report("root "+r.ID+" share descriptor", supported(share)) {
				continue
			}
			server, _, _ := SplitUNC(target)
			_, err = src.Allowed(server, nil, [][]byte{share})
			report("root "+r.ID+" authz", err)
		}
		_, err := src.Accounts("(&(objectCategory=person)(objectClass=user)(mail=thero-connect-check@invalid))")
		report("directory", err)
	}
	if configured && enrolled {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		a := &agent{cfg: cfg, id: id}
		a.cert.Store(cert)
		conn, err := a.dial(ctx)
		if err == nil {
			conn.CloseNow()
		}
		report("link", err)
	}
	if failed {
		return errors.New("check failed")
	}
	return nil
}

func loadConfig(dir string) (config, error) {
	f, err := os.Open(filepath.Join(dir, "config.yaml"))
	if err != nil {
		return config{}, err
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)
	var cfg config
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("config.yaml: %w", err)
	}
	if len(cfg.Roots) == 0 || len(cfg.Roots) > 64 {
		return config{}, errors.New("config.yaml: 1 to 64 roots required")
	}
	ids := map[string]bool{}
	servers := map[string]string{}
	cfg.samba = map[string]bool{}
	for _, r := range cfg.Roots {
		if !rootPattern.MatchString(r.ID) || ids[r.ID] {
			return config{}, fmt.Errorf("config.yaml: invalid or duplicate root id %q", r.ID)
		}
		ids[r.ID] = true
		server, _, err := SplitUNC(r.Path)
		if err != nil {
			return config{}, fmt.Errorf("config.yaml: root %s: %w", r.ID, err)
		}
		kind := r.Server
		if kind == "" {
			kind = "windows"
		}
		if kind != "windows" && kind != "samba" {
			return config{}, fmt.Errorf("config.yaml: root %s: server must be windows or samba", r.ID)
		}
		server = strings.ToLower(server)
		if known, ok := servers[server]; ok && known != kind {
			return config{}, fmt.Errorf("config.yaml: root %s: host %s has roots with server windows and samba", r.ID, server)
		}
		servers[server] = kind
		if kind == "samba" {
			cfg.samba[server] = true
		}
		for _, pattern := range r.Exclude {
			if _, err := path.Match(pattern, ""); err != nil {
				return config{}, fmt.Errorf("config.yaml: root %s: exclude %q: %w", r.ID, pattern, err)
			}
		}
	}
	for _, name := range cfg.SambaServers {
		name = strings.ToLower(name)
		if !validHost(name) {
			return config{}, fmt.Errorf("config.yaml: samba_servers: invalid host %q", name)
		}
		if servers[name] == "windows" {
			return config{}, fmt.Errorf("config.yaml: host %s is listed in samba_servers and has roots with server windows", name)
		}
		cfg.samba[name] = true
	}
	if cfg.Limits.MaxFileMB < 0 || cfg.Limits.MaxGBPerDay < 0 || cfg.Limits.MaxMbit < 0 {
		return config{}, errors.New("config.yaml: limits must not be negative")
	}
	if cfg.Limits.MaxFileMB == 0 {
		cfg.Limits.MaxFileMB = 20
	}
	if cfg.Limits.MaxGBPerDay == 0 {
		cfg.Limits.MaxGBPerDay = 50
	}
	if cfg.Limits.MaxMbit == 0 {
		cfg.Limits.MaxMbit = 40
	}
	if cfg.Limits.ReadWindow != "" {
		if _, _, err := parseWindow(cfg.Limits.ReadWindow); err != nil {
			return config{}, fmt.Errorf("config.yaml: %w", err)
		}
	}
	if _, err := url.Parse(cfg.Proxy); err != nil {
		return config{}, fmt.Errorf("config.yaml: proxy: %w", err)
	}
	return cfg, nil
}

func statePath(dir, name string) string {
	return filepath.Join(dir, "state", name)
}

func writeFile(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	temp := name + ".tmp"
	if err := os.Remove(temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(temp)
		return err
	}
	return os.Rename(temp, name)
}

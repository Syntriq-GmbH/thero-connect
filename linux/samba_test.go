//go:build samba

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Syntriq-GmbH/thero-connect/core"
	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const (
	dc1 = "dc1.samdom.example.com"
	fs1 = "fs1.samdom.example.com"
)

var users = []string{"alice", "bob", "dave", "erin"}

func lab(t *testing.T) (*linuxSource, string, map[string]core.Account) {
	dir := os.Getenv("THERO_SAMBA_DIR")
	if dir == "" {
		t.Skip("THERO_SAMBA_DIR is not set")
	}
	source, err := newSource(dir, "svc-thero@SAMDOM.EXAMPLE.COM", map[string]bool{dc1: true, fs1: true})
	if err != nil {
		t.Fatal(err)
	}
	found, err := source.Accounts("(&(objectCategory=person)(objectClass=user)(|(mail=alice@samdom.example.com)(mail=bob@samdom.example.com)(mail=carol@samdom.example.com)(mail=dave@samdom.example.com)(mail=erin@samdom.example.com)))")
	if err != nil {
		t.Fatal(err)
	}
	accounts := map[string]core.Account{}
	for _, account := range found {
		name, _, _ := strings.Cut(account.Mail, "@")
		accounts[name] = account
	}
	if len(accounts) != 5 {
		t.Fatalf("accounts: got %d of 5", len(accounts))
	}
	return source.(*linuxSource), dir, accounts
}

func readers(t *testing.T, s *linuxSource, server, root string, sids []string, descriptors [][]byte) [][]bool {
	share, err := s.Share(root)
	if err != nil {
		t.Fatalf("share %s: %v", root, err)
	}
	rows, err := s.Allowed(server, sids, [][]byte{share})
	if err != nil {
		t.Fatalf("share rights %s: %v", root, err)
	}
	result := make([][]bool, len(sids))
	var passing []int
	var passingSIDs []string
	for k, row := range rows {
		result[k] = make([]bool, len(descriptors))
		if row[0] {
			passing = append(passing, k)
			passingSIDs = append(passingSIDs, sids[k])
		}
	}
	if len(passing) == 0 {
		return result
	}
	matrix, err := s.Allowed(server, passingSIDs, descriptors)
	if err != nil {
		t.Fatalf("rights %s: %v", root, err)
	}
	for i, k := range passing {
		result[k] = matrix[i]
	}
	return result
}

func TestSambaFresh(t *testing.T) {
	s, dir, accounts := lab(t)
	if !accounts["erin"].Enabled {
		t.Fatal("erin must be enabled before the fresh run")
	}
	if err := os.WriteFile(filepath.Join(dir, "erin.sid"), []byte(accounts["erin"].SID), 0o644); err != nil {
		t.Fatal(err)
	}
	root := `\\` + fs1 + `\docs`
	sd, _, err := s.Descriptor(root + `\builtindeny\x.txt`)
	if err != nil {
		t.Fatal(err)
	}
	var sids []string
	for _, name := range users {
		sids = append(sids, accounts[name].SID)
	}
	for k, row := range readers(t, s, fs1, root, sids, [][]byte{sd}) {
		if row[0] {
			t.Errorf("builtindeny/x.txt on fs1 before any logon: %s is a reader", users[k])
		}
	}
}

func TestSamba(t *testing.T) {
	s, dir, accounts := lab(t)
	erin, err := os.ReadFile(filepath.Join(dir, "erin.sid"))
	if err != nil {
		t.Fatal(err)
	}
	if accounts["erin"].SID != string(erin) || accounts["erin"].Enabled {
		t.Fatalf("erin must keep the recorded SID and be disabled: %+v", accounts["erin"])
	}
	if accounts["carol"].Enabled || !accounts["alice"].Enabled {
		t.Errorf("carol must be disabled and alice enabled: %+v %+v", accounts["carol"], accounts["alice"])
	}
	raw, err := os.ReadFile(filepath.Join(dir, "truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Server, Share, Path, User string
		Read                      bool
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	truth := map[string]bool{}
	for _, row := range rows {
		truth[row.Server+".samdom.example.com/"+row.Share+"/"+row.Path+"/"+row.User] = row.Read
	}

	conn, _, err := s.directory()
	if err != nil {
		t.Fatalf("sealed ldap bind with ldap/%s/samdom.example.com: %v", dc1, err)
	}
	conn.Close()

	var sids []string
	for _, name := range users {
		sids = append(sids, accounts[name].SID)
	}
	exact := []string{"alice/plan.txt", "shared/handbook.txt", "finance/budget.txt", "nested/n.txt", "hidden/secret.txt", "r/doc.txt", "noread/attrs.txt", "aliasdeny/x.txt"}
	ids := map[string]uint64{}
	checked := 0
	for _, root := range []struct{ server, share string }{{dc1, "docs"}, {fs1, "docs"}, {fs1, "restricted"}, {fs1, "ownerrights"}} {
		unc := `\\` + root.server + `\` + root.share
		share, err := s.Share(unc)
		if err != nil {
			t.Fatalf("share %s: %v", unc, err)
		}
		if _, err := s.Allowed(root.server, nil, [][]byte{share}); err != nil {
			t.Errorf("own rights on %s: %v", root.server, err)
		}
		var paths []string
		var descriptors [][]byte
		folders := []string{""}
		for len(folders) > 0 {
			folder := folders[0]
			folders = folders[1:]
			entries, err := s.List(strings.TrimSuffix(unc+`\`+strings.ReplaceAll(folder, "/", `\`), `\`))
			if err != nil {
				t.Fatalf("list %s %q: %v", unc, folder, err)
			}
			for _, entry := range entries {
				rel := strings.TrimPrefix(folder+"/"+entry.Name, "/")
				if entry.Dir {
					folders = append(folders, rel)
					continue
				}
				sd, id, err := s.Descriptor(unc + `\` + strings.ReplaceAll(rel, "/", `\`))
				if rel == "link/h.txt" {
					if err == nil {
						if file, err := s.Open(unc, `link\h.txt`); err == nil {
							file.Close()
							t.Errorf("%s: symlink link/h.txt opens", unc)
						}
					}
					continue
				}
				if err != nil {
					t.Errorf("descriptor %s %s: %v", unc, rel, err)
					continue
				}
				if id != entry.ID {
					t.Errorf("descriptor %s %s: id %d, listed %d", unc, rel, id, entry.ID)
				}
				ids[root.server+"/"+root.share+"/"+rel] = id
				paths = append(paths, rel)
				descriptors = append(descriptors, sd)
			}
		}
		matrix := readers(t, s, root.server, unc, sids, descriptors)
		for j, rel := range paths {
			var thero, samba []string
			for k, name := range users {
				if matrix[k][j] {
					thero = append(thero, name)
				}
				if truth[root.server+"/"+root.share+"/"+rel+"/"+name] {
					samba = append(samba, name)
				}
			}
			t.Logf("%s %s %-22s thero=%v samba=%v", root.server, root.share, rel, thero, samba)
			for k, name := range users {
				got := matrix[k][j]
				want, known := truth[root.server+"/"+root.share+"/"+rel+"/"+name]
				if !known && name != "erin" {
					t.Errorf("%s %s %s: no truth", root.server, root.share, rel)
					continue
				}
				checked++
				under := rel == "order/allow-first.txt" && name == "bob" || root.server == fs1 && rel == "dl/report.txt" || rel == "dlfsp/x.txt" || root.share == "ownerrights"
				switch {
				case got && !want:
					t.Errorf("OVER-GRANT %s %s %s %s: Thero reads, Samba refuses", root.server, root.share, rel, name)
				case got != want && slices.Contains(exact, rel):
					t.Errorf("%s %s %s %s: Thero %v, Samba %v", root.server, root.share, rel, name, got, want)
				case !got && want && !under:
					t.Errorf("under-grant %s %s %s %s: Thero false, Samba true", root.server, root.share, rel, name)
				case got && root.share == "ownerrights":
					t.Errorf("ownerrights reports %s for %s", name, rel)
				}
				if root.server == dc1 && (rel == "builtin/users.txt" || rel == "dl/report.txt") && got != want {
					t.Errorf("%s %s %s: Thero %v, Samba %v", root.server, rel, name, got, want)
				}
			}
		}
		for key := range truth {
			if strings.HasPrefix(key, root.server+"/"+root.share+"/") {
				rel := strings.TrimPrefix(key, root.server+"/"+root.share+"/")
				rel = rel[:strings.LastIndex(rel, "/")]
				if !slices.Contains(paths, rel) {
					t.Errorf("%s %s %s: in truth but not walked", root.server, root.share, rel)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("nothing checked")
	}

	for _, server := range []string{dc1, fs1} {
		file, err := s.Open(`\\`+server+`\docs`, `alice\plan.txt`)
		if err != nil {
			t.Fatalf("open plan.txt on %s: %v", server, err)
		}
		buffer := make([]byte, 262144)
		n, err := file.ReadAt(buffer, 0)
		if !errors.Is(err, io.EOF) || !bytes.Equal(buffer[:n], []byte("Alice only: kestrel-7341")) {
			t.Errorf("read plan.txt on %s: %q %v", server, buffer[:n], err)
		}
		info, err := file.Info()
		if err != nil || info.ID != ids[server+"/docs/alice/plan.txt"] || info.Size != int64(n) {
			t.Errorf("info plan.txt on %s: %+v %v", server, info, err)
		}
		file.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	session, err := (&smb2.Dialer{Credentials: s.smb, RequireMessageSigning: true}).Dial(ctx, fs1)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	share, err := session.Mount(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	other := tree{source: s, server: fs1, connection: &connection{session: session}, share: share}
	held, _, err := other.create(ctx, `busy\held.txt`, wire.FILE_READ_DATA|wire.SYNCHRONIZE, 0, wire.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Descriptor(`\\` + fs1 + `\docs\busy\held.txt`); err != nil {
		t.Errorf("descriptor of a file held deny-all: %v", err)
	}
	other.close(ctx, held)
	held, _, err = other.create(ctx, `busy\held.txt`, wire.FILE_WRITE_DATA|wire.SYNCHRONIZE, wire.FILE_SHARE_READ|wire.FILE_SHARE_WRITE|wire.FILE_SHARE_DELETE, wire.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		t.Fatal(err)
	}
	if file, err := s.Open(`\\`+fs1+`\docs`, `busy\held.txt`); !errors.Is(err, core.ErrBusy) {
		if file != nil {
			file.Close()
		}
		t.Errorf("open of a file held for write: %v, want busy", err)
	}
	other.close(ctx, held)

	s.mu.Lock()
	s.connections[fs1].session.Abort()
	s.mu.Unlock()
	if _, err := s.List(`\\` + fs1 + `\docs`); err != nil {
		t.Errorf("list after the server dropped the cached session: %v", err)
	}

	before := runtime.NumGoroutine()
	for range 10 {
		share, err := s.Share(`\\` + fs1 + `\docs`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Allowed(fs1, sids, [][]byte{share}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines grew from %d to %d over 10 rights cycles", before, after)
	}
}

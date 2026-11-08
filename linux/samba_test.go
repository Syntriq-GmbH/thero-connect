//go:build samba

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Syntriq-GmbH/thero-connect/core"
	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/dfs"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const (
	dc1    = "dc1.samdom.example.com"
	fs1    = "fs1.samdom.example.com"
	fs2    = "fs2.samdom.example.com"
	domain = "samdom.example.com"
)

var users = []string{"alice", "bob", "dave", "erin"}

func lab(t *testing.T) (*linuxSource, string, map[string]core.Account) {
	dir := os.Getenv("THERO_SAMBA_DIR")
	if dir == "" {
		t.Skip("THERO_SAMBA_DIR is not set")
	}
	source, err := newSource(dir, "svc-thero@SAMDOM.EXAMPLE.COM", map[string]bool{dc1: true, fs1: true, fs2: true})
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

func TestSambaDFS(t *testing.T) {
	s, dir, accounts := lab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ns := `\\` + fs1 + `\ns`

	ipc, _, err := s.tree(ctx, `\\`+dc1+`\IPC$`)
	if err != nil {
		t.Fatal(err)
	}
	names, err := dfs.NewClient(ipc.share).GetReferrals(ctx, `\`+domain)
	if err != nil || len(names.Entries) != 1 || names.Entries[0].Flags&dfs.FlagNameList == 0 {
		t.Fatalf("L1 domain controller referral: %+v %v", names, err)
	}
	t.Logf("L1 \\%s on dc1 IPC$: special %q expanded %q", domain, names.Entries[0].SpecialName, names.Entries[0].ExpandedNames)
	if !slices.ContainsFunc(names.Entries[0].ExpandedNames, func(name string) bool { return strings.EqualFold(name, `\`+dc1) }) {
		t.Errorf("L1: %s is not listed with a leading backslash", dc1)
	}
	proxy, err := dfs.NewClient(ipc.share).GetReferrals(ctx, `\\`+domain+`\corp`)
	if err != nil || len(proxy.Entries) != 1 || !strings.EqualFold(strings.Trim(proxy.Entries[0].NetworkAddress, `\`), fs1+`\ns`) {
		t.Fatalf("L2 proxy referral on dc1: %+v %v", proxy, err)
	}
	t.Logf("L2 \\\\%s\\corp on dc1 IPC$: prefix %q target %q server type %d header %#x", domain, proxy.Prefix, proxy.Entries[0].NetworkAddress, proxy.Entries[0].ServerType, proxy.HeaderFlags)

	root, _, err := s.tree(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	strict := `\\` + fs2 + `\ns3`
	statuses := map[string]uint32{ns + `\docs`: statusNotADirectory, ns + `\docs\shared`: statusPathNotCovered, strict + `\docs`: statusNotADirectory, strict + `\docs\shared`: statusStoppedOnSymlink}
	for _, share := range []string{ns, strict} {
		tr, _, err := s.tree(ctx, share)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"docs", `docs\shared`} {
			res, err := tr.share.Request().Append(&wire.CreateRequest{ImpersonationLevel: wire.Impersonation, DesiredAccess: wire.FILE_READ_ATTRIBUTES | wire.SYNCHRONIZE, ShareAccess: wire.FILE_SHARE_READ | wire.FILE_SHARE_WRITE, CreateDisposition: wire.FILE_OPEN, CreateOptions: wire.FILE_DIRECTORY_FILE | wire.FILE_OPEN_REPARSE_POINT, Name: name}).Do(ctx)
			var attributes uint32
			if err == nil {
				created, _ := res.Create(0)
				attributes = created.FileAttributes()
				res.Close()
				tr.close(ctx, created.FileId().Decode())
				if attributes&wire.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
					t.Errorf("L3 %s\\%s opens as a plain folder", share, name)
				}
			}
			t.Logf("L3 create %s\\%s with FILE_OPEN_REPARSE_POINT: status %#x attributes %#x", share, name, code(err), attributes)
			if code(err) != statuses[share+`\`+name] {
				t.Errorf("L3 %s\\%s: status %#x, want %#x", share, name, code(err), statuses[share+`\`+name])
			}
		}
		for _, path := range []string{share + `\docs`, share + `\docs\shared`, share + `\docs\x`} {
			_, err := s.List(path)
			t.Logf("L3 list %s: %v", path, err)
			if !errors.Is(err, core.ErrDenied) {
				t.Errorf("L3 list %s: %v, want denied (hold meets the link component)", path, err)
			}
		}
	}

	id, err := root.open(ctx, "", wire.FILE_LIST_DIRECTORY|wire.FILE_READ_ATTRIBUTES|wire.SYNCHRONIZE, wire.FILE_SHARE_READ|wire.FILE_SHARE_WRITE|wire.FILE_SHARE_DELETE, wire.FILE_DIRECTORY_FILE, true)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string][2]uint32{}
	for {
		res, err := root.share.Request().WithFileID(id).QueryDir(wire.FileIdBothDirectoryInformation, "*", readSize).Do(ctx)
		if code(err) == statusNoMoreFiles {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		query, err := res.QueryDir(0)
		if err != nil {
			t.Fatal(err)
		}
		items, err := query.FileIdBothDirectoryInformation()
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			raw[item.FileName()] = [2]uint32{item.FileAttributes(), item.EaSize()}
		}
		res.Close()
	}
	root.close(ctx, id)
	links := []string{"docs", "docs2", "failover", "loop", "nested", "offline", "projects", "replica", "restricted", "short"}
	for _, name := range append(slices.Clone(links), "plain", "sub", "locked") {
		t.Logf("L4 %-10s attributes %#08x EaSize %#08x", name, raw[name][0], raw[name][1])
	}
	t.Logf("L6 raw EaSize of ns/docs: %#x (IO_REPARSE_TAG_DFS %#x)", raw["docs"][1], uint32(wire.IO_REPARSE_TAG_DFS))
	for _, name := range links {
		if raw[name][0]&(wire.FILE_ATTRIBUTE_DIRECTORY|wire.FILE_ATTRIBUTE_REPARSE_POINT) != wire.FILE_ATTRIBUTE_DIRECTORY|wire.FILE_ATTRIBUTE_REPARSE_POINT || raw[name][1] != wire.IO_REPARSE_TAG_DFS {
			t.Errorf("L4 %s: attributes %#x EaSize %#x", name, raw[name][0], raw[name][1])
		}
	}
	entries, err := s.List(ns)
	if err != nil {
		t.Fatal(err)
	}
	var listed, plain []string
	for _, entry := range entries {
		if entry.Link {
			listed = append(listed, entry.Name)
		}
		if !entry.Link && entry.Dir {
			plain = append(plain, entry.Name)
		}
		if entry.Link && !entry.Dir {
			t.Errorf("L6 %s is a link but not a folder", entry.Name)
		}
	}
	slices.Sort(listed)
	slices.Sort(plain)
	if !slices.Equal(listed, links) || !slices.Equal(plain, []string{"locked", "plain", "sub"}) {
		t.Errorf("L6 links %v folders %v", listed, plain)
	}
	if entries, err := s.List(ns + `\sub`); err != nil || len(entries) != 1 || entries[0].Name != "deep" || !entries[0].Link {
		t.Errorf("L6 sub: %+v %v", entries, err)
	}

	locked, err := s.List(ns + `\locked`)
	inner, referralErr := s.Referral(ns + `\locked\inner`)
	t.Logf("L5 list of a folder the service account cannot open: %v %v; referral below it: %+v %v", locked, err, inner, referralErr)
	if !errors.Is(err, core.ErrDenied) {
		t.Errorf("L5 locked folder lists: %v", err)
	}

	self := func(r core.Referral) bool {
		return slices.ContainsFunc(slices.Concat(r.Sets...), func(target string) bool { return strings.EqualFold(target, r.Consumed) })
	}
	for _, test := range []struct {
		unc, consumed string
		targets       []string
		err           error
	}{
		{unc: ns, consumed: ns, targets: []string{ns}},
		{unc: ns + `\replica`, consumed: ns + `\replica`, targets: []string{`\\` + fs1 + `\replica`, `\\` + fs2 + `\replica`}},
		{unc: ns + `\docs\shared\handbook.txt`, consumed: ns + `\docs`, targets: []string{`\\` + fs1 + `\docs`}},
		{unc: ns + `\failover`, consumed: ns + `\failover`, targets: []string{`\\down.samdom.example.com\projects`, `\\` + fs2 + `\projects`}},
		{unc: ns + `\short`, consumed: ns + `\short`, targets: []string{`\\fs2\projects`}},
		{unc: ns + `\nested`, consumed: ns + `\nested`, targets: []string{`\\` + fs2 + `\ns2`}},
		{unc: `\\` + fs2 + `\ns2\back`, consumed: `\\` + fs2 + `\ns2\back`, targets: []string{`\\` + fs1 + `\restricted`}},
		{unc: ns + `\sub\deep`, consumed: ns + `\sub\deep`, targets: []string{`\\` + dc1 + `\docs\shared`}},
		{unc: ns + `\plain`, err: core.ErrNotFound},
		{unc: ns + `\plain\readme.txt`, err: core.ErrNotFound},
		{unc: `\\` + fs1 + `\docs`, err: core.ErrNotFound},
		{unc: `\\` + fs1 + `\nothing`, err: core.ErrNotFound},
		{unc: `\\` + domain + `\corp`, consumed: `\\` + domain + `\corp`, targets: []string{ns}},
		{unc: `\\` + strings.ToUpper(domain) + `\corp\docs\x`, consumed: `\\` + strings.ToUpper(domain) + `\corp`, targets: []string{ns}},
		{unc: `\\` + domain + `\nothing`, err: core.ErrUnavailable},
	} {
		got, err := s.Referral(test.unc)
		t.Logf("referral %-55s consumed %q sets %q error %v", test.unc, got.Consumed, got.Sets, err)
		if test.err != nil {
			if !errors.Is(err, test.err) || test.err == core.ErrUnavailable && errors.Is(err, core.ErrNotFound) {
				t.Errorf("%s: %v, want %v", test.unc, err, test.err)
			}
			continue
		}
		targets := slices.Concat(got.Sets...)
		slices.SortFunc(targets, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
		if err != nil || len(got.Sets) != 1 || !strings.EqualFold(got.Consumed, test.consumed) || !slices.EqualFunc(targets, test.targets, strings.EqualFold) {
			t.Errorf("%s: %+v %v, want %s %v", test.unc, got, err, test.consumed, test.targets)
		}
		if self(got) != (test.unc == ns) {
			t.Errorf("%s: self referral %v", test.unc, self(got))
		}
	}
	own, err := dfs.NewClient(ipc.share).GetReferrals(ctx, `\\`+domain+`\selfns`)
	if err != nil || len(own.Entries) != 1 || !strings.EqualFold(`\\`+strings.Trim(own.Entries[0].NetworkAddress, `\`), `\\`+domain+`\selfns`) {
		t.Fatalf("raw self referral of the domain: %+v %v", own, err)
	}
	if _, err := s.Referral(`\\` + domain + `\selfns`); !errors.Is(err, core.ErrUnavailable) || !strings.Contains(err.Error(), "refers to itself") {
		t.Errorf("self referral of the domain: %v", err)
	} else {
		t.Logf("referral \\\\%s\\selfns: dc1 answers %q, client: %v", domain, own.Entries[0].NetworkAddress, err)
	}
	sysvol, err := s.Referral(`\\` + domain + `\sysvol`)
	t.Logf("referral \\\\%s\\sysvol consumed %q sets %q error %v", domain, sysvol.Consumed, sysvol.Sets, err)
	if err != nil || !slices.ContainsFunc(slices.Concat(sysvol.Sets...), func(target string) bool { return strings.EqualFold(target, `\\`+dc1+`\sysvol`) }) {
		t.Errorf("sysvol: %+v %v", sysvol, err)
	}

	var sids []string
	for _, name := range users {
		sids = append(sids, accounts[name].SID)
	}
	for _, call := range []struct {
		name string
		run  func() error
	}{
		{"list", func() error { _, err := s.List(`\\` + domain + `\corp`); return err }},
		{"list sysvol", func() error { _, err := s.List(`\\` + strings.ToUpper(domain) + `\sysvol`); return err }},
		{"descriptor", func() error { _, _, err := s.Descriptor(`\\` + domain + `\corp\docs\shared\handbook.txt`); return err }},
		{"open", func() error { _, err := s.Open(`\\`+domain+`\corp`, `docs\shared\handbook.txt`); return err }},
		{"share", func() error { _, err := s.Share(`\\` + domain + `\corp`); return err }},
		{"allowed", func() error { _, err := s.Allowed(domain, sids, [][]byte{{1}}); return err }},
		{"allowed own", func() error { _, err := s.Allowed(strings.ToUpper(domain), nil, [][]byte{{1}}); return err }},
	} {
		start := time.Now()
		err := call.run()
		took := time.Since(start)
		t.Logf("%s on %s: %v after %v", call.name, domain, err, took)
		if !errors.Is(err, core.ErrUnavailable) || took > 100*time.Millisecond {
			t.Errorf("%s on %s: %v after %v", call.name, domain, err, took)
		}
	}
	s.mu.Lock()
	for server := range s.connections {
		if strings.EqualFold(server, domain) {
			t.Errorf("connection to %s", server)
		}
	}
	_, dialed := s.dialing[domain]
	_, failed := s.down[domain]
	t.Logf("servers with a connection: %v", slices.Sorted(maps.Keys(s.connections)))
	s.mu.Unlock()
	if dialed || failed {
		t.Errorf("%s was dialed", domain)
	}

	down := `\\down.samdom.example.com\projects`
	for i := range 2 {
		start := time.Now()
		_, err := s.Referral(down)
		took := time.Since(start)
		t.Logf("referral %s attempt %d: %v after %v", down, i+1, err, took)
		if !errors.Is(err, core.ErrUnavailable) || errors.Is(err, core.ErrNotFound) || took > 12*time.Second || i == 1 && took > 100*time.Millisecond {
			t.Errorf("dead host attempt %d: %v after %v", i+1, err, took)
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Server, Share, Path, User string
		Read                      bool
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	truth := map[string]bool{}
	for _, row := range rows {
		truth[row.Server+".samdom.example.com/"+row.Share+"/"+row.Path+"/"+row.User] = row.Read
	}
	var contents [][]byte
	var infos []core.FileInfo
	for _, file := range []struct{ server, share, rel string }{{fs1, "replica", "r/doc.txt"}, {fs2, "replica", "r/doc.txt"}, {fs1, "ns", "plain/readme.txt"}, {fs2, "projects", "p.txt"}} {
		share := `\\` + file.server + `\` + file.share
		rel := strings.ReplaceAll(file.rel, "/", `\`)
		sd, _, err := s.Descriptor(share + `\` + rel)
		if err != nil {
			t.Fatalf("descriptor %s %s: %v", share, rel, err)
		}
		matrix := readers(t, s, file.server, share, sids, [][]byte{sd})
		var thero, samba []string
		for k, name := range users {
			if matrix[k][0] {
				thero = append(thero, name)
			}
			want, known := truth[file.server+"/"+file.share+"/"+file.rel+"/"+name]
			if want {
				samba = append(samba, name)
			}
			if known && matrix[k][0] != want || !known && matrix[k][0] {
				t.Errorf("%s %s for %s: Thero %v, Samba %v", share, file.rel, name, matrix[k][0], want)
			}
		}
		t.Logf("%s %s: thero=%v samba=%v", share, file.rel, thero, samba)
		if file.share != "replica" {
			continue
		}
		opened, err := s.Open(share, rel)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		n, _ := opened.ReadAt(buffer, 0)
		info, err := opened.Info()
		opened.Close()
		if err != nil {
			t.Fatal(err)
		}
		contents = append(contents, buffer[:n])
		infos = append(infos, info)
	}
	if !bytes.Equal(contents[0], contents[1]) || infos[0].Size != infos[1].Size || !infos[0].Modified.Equal(infos[1].Modified) {
		t.Errorf("replica copies differ: %q %+v, %q %+v", contents[0], infos[0], contents[1], infos[1])
	}
	for path, target := range map[string]string{"docs/shared/handbook.txt": fs1 + "/docs/shared/handbook.txt", "projects/p.txt": fs2 + "/projects/p.txt", "sub/deep/handbook.txt": dc1 + "/docs/shared/handbook.txt", "nested/back/r/doc.txt": fs1 + "/restricted/r/doc.txt", "plain/readme.txt": fs1 + "/ns/plain/readme.txt"} {
		var readable []string
		for _, name := range []string{"alice", "bob", "dave"} {
			through, known := truth[fs1+"/ns/"+path+"/"+name]
			if through {
				readable = append(readable, name)
			}
			if !known || through != truth[target+"/"+name] {
				t.Errorf("%s through the namespace for %s: %v, physical %s: %v", path, name, through, target, truth[target+"/"+name])
			}
		}
		t.Logf("truth through \\\\%s\\ns\\%s equals %s: %v", fs1, path, target, readable)
	}
}

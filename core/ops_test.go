package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func testAgent(t *testing.T, src Source) *agent {
	cfg := config{
		Roots: []root{
			{ID: "finance", Path: `\\fs01\finance`, Exclude: []string{"~$*", "*.tmp", "Archive/Old"}},
			{ID: "hr", Path: `\\fs01\hr`},
		},
		Limits: limits{MaxFileMB: 20, MaxGBPerDay: 50, MaxMbit: 100000},
	}
	a, err := newAgent(t.TempDir(), cfg, src)
	if err != nil {
		t.Fatal(err)
	}
	walkedMounts(a)
	return a
}

func walkedMounts(a *agent) {
	for _, r := range a.cfg.Roots {
		a.mounts[r.ID] = mountTable{Path: r.Path, Targets: map[string]string{"": r.Path}}
	}
	a.save("mounts.json", a.mounts)
}

func openWindow() *transfer {
	t := &transfer{notify: make(chan struct{}, 1), stop: func() {}}
	t.acked.Store(1 << 62)
	return t
}

func walkAll(t *testing.T, a *agent, rootID string) []pageEntry {
	var entries []pageEntry
	cursor := ""
	for {
		reply := a.walk(message{Type: "walk", ID: 1, Root: rootID, Cursor: cursor})
		page, ok := reply.(pageMessage)
		if !ok {
			t.Fatalf("walk answered %+v", reply)
		}
		entries = append(entries, page.Entries...)
		if page.Cursor == "" {
			return entries
		}
		cursor = page.Cursor
	}
}

func readFile(a *agent, root, rel string, f *fakeFile) (string, any) {
	var data []byte
	reply := a.read(context.Background(), message{Type: "read", ID: 3, Root: root, Path: rel, File: fmt.Sprintf("%016x", f.id), Size: int64(len(f.data)), Modified: f.modified.UnixMilli()}, openWindow(), func(frame []byte) error {
		data = append(data, frame[4:]...)
		return nil
	})
	return string(data), reply
}

func codeOfReply(reply any) string {
	if refusal, ok := reply.(errorMessage); ok {
		return refusal.Code
	}
	if _, ok := reply.(doneMessage); ok {
		return "done"
	}
	return fmt.Sprintf("%T", reply)
}

func TestWalkPagesAndCursor(t *testing.T) {
	src := newFakeSource()
	for i := range 1200 {
		src.add(fmt.Sprintf(`\\fs01\finance\d%d\f%04d.txt`, i%3, i), "x", readable("S-1-1-0"))
	}
	a := testAgent(t, src)
	first := a.walk(message{Type: "walk", ID: 1, Root: "finance"}).(pageMessage)
	if len(first.Entries) != 500 || !regexp.MustCompile(`^[0-9a-f]{16}-1$`).MatchString(first.Cursor) {
		t.Fatalf("first page %d entries, cursor %q", len(first.Entries), first.Cursor)
	}
	if refusal := a.walk(message{Type: "walk", ID: 2, Root: "finance", Cursor: "0123456789abcdef-1"}); codeOfReply(refusal) != "cursor" {
		t.Fatalf("unknown cursor answered %+v", refusal)
	}
	second := a.walk(message{Type: "walk", ID: 3, Root: "finance", Cursor: first.Cursor}).(pageMessage)
	if len(second.Entries) != 500 || second.Cursor != strings.TrimSuffix(first.Cursor, "1")+"2" {
		t.Fatalf("second page %d entries, cursor %q", len(second.Entries), second.Cursor)
	}
	if refusal := a.walk(message{Type: "walk", ID: 4, Root: "finance", Cursor: first.Cursor}); codeOfReply(refusal) != "cursor" {
		t.Fatalf("stale cursor answered %+v", refusal)
	}
	third := a.walk(message{Type: "walk", ID: 5, Root: "finance", Cursor: second.Cursor}).(pageMessage)
	if len(third.Entries) != 200 || third.Cursor != "" {
		t.Fatalf("third page %d entries, cursor %q", len(third.Entries), third.Cursor)
	}
	seen := map[string]bool{}
	for _, e := range slices.Concat(first.Entries, second.Entries, third.Entries) {
		seen[e.Path] = true
	}
	if len(seen) != 1200 {
		t.Fatalf("%d unique paths", len(seen))
	}
	if refusal := a.walk(message{Type: "walk", ID: 6, Root: "finance", Cursor: second.Cursor}); codeOfReply(refusal) != "cursor" {
		t.Fatalf("cursor of a finished walk answered %+v", refusal)
	}
}

func TestWalkSkipsExcludedOversizeAndLongPaths(t *testing.T) {
	src := newFakeSource()
	sd := readable("S-1-1-0")
	src.add(`\\fs01\finance\ok.txt`, "ok", sd)
	src.add(`\\fs01\finance\Reports\~$draft.docx`, "lock", sd)
	src.add(`\\fs01\finance\cache.tmp`, "tmp", sd)
	src.add(`\\fs01\finance\Archive\Old\b.pdf`, "old", sd)
	src.add(`\\fs01\finance\archive\OLD\c.pdf`, "old", sd)
	src.add(`\\fs01\finance\big.bin`, strings.Repeat("x", 20<<20+1), sd)
	src.add(`\\fs01\finance\`+strings.Repeat("d", 1020)+`\long.txt`, "long", sd)
	src.add(`\\fs01\finance\aux.txt`, "device", sd)
	src.add(`\\fs01\finance\trailing.`, "dot", sd)
	src.add(`\\fs01\finance\con\inside.txt`, "device folder", sd)
	entries := walkAll(t, testAgent(t, src), "finance")
	if len(entries) != 1 || entries[0].Path != "ok.txt" || entries[0].Size != 2 {
		t.Fatalf("entries %+v", entries)
	}
}

func TestWalkReportsIncompleteDirectory(t *testing.T) {
	src := newFakeSource()
	src.add(`\\fs01\finance\a\x.txt`, "x", readable("S-1-1-0"))
	src.add(`\\fs01\finance\b\y.txt`, "y", readable("S-1-1-0"))
	src.failures[`list:\\fs01\finance\b`] = ErrDenied
	page := testAgent(t, src).walk(message{Type: "walk", ID: 1, Root: "finance"}).(pageMessage)
	if len(page.Entries) != 1 || page.Entries[0].Path != "a/x.txt" || !slices.Equal(page.Incomplete, []string{"b"}) || page.Cursor != "" {
		t.Fatalf("page %+v", page)
	}
}

func TestWalkRootFailure(t *testing.T) {
	src := newFakeSource()
	src.failures[`list:\\fs01\finance`] = ErrDenied
	a := testAgent(t, src)
	if reply := a.walk(message{Type: "walk", ID: 1, Root: "finance"}); codeOfReply(reply) != "denied" {
		t.Fatalf("root failure answered %+v", reply)
	}
	src.failures[`list:\\fs01\finance`] = ErrNotFound
	if reply := a.walk(message{Type: "walk", ID: 2, Root: "finance"}); codeOfReply(reply) != "not_found" {
		t.Fatalf("missing root answered %+v", reply)
	}
	if reply := a.walk(message{Type: "walk", ID: 3, Root: "nope"}); codeOfReply(reply) != "bad_request" {
		t.Fatalf("unknown root answered %+v", reply)
	}
}

func TestWalkClassCacheReusesUnchangedFiles(t *testing.T) {
	src := newFakeSource()
	src.add(`\\fs01\finance\a.txt`, "a", readable("S-1-5-21-1-2-3-1104"))
	src.add(`\\fs01\finance\b.txt`, "b", readable("S-1-5-21-1-2-3-1104"))
	changed := src.add(`\\fs01\finance\c.txt`, "c", readable("S-1-5-21-1-2-3-1104"))
	a := testAgent(t, src)
	before := walkAll(t, a, "finance")
	if src.descriptorCalls != 3 {
		t.Fatalf("%d descriptor reads on the first walk", src.descriptorCalls)
	}
	changed.changed = changed.changed.Add(time.Second)
	changed.sd = readable("S-1-5-21-1-2-3-1105")
	after := walkAll(t, a, "finance")
	if src.descriptorCalls != 4 {
		t.Fatalf("%d descriptor reads after one change", src.descriptorCalls)
	}
	if *after[0].Class != *before[0].Class || *after[2].Class == *before[2].Class {
		t.Fatalf("classes %v %v", *before[2].Class, *after[2].Class)
	}
}

func TestWalkUnsupportedDescriptorHasNoClass(t *testing.T) {
	src := newFakeSource()
	src.add(`\\fs01\finance\good.txt`, "g", readable("S-1-5-21-1-2-3-1104"))
	src.add(`\\fs01\finance\network.txt`, "n", descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(1, 0, 0x1, "S-1-5-2"), aceBytes(0, 0, 0x1200a9, "S-1-1-0")), nil))
	src.add(`\\fs01\finance\unreadable.txt`, "u", readable("S-1-1-0"))
	src.failures[`descriptor:\\fs01\finance\unreadable.txt`] = ErrDenied
	a := testAgent(t, src)
	entries := walkAll(t, a, "finance")
	if len(entries) != 3 || entries[0].Class == nil || entries[1].Class != nil || entries[2].Class != nil {
		t.Fatalf("entries %+v", entries)
	}
	if len(a.classes) != 1 {
		t.Fatalf("registry %v", a.classes)
	}
	data, _ := json.Marshal(entries[1])
	if !strings.Contains(string(data), `"class":null`) {
		t.Fatalf("encoded %s", data)
	}
}

func TestWalkDescriptorOfAnotherFileHasNoClass(t *testing.T) {
	src := newFakeSource()
	src.add(`\\fs01\finance\a.txt`, "a", readable("S-1-5-21-1-2-3-1104"))
	swapped := src.add(`\\fs01\finance\b.txt`, "b", readable("S-1-5-21-1-2-3-1105"))
	swapped.handle = 99
	a := testAgent(t, src)
	entries := walkAll(t, a, "finance")
	if len(entries) != 2 || entries[0].Class == nil || entries[1].Class != nil {
		t.Fatalf("entries %+v", entries)
	}
	if len(a.classes) != 1 {
		t.Fatalf("registry %v", a.classes)
	}
}

func TestWalkPrunesClassesAfterCompleteWalk(t *testing.T) {
	src := newFakeSource()
	src.add(`\\fs01\finance\a.txt`, "a", readable("S-1-5-21-1-2-3-1104"))
	src.add(`\\fs01\finance\b.txt`, "b", readable("S-1-5-21-1-2-3-1105"))
	src.add(`\\fs01\hr\c.txt`, "c", readable("S-1-5-21-1-2-3-1106"))
	a := testAgent(t, src)
	walkAll(t, a, "finance")
	walkAll(t, a, "hr")
	if len(a.classes) != 3 {
		t.Fatalf("registry %v", a.classes)
	}
	delete(src.files, `\\fs01\finance\b.txt`)
	walkAll(t, a, "finance")
	stored := map[string]classEntry{}
	data, _ := os.ReadFile(statePath(a.dir, "classes.json"))
	json.Unmarshal(data, &stored)
	roots := []string{}
	for _, entry := range stored {
		roots = append(roots, entry.Root)
	}
	slices.Sort(roots)
	if len(a.classes) != 2 || !slices.Equal(roots, []string{"finance", "hr"}) {
		t.Fatalf("registry %v, stored %v", a.classes, roots)
	}
	restarted, _ := newAgent(a.dir, a.cfg, src)
	if len(restarted.classes) != 2 {
		t.Fatalf("restarted registry %v", restarted.classes)
	}
}

func TestLoadDropsForeignClassEntries(t *testing.T) {
	alice := "S-1-5-21-1-2-3-1104"
	src := newFakeSource()
	src.add(`\\fs01\hr\salaries.xlsx`, "s", readable(alice))
	src.shares[`\\fs01\hr`] = readable("S-1-1-0")
	a := testAgent(t, src)
	hrClass := classOf("hr", readable(alice))
	unsupported := descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(1, 0, 0x1, "S-1-5-2"), aceBytes(0, 0, 0x1200a9, "S-1-1-0")), nil)
	planted, _ := json.Marshal(map[string]classEntry{
		hrClass:                                        {Root: "hr", SD: readable("S-1-1-0")},
		classOf("finance", readable(alice)):            {Root: "hr", SD: readable(alice)},
		classOf("hr", unsupported):                     {Root: "hr", SD: unsupported},
		classOf("hr", readable("S-1-5-21-1-2-3-1105")): {Root: "hr", SD: readable("S-1-5-21-1-2-3-1105")},
	})
	if err := writeFile(statePath(a.dir, "classes.json"), planted); err != nil {
		t.Fatal(err)
	}
	loaded, err := newAgent(a.dir, a.cfg, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.classes) != 1 {
		t.Fatalf("registry %v", loaded.classes)
	}
	entries := walkAll(t, loaded, "hr")
	if len(entries) != 1 || entries[0].Class == nil || *entries[0].Class != hrClass {
		t.Fatalf("entries %+v", entries)
	}
	rights := loaded.access(message{Type: "access", ID: 4, SIDs: []string{alice, "S-1-5-21-1-2-3-1107"}}).(rightsMessage)
	if len(rights.Classes) != 1 || rights.Classes[0].Class != hrClass || !slices.Equal(rights.Classes[0].Readers, []int{0}) {
		t.Fatalf("rights %+v", rights.Classes)
	}
}

func TestPrincipalsBatchesAndAmbiguity(t *testing.T) {
	src := newFakeSource()
	src.accountList = []Account{
		{SID: "S-1-5-21-1-1", GUID: "a", Mail: "user0@example.com", Proxies: []string{"user119@example.com"}, Enabled: true},
		{SID: "S-1-5-21-1-2", GUID: "b", UPN: "user50@example.com", Enabled: true},
	}
	var emails []string
	for i := range 120 {
		emails = append(emails, fmt.Sprintf("user%d@example.com", i))
	}
	emails = append(emails, "USER0@example.com")
	a := testAgent(t, src)
	users := a.principals(message{Type: "principals", ID: 2, Emails: emails}).(usersMessage)
	if len(src.filters) != 3 {
		t.Fatalf("%d directory searches", len(src.filters))
	}
	got := map[string]bool{}
	for _, u := range users.Users {
		got[u.Email] = u.Ambiguous
	}
	if fmt.Sprint(got) != fmt.Sprint(map[string]bool{"user0@example.com": true, "user119@example.com": true, "user50@example.com": false}) {
		t.Fatalf("users %v", got)
	}
	src.failures["accounts"] = fmt.Errorf("ldap: %w", ErrUnavailable)
	if reply := a.principals(message{Type: "principals", ID: 3, Emails: emails}); codeOfReply(reply) != "unavailable" {
		t.Fatalf("directory failure answered %+v", reply)
	}
}

func TestAccessReadersAndRootErrors(t *testing.T) {
	alice, bob, carol, dave := "S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-1107"
	src := newFakeSource()
	src.shares[`\\fs01\finance`] = readable(alice, bob, dave)
	src.failures["user:"+dave] = ErrUnavailable
	src.failures[`share:\\fs01\hr`] = ErrDenied
	src.shares[`\\fs02\legal`] = descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(1, 0, 0x1, "S-1-5-2"), aceBytes(0, 0, 0x1200a9, "S-1-1-0")), nil)
	src.failures["allowed:fs03"] = ErrUnavailable
	a := testAgent(t, src)
	a.cfg.Roots = []root{{ID: "finance", Path: `\\fs01\finance`}, {ID: "hr", Path: `\\fs01\hr`}, {ID: "legal", Path: `\\fs02\legal`}, {ID: "ops", Path: `\\fs03\ops`}}
	walkedMounts(a)
	for _, r := range a.cfg.Roots {
		a.walked[r.ID] = a.now()
	}
	register := func(rootID string, sd []byte) string {
		id := classOf(rootID, sd)
		a.classes[id] = classEntry{Root: rootID, SD: sd}
		return id
	}
	aliceOnly := register("finance", readable(alice, dave))
	shared := register("finance", readable(alice, bob, carol, dave))
	others := []string{register("hr", readable(alice)), register("legal", readable(alice)), register("ops", readable(alice)), register("old", readable(alice))}
	rights := a.access(message{Type: "access", ID: 3, SIDs: []string{alice, bob, carol, dave}}).(rightsMessage)
	readers := map[string][]int{}
	for _, c := range rights.Classes {
		readers[c.Class] = c.Readers
	}
	if len(readers) != 6 || !slices.Equal(readers[aliceOnly], []int{0}) || !slices.Equal(readers[shared], []int{0, 1}) {
		t.Fatalf("readers %v", readers)
	}
	for _, id := range others {
		if readers[id] == nil || len(readers[id]) != 0 {
			t.Fatalf("class %s of a failing or removed root has readers %v", id, readers[id])
		}
	}
	if fmt.Sprint(rights.Errors) != "[{hr denied} {legal unsupported} {ops unavailable}]" {
		t.Fatalf("errors %v", rights.Errors)
	}
	if fmt.Sprint(src.authzCalls[1]) != fmt.Sprint([]string{"fs01", alice, bob}) {
		t.Fatalf("file checks ran for %v", src.authzCalls[1])
	}
}

func TestAccessShareOwnerRights(t *testing.T) {
	admin := "S-1-5-21-1-2-3-500"
	src := newFakeSource()
	src.tokens = map[string]Token{admin: {Sure: map[string]bool{admin: true, "S-1-5-32-544": true, "S-1-1-0": true}}}
	src.shares[`\\fs01\finance`] = descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(0, 0, 0x1200a9, "S-1-3-4")), nil)
	src.shares[`\\files\projects`] = descriptorBytes("S-1-5-32-544", aclBytes(aceBytes(0, 0x0b, 0x1200a9, "S-1-3-4"), aceBytes(0, 0, 0x1200a9, "S-1-1-0")), nil)
	a := testAgent(t, src)
	a.cfg.Roots = []root{{ID: "finance", Path: `\\fs01\finance`}, {ID: "projects", Path: `\\files\projects`, Server: "samba"}, {ID: "legal", Path: `\\fs02\legal`}}
	a.cfg.samba = map[string]bool{"files": true}
	walkedMounts(a)
	finance := classOf("finance", readable("S-1-1-0"))
	projects := classOf("projects", readable("S-1-1-0"))
	a.classes[finance] = classEntry{Root: "finance", SD: readable("S-1-1-0")}
	a.classes[projects] = classEntry{Root: "projects", SD: readable("S-1-1-0")}
	legal := classOf("legal", readable("S-1-1-0"))
	a.classes[legal] = classEntry{Root: "legal", SD: readable("S-1-1-0")}
	for _, r := range a.cfg.Roots {
		a.walked[r.ID] = a.now()
	}
	if !Grants(src.tokens[admin], src.shares[`\\fs01\finance`]) {
		t.Fatal("the share descriptor alone would grant the administrator")
	}
	rights := a.access(message{Type: "access", ID: 4, SIDs: []string{admin}}).(rightsMessage)
	readers := map[string][]int{}
	for _, c := range rights.Classes {
		readers[c.Class] = c.Readers
	}
	if len(rights.Errors) != 0 || len(readers[finance]) != 0 || !slices.Equal(readers[projects], []int{0}) || !slices.Equal(readers[legal], []int{0}) {
		t.Fatalf("readers %v, errors %v", readers, rights.Errors)
	}
	if fmt.Sprint(src.authzCalls) != fmt.Sprint([][]string{{"files", admin}, {"files", admin}, {"fs02", admin}, {"fs02", admin}}) {
		t.Fatalf("authz calls %v", src.authzCalls)
	}
}

func TestAccessNeedsFreshWalk(t *testing.T) {
	bob := "S-1-5-21-1-2-3-1105"
	src := newFakeSource()
	src.shares[`\\fs01\finance`] = readable(bob)
	src.add(`\\fs01\finance\a.txt`, "content", readable(bob))
	a := testAgent(t, src)
	a.cfg.Roots = a.cfg.Roots[:1]
	readersOf := func(a *agent) ([]classReaders, string) {
		rights := a.access(message{Type: "access", ID: 2, SIDs: []string{bob}}).(rightsMessage)
		return rights.Classes, fmt.Sprint(rights.Errors)
	}
	if classes, errs := readersOf(a); len(classes) != 0 || errs != "[{finance unavailable}]" {
		t.Fatalf("before any walk %v %s", classes, errs)
	}
	walkAll(t, a, "finance")
	if classes, errs := readersOf(a); len(classes) != 1 || !slices.Equal(classes[0].Readers, []int{0}) || errs != "[]" {
		t.Fatalf("after a walk %v %s", classes, errs)
	}
	restarted, _ := newAgent(a.dir, a.cfg, src)
	if classes, _ := readersOf(restarted); len(classes) != 1 || len(classes[0].Readers) != 1 {
		t.Fatalf("after a restart %v", classes)
	}
	src.failures[`list:\\fs01\finance`] = ErrDenied
	a.walk(message{Type: "walk", ID: 1, Root: "finance"})
	if classes, errs := readersOf(a); len(classes) != 1 || len(classes[0].Readers) != 0 || errs != "[{finance unavailable}]" {
		t.Fatalf("after a failed walk %v %s", classes, errs)
	}
	delete(src.failures, `list:\\fs01\finance`)
	walkAll(t, a, "finance")
	a.now = func() time.Time { return time.Now().Add(snapshotAge + time.Minute) }
	if classes, errs := readersOf(a); len(classes) != 1 || len(classes[0].Readers) != 0 || errs != "[{finance unavailable}]" {
		t.Fatalf("with an old walk %v %s", classes, errs)
	}
}

func TestReadChargesEveryByteSent(t *testing.T) {
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, strings.Repeat("x", 3*chunkSize), readable("S-1-1-0"))
	a := testAgent(t, src)
	a.cfg.Limits.MaxGBPerDay = 1
	request := message{Type: "read", ID: 3, Root: "finance", Path: "a.txt", File: fmt.Sprintf("%016x", f.id), Size: int64(len(f.data)), Modified: f.modified.UnixMilli()}
	ctx, cancel := context.WithCancel(context.Background())
	a.read(ctx, request, openWindow(), func([]byte) error {
		cancel()
		return nil
	})
	if a.quota.Bytes != chunkSize {
		t.Fatalf("canceled read charged %d", a.quota.Bytes)
	}
	a.read(context.Background(), request, openWindow(), func([]byte) error { return os.ErrClosed })
	if a.quota.Bytes != 2*chunkSize {
		t.Fatalf("failed send charged %d", a.quota.Bytes-chunkSize)
	}
	a.quota.Bytes = 1<<30 - int64(len(f.data))
	var nested any
	reply := a.read(context.Background(), request, openWindow(), func([]byte) error {
		if nested == nil {
			_, nested = readFile(a, "finance", "a.txt", f)
		}
		return nil
	})
	if codeOfReply(reply) != "done" || codeOfReply(nested) != "limit" {
		t.Fatalf("concurrent reads answered %s and %s", codeOfReply(reply), codeOfReply(nested))
	}
	restarted, _ := newAgent(a.dir, a.cfg, src)
	if restarted.quota.Bytes != 1<<30 {
		t.Fatalf("quota after restart %d", restarted.quota.Bytes)
	}
}

func TestReadRejectsEscapes(t *testing.T) {
	src := newFakeSource()
	sd := readable("S-1-1-0")
	files := map[string]*fakeFile{
		"x.tmp":             src.add(`\\fs01\finance\x.tmp`, "t", sd),
		"Archive/Old/b.pdf": src.add(`\\fs01\finance\Archive\Old\b.pdf`, "b", sd),
		"archive/old/b.pdf": src.add(`\\fs01\finance\archive\old\b.pdf`, "b", sd),
		"Reports/~$a.docx":  src.add(`\\fs01\finance\Reports\~$a.docx`, "a", sd),
	}
	ok := src.add(`\\fs01\finance\ok.txt`, "ok", sd)
	a := testAgent(t, src)
	cases := map[string]string{
		"nope ok.txt":               "bad_request",
		"finance ../ok.txt":         "bad_request",
		"finance a/../../x":         "bad_request",
		"finance ok.txt:secret":     "bad_request",
		"finance ok.txt::$DATA":     "bad_request",
		"finance CON":               "bad_request",
		"finance dir/aux.txt":       "bad_request",
		`finance a\b`:               "bad_request",
		"finance /ok.txt":           "bad_request",
		"finance missing.txt":       "not_found",
		"finance x.tmp":             "not_found",
		"finance Archive/Old/b.pdf": "not_found",
		"finance archive/old/b.pdf": "not_found",
		"finance Reports/~$a.docx":  "not_found",
		"finance ok.txt":            "done",
	}
	for input, want := range cases {
		rootID, rel, _ := strings.Cut(input, " ")
		f := files[rel]
		if f == nil {
			f = ok
		}
		if _, reply := readFile(a, rootID, rel, f); codeOfReply(reply) != want {
			t.Errorf("%s answered %+v", input, reply)
		}
	}
}

func TestReadRevisionMismatch(t *testing.T) {
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, "content", readable("S-1-1-0"))
	a := testAgent(t, src)
	base := message{Type: "read", ID: 3, Root: "finance", Path: "a.txt", File: fmt.Sprintf("%016x", f.id), Size: 7, Modified: f.modified.UnixMilli()}
	variants := []func(m *message){
		func(m *message) { m.File = "00000000000000ff" },
		func(m *message) { m.Size = 8 },
		func(m *message) { m.Modified++ },
	}
	for i, change := range variants {
		m := base
		change(&m)
		if reply := a.read(t.Context(), m, openWindow(), func([]byte) error { return nil }); codeOfReply(reply) != "changed" {
			t.Errorf("variant %d answered %+v", i, reply)
		}
	}
	if data, reply := readFile(a, "finance", "a.txt", f); codeOfReply(reply) != "done" || data != "content" {
		t.Fatalf("read %q, %+v", data, reply)
	}
}

func TestReadChangedDuringRead(t *testing.T) {
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, "content", readable("S-1-1-0"))
	f.touch = true
	if _, reply := readFile(testAgent(t, src), "finance", "a.txt", f); codeOfReply(reply) != "changed" {
		t.Fatalf("read answered %+v", reply)
	}
}

func TestReadBusyAfterTwo(t *testing.T) {
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, "content", readable("S-1-1-0"))
	a := testAgent(t, src)
	a.slots <- struct{}{}
	a.slots <- struct{}{}
	if _, reply := readFile(a, "finance", "a.txt", f); codeOfReply(reply) != "busy" {
		t.Fatalf("third read answered %+v", reply)
	}
	<-a.slots
	if _, reply := readFile(a, "finance", "a.txt", f); codeOfReply(reply) != "done" {
		t.Fatalf("read with a free slot answered %+v", reply)
	}
	if len(a.slots) != 1 {
		t.Fatalf("%d slots taken after the read", len(a.slots))
	}
}

func TestReadQuotaPersistsAcrossRestart(t *testing.T) {
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, "12345", readable("S-1-1-0"))
	a := testAgent(t, src)
	a.cfg.Limits.MaxGBPerDay = 1
	readFile(a, "finance", "a.txt", f)
	restarted, _ := newAgent(a.dir, a.cfg, src)
	if restarted.quota.Bytes != 5 || restarted.quota.Day != time.Now().Format(time.DateOnly) {
		t.Fatalf("quota after restart %+v", restarted.quota)
	}
	data, _ := json.Marshal(quota{Day: time.Now().Format(time.DateOnly), Bytes: 1<<30 - 4})
	writeFile(statePath(a.dir, "quota.json"), data)
	restarted, _ = newAgent(a.dir, a.cfg, src)
	if _, reply := readFile(restarted, "finance", "a.txt", f); codeOfReply(reply) != "limit" {
		t.Fatalf("read over quota answered %+v", reply)
	}
	data, _ = json.Marshal(quota{Day: "2000-01-01", Bytes: 1 << 30})
	writeFile(statePath(a.dir, "quota.json"), data)
	restarted, _ = newAgent(a.dir, a.cfg, src)
	if _, reply := readFile(restarted, "finance", "a.txt", f); codeOfReply(reply) != "done" {
		t.Fatalf("read on a new day answered %+v", reply)
	}
}

func TestReadWindow(t *testing.T) {
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, "a", readable("S-1-1-0"))
	a := testAgent(t, src)
	cases := []struct {
		window, clock, want string
	}{
		{"19:00-07:00", "12:00", "limit"},
		{"19:00-07:00", "19:00", "done"},
		{"19:00-07:00", "23:30", "done"},
		{"19:00-07:00", "06:59", "done"},
		{"19:00-07:00", "07:00", "limit"},
		{"09:00-17:00", "08:59", "limit"},
		{"09:00-17:00", "09:00", "done"},
		{"09:00-17:00", "17:00", "limit"},
		{"", "03:00", "done"},
	}
	for _, c := range cases {
		clock, _ := time.ParseInLocation("15:04", c.clock, time.Local)
		a.now = func() time.Time { return time.Date(2026, 11, 1, clock.Hour(), clock.Minute(), 0, 0, time.Local) }
		a.cfg.Limits.ReadWindow = c.window
		if _, reply := readFile(a, "finance", "a.txt", f); codeOfReply(reply) != c.want {
			t.Errorf("window %s at %s answered %+v", c.window, c.clock, reply)
		}
	}
}

func TestReadRateLimit(t *testing.T) {
	var l limiter
	start := time.Unix(1761990000, 0)
	bytesPerSecond := int64(40) * 125000
	waits := []time.Duration{
		l.delay(start, chunkSize, bytesPerSecond),
		l.delay(start, chunkSize, bytesPerSecond),
		l.delay(start.Add(10*time.Millisecond), chunkSize, bytesPerSecond),
		l.delay(start.Add(time.Second), chunkSize, bytesPerSecond),
	}
	want := []time.Duration{0, 52428800 * time.Nanosecond, 94857600 * time.Nanosecond, 0}
	if !slices.Equal(waits, want) {
		t.Fatalf("waits %v", waits)
	}
}

func TestAtomicWriteReplacesPlantedTemp(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	target := statePath(dir, "quota.json")
	os.MkdirAll(filepath.Dir(target), 0o700)
	if err := os.Link(victim, target+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(target, []byte("new")); err != nil {
		t.Fatal(err)
	}
	kept, _ := os.ReadFile(victim)
	written, _ := os.ReadFile(target)
	if string(kept) != "keep" || string(written) != "new" {
		t.Fatalf("victim %q, target %q", kept, written)
	}
	if _, err := os.Lstat(target + ".tmp"); err == nil {
		t.Fatal("temporary file left behind")
	}
}

func TestWalkChangesOnFileShare(t *testing.T) {
	src := newFakeSource()
	src.add(`\\fs01\finance\a.txt`, "content", readable("S-1-1-0"))
	a := testAgent(t, src)
	reply := a.walk(message{Type: "walk", ID: 1, Root: "finance", Changes: true})
	if refusal, ok := reply.(errorMessage); !ok || refusal.Code != "bad_request" || refusal.Message != "changes on a file share" {
		t.Fatalf("changes walk on a file share answered %+v", reply)
	}
	if entries := walkAll(t, a, "finance"); len(entries) != 1 || a.sites != nil {
		t.Fatalf("file share walk after a changes request: %d entries", len(entries))
	}
}

func dfsAgent(t *testing.T, src *fakeSource, roots ...root) *agent {
	a, err := newAgent(t.TempDir(), config{Roots: roots, Limits: limits{MaxFileMB: 20, MaxGBPerDay: 50, MaxMbit: 100000}}, src)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func refer(src *fakeSource, unc string, sets ...[]string) {
	src.referrals[strings.ToLower(unc)] = Referral{Consumed: unc, Sets: sets}
}

func namespace(src *fakeSource) {
	refer(src, `\\fs1.corp\ns`, []string{`\\fs1.corp\ns`})
	src.add(`\\fs1.corp\ns\readme.txt`, "root", readable("S-1-5-21-1-2-3-1104"))
}

func byPath(entries []pageEntry) map[string]pageEntry {
	found := map[string]pageEntry{}
	for _, e := range entries {
		found[e.Path] = e
	}
	return found
}

func TestWalkPlainRootUnchanged(t *testing.T) {
	src := newFakeSource()
	sd := readable("S-1-5-21-1-2-3-1104")
	a1 := src.add(`\\fs01\finance\a.txt`, "a", sd)
	b := src.add(`\\fs01\finance\d\b.txt`, "b", sd)
	a := testAgent(t, src)
	entries := walkAll(t, a, "finance")
	data, _ := json.Marshal(entries)
	class := classOf("finance", sd)
	want := fmt.Sprintf(`[{"path":"a.txt","file":"%016x","size":1,"created":1761990000000,"modified":1761990000000,"class":"%s"},{"path":"d/b.txt","file":"%016x","size":1,"created":1761990000000,"modified":1761990000000,"class":"%s"}]`, a1.id, class, b.id, class)
	if string(data) != want {
		t.Fatalf("page entries %s, want %s", data, want)
	}
	if calls := src.called("referral:"); !slices.Equal(calls, []string{`\\fs01\finance`}) {
		t.Fatalf("referrals %v", calls)
	}
	if fmt.Sprint(a.mounts["finance"].Targets) != fmt.Sprint(map[string]string{"": `\\fs01\finance`}) || a.classes[class].Target != "" {
		t.Fatalf("mounts %v, registry %v", a.mounts, a.classes)
	}
}

func TestWalkStandaloneLink(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\docs`})
	sd := readable("S-1-5-21-1-2-3-1105")
	inner := src.add(`\\fs2.corp\docs\a\b.txt`, "b", sd)
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	entries := byPath(walkAll(t, a, "ns"))
	readme, linked := entries["readme.txt"], entries["docs/a/b.txt"]
	if len(entries) != 2 || readme.File != "0000000000000001" || *readme.Class != classOf("ns", readable("S-1-5-21-1-2-3-1104")) {
		t.Fatalf("root share entries %+v", entries)
	}
	if *linked.Class != classOf("ns\x00"+`\\fs2.corp\docs`, sd) || linked.File != fmt.Sprintf("%016x", inner.id^bind(`\\fs2.corp\docs`)) {
		t.Fatalf("linked entry %+v", linked)
	}
	if a.classes[*linked.Class].Target != `\\fs2.corp\docs` || a.classes[*readme.Class].Target != "" {
		t.Fatalf("registry %+v", a.classes)
	}
	if fmt.Sprint(a.mounts["ns"].Targets) != fmt.Sprint(map[string]string{"": `\\fs1.corp\ns`, "docs": `\\fs2.corp\docs`}) {
		t.Fatalf("mounts %v", a.mounts["ns"].Targets)
	}
	if lists := src.called("list:"); !slices.Equal(lists, []string{`\\fs1.corp\ns`, `\\fs2.corp\docs`, `\\fs2.corp\docs\a`}) {
		t.Fatalf("lists %v", lists)
	}
}

func TestWalkDomainRoot(t *testing.T) {
	src := newFakeSource()
	refer(src, `\\corp.example\ns`, []string{`\\ns2.corp.example\ns`, `\\ns1.corp.example\ns`})
	refer(src, `\\ns1.corp.example\ns`, []string{`\\ns1.corp.example\ns`})
	refer(src, `\\ns2.corp.example\ns`, []string{`\\ns2.corp.example\ns`})
	sd := readable("S-1-5-21-1-2-3-1104")
	first := src.add(`\\ns1.corp.example\ns\r.txt`, "1", sd)
	src.add(`\\ns2.corp.example\ns\r.txt`, "2", sd)
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\corp.example\ns`})
	entries := walkAll(t, a, "ns")
	key := `\\ns1.corp.example\ns`
	if len(entries) != 1 || entries[0].File != fmt.Sprintf("%016x", first.id^bind(key)) || *entries[0].Class != classOf(scope("ns", key), sd) {
		t.Fatalf("entries %+v", entries)
	}
	if a.mounts["ns"].Targets[""] != key || a.classes[*entries[0].Class].Target != key {
		t.Fatalf("mounts %v", a.mounts["ns"].Targets)
	}
	for _, list := range src.called("list:") {
		if strings.HasPrefix(strings.ToLower(list), `\\corp.example`) {
			t.Fatalf("listed the domain host: %s", list)
		}
	}
}

func TestWalkTargetOrder(t *testing.T) {
	cases := []struct {
		name  string
		sets  [][][]string
		files []string
		want  string
	}{
		{"shuffled", [][][]string{{{`\\fs3.corp\docs`, `\\fs2.corp\docs`}}, {{`\\fs2.corp\docs`, `\\fs3.corp\docs`}}}, []string{`\\fs2.corp\docs`, `\\fs3.corp\docs`}, `\\fs2.corp\docs`},
		{"case", [][][]string{{{`\\fs2.corp\docs`, `\\fs2.corp\Docs`}}, {{`\\fs2.corp\Docs`, `\\fs2.corp\docs`}}}, []string{`\\fs2.corp\docs`, `\\fs2.corp\Docs`}, `\\fs2.corp\Docs`},
		{"sets", [][][]string{{{`\\fs9.corp\docs`}, {`\\fs1.corp\docs`}}, {{`\\fs9.corp\docs`}, {`\\fs1.corp\docs`}}}, []string{`\\fs9.corp\docs`, `\\fs1.corp\docs`}, `\\fs9.corp\docs`},
	}
	for _, c := range cases {
		src := newFakeSource()
		namespace(src)
		src.links[`\\fs1.corp\ns\docs`] = true
		for _, share := range c.files {
			src.add(share+`\x.txt`, "x", readable("S-1-1-0"))
		}
		a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
		for walk, sets := range c.sets {
			refer(src, `\\fs1.corp\ns\docs`, sets...)
			a.mounts = map[string]mountTable{}
			walkAll(t, a, "ns")
			if got := a.mounts["ns"].Targets["docs"]; got != c.want {
				t.Errorf("%s walk %d chose %s", c.name, walk, got)
			}
		}
	}
}

func TestWalkFailover(t *testing.T) {
	for name, failure := range map[string]error{"unavailable": ErrUnavailable, "not found": ErrNotFound, "denied": ErrDenied} {
		src := newFakeSource()
		namespace(src)
		src.links[`\\fs1.corp\ns\docs`] = true
		refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs3.corp\docs`, `\\fs2.corp\docs`})
		src.add(`\\fs2.corp\docs\x.txt`, "x", readable("S-1-1-0"))
		src.add(`\\fs3.corp\docs\x.txt`, "x", readable("S-1-1-0"))
		src.failures[`list:\\fs2.corp\docs`] = failure
		a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
		page := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
		listedSecond := slices.Contains(src.called("list:"), `\\fs3.corp\docs`)
		if failure == ErrDenied {
			if !slices.Equal(page.Incomplete, []string{"docs"}) || listedSecond || a.mounts["ns"].Targets["docs"] != "" {
				t.Errorf("%s: incomplete %v, second listed %v", name, page.Incomplete, listedSecond)
			}
			continue
		}
		if len(page.Incomplete) != 0 || a.mounts["ns"].Targets["docs"] != `\\fs3.corp\docs` || len(byPath(page.Entries)) != 2 {
			t.Errorf("%s: page %+v, mounts %v", name, page, a.mounts["ns"].Targets)
		}
	}
}

func TestWalkPinnedTarget(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\a`, `\\fs2.corp\b`})
	src.add(`\\fs2.corp\a\x.txt`, "x", readable("S-1-1-0"))
	src.add(`\\fs2.corp\b\x.txt`, "x", readable("S-1-1-0"))
	src.failures[`list:\\fs2.corp\a`] = ErrUnavailable
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	walkAll(t, a, "ns")
	first := a.mounts["ns"].Targets["docs"]
	delete(src.failures, `list:\\fs2.corp\a`)
	restarted, _ := newAgent(a.dir, a.cfg, src)
	walkAll(t, restarted, "ns")
	second := restarted.mounts["ns"].Targets["docs"]
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\a`})
	walkAll(t, restarted, "ns")
	third := restarted.mounts["ns"].Targets["docs"]
	if first != `\\fs2.corp\b` || second != `\\fs2.corp\b` || third != `\\fs2.corp\a` {
		t.Fatalf("targets %s %s %s", first, second, third)
	}
}

func TestWalkAllTargetsDown(t *testing.T) {
	src := newFakeSource()
	refer(src, `\\corp.example\ns`, []string{`\\ns1.corp.example\ns`, `\\ns2.corp.example\ns`})
	src.links[`\\ns1.corp.example\ns\docs`] = true
	refer(src, `\\ns1.corp.example\ns\docs`, []string{`\\fs2.corp\docs`, `\\fs3.corp\docs`})
	src.failures[`list:\\fs2.corp\docs`] = ErrUnavailable
	src.failures[`list:\\fs3.corp\docs`] = ErrUnavailable
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\corp.example\ns`})
	page := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	if !slices.Equal(page.Incomplete, []string{"docs"}) || page.Cursor != "" || a.walked["ns"].IsZero() {
		t.Fatalf("page %+v", page)
	}
	src.failures[`list:\\ns1.corp.example\ns`] = ErrUnavailable
	src.failures[`list:\\ns2.corp.example\ns`] = ErrUnavailable
	if reply := a.walk(message{Type: "walk", ID: 2, Root: "ns"}); codeOfReply(reply) != "unavailable" {
		t.Fatalf("root with all targets down answered %+v", reply)
	}
	if _, ok := a.walked["ns"]; ok || a.walks["ns"] != nil {
		t.Fatal("failed root walk kept its state")
	}
	src.failures[`list:\\ns2.corp.example\ns`] = ErrDenied
	if reply := a.walk(message{Type: "walk", ID: 3, Root: "ns"}); codeOfReply(reply) != "denied" {
		t.Fatalf("root with a denied target answered %+v", reply)
	}
}

func TestWalkInterlink(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\x`] = true
	refer(src, `\\fs1.corp\ns\x`, []string{`\\corp.example\ns2\x`})
	src.referrals[strings.ToLower(`\\corp.example\ns2\x`)] = Referral{Consumed: `\\corp.example\ns2`, Sets: [][]string{{`\\ns2.corp.example\ns2`}}}
	src.referrals[strings.ToLower(`\\ns2.corp.example\ns2\x`)] = Referral{Consumed: `\\NS2.corp.example\ns2\X`, Sets: [][]string{{`\\fs3.corp\data\deep`}}}
	sd := readable("S-1-1-0")
	f := src.add(`\\fs3.corp\data\deep\y\z.txt`, "z", sd)
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	entries := byPath(walkAll(t, a, "ns"))
	got, ok := entries["x/y/z.txt"]
	if !ok || got.File != fmt.Sprintf("%016x", f.id^bind(`\\fs3.corp\data`)) || *got.Class != classOf(scope("ns", `\\fs3.corp\data`), sd) {
		t.Fatalf("entries %+v", entries)
	}
	if a.mounts["ns"].Targets["x"] != `\\fs3.corp\data\deep` {
		t.Fatalf("mounts %v", a.mounts["ns"].Targets)
	}
	want := []string{`\\fs1.corp\ns`, `\\fs1.corp\ns\x`, `\\corp.example\ns2\x`, `\\ns2.corp.example\ns2\x`, `\\fs3.corp\data\deep`}
	if calls := src.called("referral:"); !slices.Equal(calls, want) {
		t.Fatalf("referrals %v", calls)
	}
}

func TestWalkReferralBudget(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\loop`] = true
	refer(src, `\\fs1.corp\ns\loop`, []string{`\\fs2.corp\ns2\back`})
	refer(src, `\\fs2.corp\ns2\back`, []string{`\\fs1.corp\ns\loop`})
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	page := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	if calls := src.called("referral:"); !slices.Equal(page.Incomplete, []string{"loop"}) || len(calls) != 17 {
		t.Fatalf("incomplete %v after %d referrals", page.Incomplete, len(calls))
	}
	src = newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\dead`] = true
	var dead []string
	for i := range 20 {
		host := fmt.Sprintf(`\\h%02d.corp\s`, i)
		dead = append(dead, host)
		src.failures["list:"+host] = ErrUnavailable
	}
	refer(src, `\\fs1.corp\ns\dead`, dead)
	a = dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	page = a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	if calls := src.called("referral:"); !slices.Equal(page.Incomplete, []string{"dead"}) || len(calls) != 17 || len(src.called("list:")) != 16 {
		t.Fatalf("incomplete %v after %d referrals and %d lists", page.Incomplete, len(calls), len(src.called("list:")))
	}
}

func TestWalkOverlappingMounts(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	links := map[string]string{"self": `\\fs1.corp\ns`, "inside": `\\fs1.corp\ns\sub`, "a1": `\\fs2.corp\docs`, "a2": `\\FS2.corp\Docs`, "child": `\\fs3.corp\data\sub`, "parent": `\\fs3.corp\data`}
	for name, target := range links {
		src.links[`\\fs1.corp\ns\`+name] = true
		refer(src, `\\fs1.corp\ns\`+name, []string{target})
	}
	src.add(`\\fs1.corp\ns\sub\s.txt`, "s", readable("S-1-1-0"))
	src.add(`\\fs2.corp\docs\d.txt`, "d", readable("S-1-1-0"))
	src.add(`\\FS2.corp\Docs\d.txt`, "d", readable("S-1-1-0"))
	src.add(`\\fs3.corp\data\p.txt`, "p", readable("S-1-1-0"))
	src.add(`\\fs3.corp\data\sub\c.txt`, "c", readable("S-1-1-0"))
	var logged strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	defer slog.SetDefault(previous)
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	page := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	mounts := a.mounts["ns"].Targets
	docs := mounts["a1"] != "" != (mounts["a2"] != "")
	data := mounts["child"] != "" != (mounts["parent"] != "")
	if len(page.Incomplete) != 0 || mounts["self"] != "" || mounts["inside"] != "" || !docs || !data || len(mounts) != 3 {
		t.Fatalf("mounts %v, incomplete %v", mounts, page.Incomplete)
	}
	for _, e := range page.Entries {
		if strings.HasPrefix(e.Path, "self/") || strings.HasPrefix(e.Path, "inside/") {
			t.Fatalf("entry through an overlapping link %s", e.Path)
		}
	}
	if !strings.Contains(logged.String(), "skipped=4") || !strings.Contains(logged.String(), "targets=3") {
		t.Fatalf("log %s", logged.String())
	}
	again := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	walkAll(t, again, "ns")
	if fmt.Sprint(again.mounts["ns"].Targets) != fmt.Sprint(mounts) {
		t.Fatalf("second walk chose %v, first %v", again.mounts["ns"].Targets, mounts)
	}
}

func TestWalkConsumedChecks(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	consumed := map[string]string{"docs": `\\fs1.corp\ns\do`, "other": `\\fs9.corp\x`, "longer": `\\fs1.corp\ns\longer\more`, "empty": "", "trailing": `\\fs1.corp\ns\`}
	for name, prefix := range consumed {
		src.links[`\\fs1.corp\ns\`+name] = true
		src.referrals[strings.ToLower(`\\fs1.corp\ns\`+name)] = Referral{Consumed: prefix, Sets: [][]string{{`\\fs2.corp\docs`}}}
	}
	src.add(`\\fs2.corp\docs\x.txt`, "x", readable("S-1-1-0"))
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	page := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	slices.Sort(page.Incomplete)
	if !slices.Equal(page.Incomplete, []string{"docs", "empty", "longer", "other", "trailing"}) || slices.Contains(src.called("list:"), `\\fs2.corp\docs`) {
		t.Fatalf("incomplete %v, lists %v", page.Incomplete, src.called("list:"))
	}
}

func TestWalkDropsInvalidCandidates(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	invalid := []string{
		`\\single\docs`, `\\10.0.0.1\docs`, `\\fs2.corp@SSL@443\docs`, `\\fs2.corp:445\docs`, `\\fs2.corp.\docs`, `\\fs2.123\docs`,
		`\\fs2.corp\`, `\\fs2.corp`, `\\fs2.corp\IPC$`, `\\fs2.corp\ipc$`, `\\fs2.corp\..`, `\\fs2.corp\.`, `\\fs2.corp\do@cs`, "\\\\fs2.corp\\do\x01cs",
		`\\fs2.corp\ docs`, `\\fs2.corp\docs `, `\\fs2.corp\do:cs`, `\\fs2.corp\docs\..\x`, `\\fs2.corp\docs\`, `\\fs2.corp\docs\a\\b`, `\\fs2.corp\docs\a/b`,
		`fs2.corp\docs`, `\fs2.corp\docs`, `\\\fs2.corp\docs`, "",
	}
	valid := `\\zz.corp\docs\sub\dir`
	refer(src, `\\fs1.corp\ns\docs`, append(slices.Clone(invalid), valid))
	src.add(valid+`\x.txt`, "x", readable("S-1-1-0"))
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	entries := walkAll(t, a, "ns")
	if a.mounts["ns"].Targets["docs"] != valid || byPath(entries)["docs/x.txt"].Class == nil {
		t.Fatalf("mounts %v, entries %+v", a.mounts["ns"].Targets, entries)
	}
	if calls := src.called("referral:"); !slices.Equal(calls, []string{`\\fs1.corp\ns`, `\\fs1.corp\ns\docs`, valid}) {
		t.Fatalf("referrals %v", calls)
	}
}

func TestWalkPageTime(t *testing.T) {
	build := func() *fakeSource {
		src := newFakeSource()
		namespace(src)
		for _, name := range []string{"a", "b", "c"} {
			src.links[`\\fs1.corp\ns\`+name] = true
			refer(src, `\\fs1.corp\ns\`+name, []string{`\\fs2.corp\` + name})
			src.add(`\\fs2.corp\`+name+`\f.txt`, name, readable("S-1-1-0"))
			src.add(`\\fs2.corp\`+name+`\sub\g.txt`, name, readable("S-1-1-0"))
		}
		return src
	}
	plain := walkAll(t, dfsAgent(t, build(), root{ID: "ns", Path: `\\fs1.corp\ns`}), "ns")
	src := build()
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	start := time.Now()
	a.now = func() time.Time { return start.Add(time.Duration(len(src.called("referral:"))) * 200 * time.Second) }
	var timed []pageEntry
	pages := 0
	for cursor := ""; pages == 0 || cursor != ""; pages++ {
		page := a.walk(message{Type: "walk", ID: 1, Root: "ns", Cursor: cursor}).(pageMessage)
		timed = append(timed, page.Entries...)
		cursor = page.Cursor
		if cursor != "" && len(src.called("referral:")) != 1+2*pages {
			t.Fatalf("page %d ended after %d referrals", pages, len(src.called("referral:")))
		}
	}
	key := func(e pageEntry) string { return e.Path + " " + e.File + " " + *e.Class }
	got, want := []string{}, []string{}
	for _, e := range timed {
		got = append(got, key(e))
	}
	for _, e := range plain {
		want = append(want, key(e))
	}
	slices.Sort(got)
	slices.Sort(want)
	if pages != 5 || len(want) != 7 || !slices.Equal(got, want) {
		t.Fatalf("%d pages with %v, want %v", pages, got, want)
	}
}

func TestWalkMountLimit(t *testing.T) {
	limit := mountLimit
	mountLimit = 2
	defer func() { mountLimit = limit }()
	src := newFakeSource()
	namespace(src)
	for _, name := range []string{"a", "b", "c"} {
		src.links[`\\fs1.corp\ns\`+name] = true
		refer(src, `\\fs1.corp\ns\`+name, []string{`\\fs2.corp\` + name})
	}
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	page := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	slices.Sort(page.Incomplete)
	if len(a.mounts["ns"].Targets) != 3 || !slices.Equal(page.Incomplete, []string{"a"}) || len(src.called("referral:")) != 5 {
		t.Fatalf("mounts %v, incomplete %v, referrals %v", a.mounts["ns"].Targets, page.Incomplete, src.called("referral:"))
	}
}

func TestWalkExcludedLinkNotResolved(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\Private`] = true
	refer(src, `\\fs1.corp\ns\Private`, []string{`\\fs2.corp\private`})
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`, Exclude: []string{"private"}})
	walkAll(t, a, "ns")
	if calls := src.called("referral:"); !slices.Equal(calls, []string{`\\fs1.corp\ns`}) || len(a.mounts["ns"].Targets) != 1 {
		t.Fatalf("referrals %v, mounts %v", calls, a.mounts["ns"].Targets)
	}
}

func TestAccessPerTarget(t *testing.T) {
	alice, bob := "S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1105"
	sd := readable(alice, bob)
	src := newFakeSource()
	refer(src, `\\corp.example\ns`, []string{`\\ns1.corp.example\ns`})
	refer(src, `\\ns1.corp.example\ns`, []string{`\\ns1.corp.example\ns`})
	src.add(`\\ns1.corp.example\ns\r.txt`, "r", sd)
	for _, name := range []string{"a", "b"} {
		src.links[`\\ns1.corp.example\ns\`+name] = true
		refer(src, `\\ns1.corp.example\ns\`+name, []string{`\\FS-` + name + `.corp\docs`})
		src.add(`\\FS-`+name+`.corp\docs\x.txt`, name, sd)
	}
	src.shares[`\\fs-b.corp\docs`] = readable(alice)
	plain := root{ID: "plain", Path: `\\fs6.corp\p`}
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\corp.example\ns`}, root{ID: "empty", Path: `\\fs5.corp\e`}, plain)
	a.cfg.samba = map[string]bool{"fs-b.corp": true}
	walkAll(t, a, "ns")
	walkAll(t, a, "empty")
	a.walked["plain"] = a.now()
	plainClass := classOf("plain", sd)
	a.classes[plainClass] = classEntry{Root: "plain", SD: sd}
	classes := map[string]string{}
	for id, entry := range a.classes {
		classes[entry.Target] = id
	}
	if len(classes) != 4 || classes[`\\ns1.corp.example\ns`] == "" || classes[`\\fs-a.corp\docs`] == "" || classes[`\\fs-b.corp\docs`] == "" {
		t.Fatalf("classes %v", classes)
	}
	src.calls = nil
	rights := a.access(message{Type: "access", ID: 1, SIDs: []string{alice, bob}}).(rightsMessage)
	readers := map[string][]int{}
	for _, c := range rights.Classes {
		readers[c.Class] = c.Readers
	}
	if !slices.Equal(readers[classes[`\\ns1.corp.example\ns`]], []int{0, 1}) || !slices.Equal(readers[classes[`\\fs-a.corp\docs`]], []int{0, 1}) || !slices.Equal(readers[classes[`\\fs-b.corp\docs`]], []int{0}) || len(readers[plainClass]) != 0 {
		t.Fatalf("readers %v", readers)
	}
	if fmt.Sprint(rights.Errors) != "[{plain unavailable}]" {
		t.Fatalf("errors %v", rights.Errors)
	}
	if shares := src.called("share:"); !slices.Equal(shares, []string{`\\fs-a.corp\docs`, `\\fs-b.corp\docs`, `\\ns1.corp.example\ns`}) {
		t.Fatalf("shares %v", shares)
	}
	var servers []string
	for _, call := range src.authzCalls {
		servers = append(servers, call[0])
	}
	if !slices.Equal(servers, []string{"fs-a.corp", "fs-a.corp", "fs-b.corp", "fs-b.corp", "ns1.corp.example", "ns1.corp.example"}) {
		t.Fatalf("authz servers %v", servers)
	}
	src.failures[`share:\\fs-a.corp\docs`] = ErrDenied
	src.failures["allowed:ns1.corp.example"] = ErrUnavailable
	rights = a.access(message{Type: "access", ID: 2, SIDs: []string{alice, bob}}).(rightsMessage)
	readers = map[string][]int{}
	for _, c := range rights.Classes {
		readers[c.Class] = c.Readers
	}
	if fmt.Sprint(rights.Errors) != "[{ns denied} {plain unavailable}]" || !slices.Equal(readers[classes[`\\fs-b.corp\docs`]], []int{0}) || len(readers[classes[`\\fs-a.corp\docs`]]) != 0 || len(readers[classes[`\\ns1.corp.example\ns`]]) != 0 {
		t.Fatalf("readers %v, errors %v", readers, rights.Errors)
	}
}

func TestAccessSameDescriptorTwoTargets(t *testing.T) {
	sd := readable("S-1-5-21-1-2-3-1104")
	src := newFakeSource()
	namespace(src)
	for _, name := range []string{"a", "b"} {
		src.links[`\\fs1.corp\ns\`+name] = true
		refer(src, `\\fs1.corp\ns\`+name, []string{`\\fs2.corp\` + name})
		src.add(`\\fs2.corp\`+name+`\x.txt`, name, sd)
	}
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	entries := byPath(walkAll(t, a, "ns"))
	if *entries["a/x.txt"].Class == *entries["b/x.txt"].Class || len(a.classes) != 3 {
		t.Fatalf("classes %v", a.classes)
	}
}

func TestReadThroughMounts(t *testing.T) {
	sd := readable("S-1-1-0")
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\a`, `\\fs2.corp\b`})
	onA := src.add(`\\fs2.corp\a\sub\x.txt`, "same", sd)
	onB := src.add(`\\fs2.corp\b\sub\x.txt`, "same", sd)
	onB.id = onA.id
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	entries := byPath(walkAll(t, a, "ns"))
	record := entries["docs/sub/x.txt"]
	read := func(a *agent, file string) (string, any) {
		var data []byte
		reply := a.read(t.Context(), message{Type: "read", ID: 3, Root: "ns", Path: "docs/sub/x.txt", File: file, Size: 4, Modified: onA.modified.UnixMilli()}, openWindow(), func(frame []byte) error {
			data = append(data, frame[4:]...)
			return nil
		})
		return string(data), reply
	}
	if data, reply := read(a, record.File); codeOfReply(reply) != "done" || data != "same" || !slices.Contains(src.called("open:"), `\\fs2.corp\a\sub\x.txt`) {
		t.Fatalf("read %q %+v, opens %v", data, reply, src.called("open:"))
	}
	if _, reply := read(a, fmt.Sprintf("%016x", onA.id)); codeOfReply(reply) != "changed" {
		t.Fatalf("unbound file id answered %+v", reply)
	}
	if _, reply := readFile(a, "ns", "docs", onA); codeOfReply(reply) != "not_found" {
		t.Fatalf("mount point read answered %+v", reply)
	}
	if _, reply := readFile(a, "ns", "readme.txt", src.files[`\\fs1.corp\ns\readme.txt`]); codeOfReply(reply) != "done" {
		t.Fatalf("root share file answered %+v", reply)
	}
	src.failures[`list:\\fs2.corp\a`] = ErrUnavailable
	restarted, _ := newAgent(a.dir, a.cfg, src)
	if _, reply := read(restarted, record.File); codeOfReply(reply) != "done" {
		t.Fatalf("read through the stored table answered %+v", reply)
	}
	walkAll(t, restarted, "ns")
	if _, reply := read(restarted, record.File); codeOfReply(reply) != "changed" {
		t.Fatalf("record of the old target answered %+v", reply)
	}
	if _, reply := read(restarted, fmt.Sprintf("%016x", onB.id^bind(`\\fs2.corp\b`))); codeOfReply(reply) != "done" {
		t.Fatalf("record of the new target answered %+v", reply)
	}
	fresh := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	if _, reply := read(fresh, record.File); codeOfReply(reply) != "unavailable" {
		t.Fatalf("read without a table answered %+v", reply)
	}
}

func TestWalkCacheNeedsSameTarget(t *testing.T) {
	sd := readable("S-1-1-0")
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\a`, `\\fs2.corp\b`})
	onA := src.add(`\\fs2.corp\a\x.txt`, "same", sd)
	src.add(`\\fs2.corp\b\x.txt`, "same", sd).id = onA.id
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	walkAll(t, a, "ns")
	walkAll(t, a, "ns")
	if src.descriptorCalls != 2 {
		t.Fatalf("%d descriptor reads after an unchanged walk", src.descriptorCalls)
	}
	src.failures[`list:\\fs2.corp\a`] = ErrUnavailable
	entries := byPath(walkAll(t, a, "ns"))
	if src.descriptorCalls != 3 || *entries["docs/x.txt"].Class != classOf(scope("ns", `\\fs2.corp\b`), sd) {
		t.Fatalf("%d descriptor reads after a target switch, entries %+v", src.descriptorCalls, entries)
	}
	if len(a.classes) != 2 {
		t.Fatalf("old target class not pruned: %v", a.classes)
	}
}

func TestStateMountsAndTargets(t *testing.T) {
	sd := readable("S-1-1-0")
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\docs`})
	src.add(`\\fs2.corp\docs\x.txt`, "x", sd)
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	walkAll(t, a, "ns")
	restarted, err := newAgent(a.dir, a.cfg, src)
	if err != nil || fmt.Sprint(restarted.mounts) != fmt.Sprint(a.mounts) || fmt.Sprint(restarted.classes) != fmt.Sprint(a.classes) || len(restarted.classes) != 2 {
		t.Fatalf("restarted mounts %v, classes %v, %v", restarted.mounts, restarted.classes, err)
	}
	data, _ := os.ReadFile(statePath(a.dir, "classes.json"))
	if !strings.Contains(string(data), `"target":"\\\\fs2.corp\\docs"`) || strings.Count(string(data), `"target"`) != 1 {
		t.Fatalf("classes.json %s", data)
	}
	tampered := strings.ReplaceAll(string(data), `"target":"\\\\fs2.corp\\docs"`, `"target":"\\\\fs3.corp\\docs"`)
	writeFile(statePath(a.dir, "classes.json"), []byte(tampered))
	if loaded, _ := newAgent(a.dir, a.cfg, src); len(loaded.classes) != 1 {
		t.Fatalf("tampered target kept %v", loaded.classes)
	}
	writeFile(statePath(a.dir, "mounts.json"), []byte("{"))
	if _, err := newAgent(a.dir, a.cfg, src); err == nil || !strings.Contains(err.Error(), "mounts.json") {
		t.Fatalf("corrupt mounts.json loaded: %v", err)
	}
}

func TestWalkLinkWithoutReferralIncomplete(t *testing.T) {
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	src.add(`\\fs1.corp\ns\docs\x.txt`, "x", readable("S-1-1-0"))
	var logged strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	defer slog.SetDefault(previous)
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	page := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	if !slices.Equal(page.Incomplete, []string{"docs"}) || !strings.Contains(logged.String(), "skipped=0") || slices.Contains(src.called("list:"), `\\fs1.corp\ns\docs`) {
		t.Fatalf("incomplete %v, lists %v, log %s", page.Incomplete, src.called("list:"), logged.String())
	}
}

func TestFirstWalkReadsEmittedPages(t *testing.T) {
	sd := readable("S-1-1-0")
	src := newFakeSource()
	namespace(src)
	for i := range pageSize {
		src.add(fmt.Sprintf(`\\fs1.corp\ns\f%03d.txt`, i), "x", sd)
	}
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\docs`})
	linked := src.add(`\\fs2.corp\docs\x.txt`, "linked", sd)
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	first := a.walk(message{Type: "walk", ID: 1, Root: "ns"}).(pageMessage)
	if len(first.Entries) != pageSize || first.Cursor == "" {
		t.Fatalf("first page has %d entries, cursor %q", len(first.Entries), first.Cursor)
	}
	emitted := src.files[`\\fs1.corp\ns\`+strings.ReplaceAll(first.Entries[0].Path, "/", `\`)]
	linkedRead := message{Type: "read", ID: 3, Root: "ns", Path: "docs/x.txt", File: fmt.Sprintf("%016x", linked.id^bind(`\\fs2.corp\docs`)), Size: 6, Modified: linked.modified.UnixMilli()}
	if reply := a.read(t.Context(), linkedRead, openWindow(), func([]byte) error { return nil }); codeOfReply(reply) != "unavailable" {
		t.Fatalf("read through an unverified link answered %+v", reply)
	}
	second := make(chan any)
	go func() { second <- a.walk(message{Type: "walk", ID: 2, Root: "ns", Cursor: first.Cursor}) }()
	if data, reply := readFile(a, "ns", first.Entries[0].Path, emitted); codeOfReply(reply) != "done" || data == "" {
		t.Fatalf("read of a first page record answered %q %+v", data, reply)
	}
	if page := (<-second).(pageMessage); page.Cursor != "" {
		t.Fatalf("second page cursor %q", page.Cursor)
	}
	if _, err := os.Stat(statePath(a.dir, "mounts.json")); err != nil {
		t.Fatal(err)
	}
	if reply := a.read(t.Context(), linkedRead, openWindow(), func([]byte) error { return nil }); codeOfReply(reply) != "done" {
		t.Fatalf("read through the verified link answered %+v", reply)
	}
}

func TestRootPathChangeDropsState(t *testing.T) {
	alice := "S-1-5-21-1-2-3-1104"
	src := newFakeSource()
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\docs`})
	f := src.add(`\\fs2.corp\docs\x.txt`, "x", readable(alice))
	refer(src, `\\fs1.corp\public`, []string{`\\fs1.corp\public`})
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`}, root{ID: "plain", Path: `\\fs6.corp\p`})
	walkAll(t, a, "ns")
	a.walked["plain"] = a.now()
	a.save("walks.json", a.walked)
	moved := config{Roots: []root{{ID: "ns", Path: `\\fs1.corp\public`}, {ID: "plain", Path: `\\fs6.corp\p`}}, Limits: a.cfg.Limits}
	restarted, err := newAgent(a.dir, moved, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.mounts["ns"]; ok || len(restarted.classes) != 0 || !restarted.walked["ns"].IsZero() {
		t.Fatalf("mounts %v, classes %v, walked %v", restarted.mounts, restarted.classes, restarted.walked)
	}
	if restarted.mounts["plain"].Path != `\\fs6.corp\p` {
		t.Fatalf("unchanged root lost its table: %v", restarted.mounts)
	}
	record := fmt.Sprintf("%016x", f.id^bind(`\\fs2.corp\docs`))
	reply := restarted.read(t.Context(), message{Type: "read", ID: 3, Root: "ns", Path: "docs/x.txt", File: record, Size: 1, Modified: f.modified.UnixMilli()}, openWindow(), func([]byte) error { return nil })
	if codeOfReply(reply) != "unavailable" || len(src.called("open:")) != 0 {
		t.Fatalf("read after a path change answered %+v, opens %v", reply, src.called("open:"))
	}
	a.cfg = moved
	a.mounts["plain"] = restarted.mounts["plain"]
	rights := a.access(message{Type: "access", ID: 4, SIDs: []string{alice}}).(rightsMessage)
	for _, c := range rights.Classes {
		if len(c.Readers) != 0 {
			t.Fatalf("class %s of a moved root has readers %v", c.Class, c.Readers)
		}
	}
	if fmt.Sprint(rights.Errors) != "[{ns unavailable}]" {
		t.Fatalf("errors %v", rights.Errors)
	}
}

func TestUpgradeSeedsPhysicalTable(t *testing.T) {
	alice := "S-1-5-21-1-2-3-1104"
	src := newFakeSource()
	f := src.add(`\\fs01\finance\a.txt`, "a", readable(alice))
	namespace(src)
	src.links[`\\fs1.corp\ns\docs`] = true
	refer(src, `\\fs1.corp\ns\docs`, []string{`\\fs2.corp\docs`})
	src.add(`\\fs2.corp\docs\x.txt`, "x", readable(alice))
	a := dfsAgent(t, src, root{ID: "finance", Path: `\\fs01\finance`}, root{ID: "ns", Path: `\\fs1.corp\ns`}, root{ID: "fresh", Path: `\\fs7.corp\f`})
	walkAll(t, a, "finance")
	walkAll(t, a, "ns")
	for id, entry := range a.classes {
		if entry.Target != "" {
			delete(a.classes, id)
		}
	}
	a.save("classes.json", a.classes)
	os.Remove(statePath(a.dir, "mounts.json"))
	upgraded, err := newAgent(a.dir, a.cfg, src)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(upgraded.mounts) != fmt.Sprint(map[string]mountTable{"finance": {Path: `\\fs01\finance`}, "ns": {Path: `\\fs1.corp\ns`}}) {
		t.Fatalf("mounts %v", upgraded.mounts)
	}
	if _, reply := readFile(upgraded, "finance", "a.txt", f); codeOfReply(reply) != "done" {
		t.Fatalf("read after upgrade answered %+v", reply)
	}
	rights := upgraded.access(message{Type: "access", ID: 1, SIDs: []string{alice}}).(rightsMessage)
	readers := map[string][]int{}
	for _, c := range rights.Classes {
		readers[c.Class] = c.Readers
	}
	if !slices.Equal(readers[classOf("finance", readable(alice))], []int{0}) || len(readers[classOf("ns", readable(alice))]) != 0 || fmt.Sprint(rights.Errors) != "[{ns unavailable} {fresh unavailable}]" {
		t.Fatalf("readers %v, errors %v", readers, rights.Errors)
	}
}

func TestAccessOneContextPerServer(t *testing.T) {
	alice, bob := "S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1105"
	src := newFakeSource()
	namespace(src)
	src.shares[`\\fs1.corp\ns`] = readable(alice)
	for _, name := range []string{"a", "b", "c"} {
		src.links[`\\fs1.corp\ns\`+name] = true
		refer(src, `\\fs1.corp\ns\`+name, []string{`\\fs2.corp\` + name})
		src.add(`\\fs2.corp\`+name+`\x.txt`, name, readable(alice, bob))
	}
	src.shares[`\\fs2.corp\a`] = readable(alice, bob)
	src.shares[`\\fs2.corp\b`] = readable(alice)
	src.shares[`\\fs2.corp\c`] = readable("S-1-5-21-1-2-3-1199")
	a := dfsAgent(t, src, root{ID: "ns", Path: `\\fs1.corp\ns`})
	entries := byPath(walkAll(t, a, "ns"))
	src.authzCalls = nil
	rights := a.access(message{Type: "access", ID: 1, SIDs: []string{alice, bob}}).(rightsMessage)
	readers := map[string][]int{}
	for _, c := range rights.Classes {
		readers[c.Class] = c.Readers
	}
	if !slices.Equal(readers[*entries["a/x.txt"].Class], []int{0, 1}) || !slices.Equal(readers[*entries["b/x.txt"].Class], []int{0}) || len(readers[*entries["c/x.txt"].Class]) != 0 || len(rights.Errors) != 0 {
		t.Fatalf("readers %v, errors %v", readers, rights.Errors)
	}
	if fmt.Sprint(src.authzCalls) != fmt.Sprint([][]string{{"fs1.corp", alice, bob}, {"fs1.corp", alice}, {"fs2.corp", alice, bob}, {"fs2.corp", alice, bob}}) {
		t.Fatalf("authz calls %v", src.authzCalls)
	}
}

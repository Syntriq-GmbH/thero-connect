package core

import (
	"context"
	"encoding/json"
	"fmt"
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
	return a
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

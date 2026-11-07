package core

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	pageSize    = 500
	chunkSize   = 262144
	ackWindow   = 4 << 20
	readSlots   = 2
	snapshotAge = 6 * time.Hour
	pageTime    = 120 * time.Second
)

var mountLimit = 10000

var errOverlap = errors.New("overlaps another mount")

type agent struct {
	dir     string
	cfg     config
	src     Source
	id      identity
	cert    atomic.Pointer[tls.Certificate]
	now     func() time.Time
	mu      sync.Mutex
	renewal *ecdsa.PrivateKey
	classes map[string]classEntry
	quota   quota
	walked  map[string]time.Time
	limiter limiter
	slots   chan struct{}
	walkMu  sync.Mutex
	walks   map[string]*walkState
	cache   map[string]map[string]cachedClass
	mounts  map[string]map[string]string
}

type classEntry struct {
	Root   string `json:"root"`
	Target string `json:"target,omitempty"`
	SD     []byte `json:"sd"`
}

type quota struct {
	Day   string `json:"day"`
	Bytes int64  `json:"bytes"`
}

type cachedClass struct {
	target  string
	id      uint64
	changed time.Time
	class   string
}

type pendingFile struct {
	rel  string
	item Entry
}

type walkState struct {
	cursor     string
	nonce      string
	started    time.Time
	page       int
	dirs       []pendingFile
	files      []pendingFile
	mounts     map[string]string
	seen       map[string]bool
	next       map[string]cachedClass
	listed     int
	skipped    int
	incomplete int
}

type transfer struct {
	acked  atomic.Int64
	notify chan struct{}
	stop   context.CancelFunc
}

type limiter struct {
	mu   sync.Mutex
	next time.Time
}

func (l *limiter) delay(now time.Time, n int, bytesPerSecond int64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(time.Duration(int64(n) * int64(time.Second) / bytesPerSecond))
	return wait
}

func newAgent(dir string, cfg config, src Source) (*agent, error) {
	a := &agent{
		dir:     dir,
		cfg:     cfg,
		src:     src,
		now:     time.Now,
		classes: map[string]classEntry{},
		walked:  map[string]time.Time{},
		slots:   make(chan struct{}, readSlots),
		walks:   map[string]*walkState{},
		cache:   map[string]map[string]cachedClass{},
		mounts:  map[string]map[string]string{},
	}
	for name, target := range map[string]any{"classes.json": &a.classes, "quota.json": &a.quota, "walks.json": &a.walked, "mounts.json": &a.mounts} {
		data, err := os.ReadFile(statePath(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, target); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for id, entry := range a.classes {
		if supported(entry.SD) != nil || classOf(scope(entry.Root, entry.Target), entry.SD) != id {
			delete(a.classes, id)
		}
	}
	return a, nil
}

func (a *agent) save(name string, value any) {
	data, err := json.Marshal(value)
	if err == nil {
		err = writeFile(statePath(a.dir, name), data)
	}
	if err != nil {
		slog.Error("state not saved", "file", name, "error", err)
	}
}

func (a *agent) root(id string) (root, bool) {
	for _, r := range a.cfg.Roots {
		if r.ID == id {
			return r, true
		}
	}
	return root{}, false
}

func failure(id int64, code, text string) errorMessage {
	return errorMessage{Type: "error", ID: id, Code: code, Message: text}
}

func join(rootPath, rel string) string {
	if rel == "" {
		return rootPath
	}
	return rootPath + `\` + strings.ReplaceAll(rel, "/", `\`)
}

func physical(mounts map[string]string, rootPath, rel string) (string, string, string) {
	prefix := rel
	for {
		if target, ok := mounts[prefix]; ok {
			key := shareOf(target)
			if key == shareOf(rootPath) {
				key = ""
			}
			return target, strings.TrimPrefix(strings.TrimPrefix(rel, prefix), "/"), key
		}
		if prefix == "" {
			return rootPath, rel, ""
		}
		prefix = prefix[:max(strings.LastIndex(prefix, "/"), 0)]
	}
}

func (a *agent) locate(unc, pin string, mounts map[string]string, budget *int) (string, []Entry, error) {
	if *budget == 0 {
		return "", nil, ErrUnavailable
	}
	*budget--
	ref, err := a.src.Referral(unc)
	self := err == nil && slices.ContainsFunc(slices.Concat(ref.Sets...), func(target string) bool { return strings.EqualFold(target, ref.Consumed) })
	if errors.Is(err, ErrNotFound) || self {
		for _, target := range mounts {
			inner, outer := unc, target
			if len(inner) < len(outer) {
				inner, outer = outer, inner
			}
			if strings.EqualFold(inner[:len(outer)], outer) && (len(inner) == len(outer) || inner[len(outer)] == '\\') {
				return "", nil, errOverlap
			}
		}
		items, err := a.src.List(unc)
		return unc, items, err
	}
	if err != nil {
		return "", nil, err
	}
	consumed := len(ref.Consumed)
	if shareOf(ref.Consumed) == "" || strings.HasSuffix(ref.Consumed, `\`) || len(unc) < consumed || !strings.EqualFold(unc[:consumed], ref.Consumed) || len(unc) > consumed && unc[consumed] != '\\' {
		return "", nil, ErrUnavailable
	}
	rest := unc[consumed:]
	var candidates []string
	for _, set := range ref.Sets {
		sorted := slices.SortedFunc(slices.Values(set), func(x, y string) int {
			return cmp.Or(strings.Compare(strings.ToLower(x), strings.ToLower(y)), strings.Compare(x, y))
		})
		for _, candidate := range sorted {
			parts := strings.SplitN(candidate, `\`, 5)
			if len(parts) < 4 || parts[0] != "" || parts[1] != "" || !validHost(parts[2]) {
				continue
			}
			share := parts[3]
			if share == "" || strings.ContainsAny(share, `/:*?"<>|@`) || strings.ContainsFunc(share, unicode.IsControl) || strings.TrimSpace(share) != share || share == "." || share == ".." || strings.EqualFold(share, "IPC$") {
				continue
			}
			if len(parts) == 5 {
				if _, err := validPath(strings.ReplaceAll(parts[4], `\`, "/")); err != nil || strings.Contains(parts[4], "/") {
					continue
				}
			}
			candidates = append(candidates, candidate)
		}
	}
	if i := slices.IndexFunc(candidates, func(candidate string) bool { return strings.EqualFold(candidate+rest, pin) }); i > 0 {
		candidates = slices.Concat(candidates[i:i+1], candidates[:i], candidates[i+1:])
	}
	err = ErrUnavailable
	for _, candidate := range candidates {
		target, items, failed := a.locate(candidate+rest, pin, mounts, budget)
		if failed == nil || !errors.Is(failed, ErrUnavailable) && !errors.Is(failed, ErrNotFound) {
			return target, items, failed
		}
		err = failed
	}
	return "", nil, err
}

func parseWindow(window string) (int, int, error) {
	from, to, ok := strings.Cut(window, "-")
	start, startErr := time.Parse("15:04", from)
	end, endErr := time.Parse("15:04", to)
	if !ok || startErr != nil || endErr != nil {
		return 0, 0, fmt.Errorf("read_window %q is not HH:MM-HH:MM", window)
	}
	return start.Hour()*60 + start.Minute(), end.Hour()*60 + end.Minute(), nil
}

func (a *agent) walk(m message) any {
	r, ok := a.root(m.Root)
	if !ok {
		return failure(m.ID, "bad_request", "unknown root")
	}
	a.walkMu.Lock()
	defer a.walkMu.Unlock()
	w := a.walks[r.ID]
	if m.Cursor == "" {
		nonce := make([]byte, 8)
		rand.Read(nonce)
		w = &walkState{nonce: hex.EncodeToString(nonce), started: a.now(), dirs: []pendingFile{{item: Entry{Dir: true, Link: true}}}, mounts: map[string]string{}, seen: map[string]bool{}, next: map[string]cachedClass{}}
		a.walks[r.ID] = w
	}
	if w == nil || m.Cursor != w.cursor {
		return failure(m.ID, "cursor", "unknown walk cursor")
	}
	a.mu.Lock()
	pins := a.mounts[r.ID]
	a.mu.Unlock()
	previous := a.cache[r.ID]
	maxFile := int64(a.cfg.Limits.MaxFileMB) << 20
	entries := []pageEntry{}
	incomplete := []string{}
	registryChanged := false
	pageStart := a.now()
	listings := 0
	for len(entries) < pageSize && len(incomplete) < pageSize && (listings == 0 || a.now().Sub(pageStart) < pageTime) {
		if len(w.files) > 0 {
			pending := w.files[0]
			w.files = w.files[1:]
			var class *string
			target, rest, key := physical(w.mounts, r.Path, pending.rel)
			cached, known := previous[pending.rel]
			if known && cached.target == key && cached.id == pending.item.ID && cached.changed.Equal(pending.item.Changed) {
				class = &cached.class
			} else if sd, handleID, err := a.src.Descriptor(join(target, rest)); err == nil && handleID == pending.item.ID && supported(sd) == nil {
				id := classOf(scope(r.ID, key), sd)
				class = &id
				a.mu.Lock()
				if _, registered := a.classes[id]; !registered {
					a.classes[id] = classEntry{Root: r.ID, Target: key, SD: sd}
					registryChanged = true
				}
				a.mu.Unlock()
			}
			if class != nil {
				w.seen[*class] = true
				w.next[pending.rel] = cachedClass{target: key, id: pending.item.ID, changed: pending.item.Changed, class: *class}
			}
			entries = append(entries, pageEntry{
				Path:     pending.rel,
				File:     fmt.Sprintf("%016x", pending.item.ID^bind(key)),
				Size:     pending.item.Size,
				Created:  max(0, pending.item.Created.UnixMilli()),
				Modified: max(0, pending.item.Modified.UnixMilli()),
				Class:    class,
			})
			w.listed++
			continue
		}
		if len(w.dirs) == 0 {
			break
		}
		pending := w.dirs[len(w.dirs)-1]
		w.dirs = w.dirs[:len(w.dirs)-1]
		listings++
		dir := pending.rel
		mount, rest, _ := physical(w.mounts, r.Path, dir)
		path := join(mount, rest)
		var items []Entry
		var err error
		switch {
		case !pending.item.Link:
			items, err = a.src.List(path)
		case len(w.mounts) >= mountLimit:
			err = ErrUnavailable
		default:
			budget := 16
			var target string
			target, items, err = a.locate(path, pins[dir], w.mounts, &budget)
			if err == nil {
				w.mounts[dir] = target
			}
		}
		if err != nil && dir == "" {
			delete(a.walks, r.ID)
			a.mu.Lock()
			delete(a.walked, r.ID)
			a.save("walks.json", a.walked)
			a.mu.Unlock()
			slog.Warn("walk failed", "root", r.ID, "code", codeOf(err))
			return failure(m.ID, codeOf(err), "root listing failed")
		}
		if errors.Is(err, errOverlap) {
			w.skipped++
			continue
		}
		if err != nil {
			incomplete = append(incomplete, dir)
			w.incomplete++
			continue
		}
		for _, item := range items {
			rel := item.Name
			if dir != "" {
				rel = dir + "/" + item.Name
			}
			if excluded(r.Exclude, rel) {
				continue
			}
			if _, err := validPath(rel); err != nil || (!item.Dir && item.Size > maxFile) {
				w.skipped++
				continue
			}
			if item.Dir {
				w.dirs = append(w.dirs, pendingFile{rel: rel, item: item})
				continue
			}
			w.files = append(w.files, pendingFile{rel: rel, item: item})
		}
	}
	w.cursor = ""
	if len(w.files) > 0 || len(w.dirs) > 0 {
		w.page++
		w.cursor = fmt.Sprintf("%s-%d", w.nonce, w.page)
	} else {
		delete(a.walks, r.ID)
		a.cache[r.ID] = w.next
		a.mu.Lock()
		for id, entry := range a.classes {
			if entry.Root == r.ID && !w.seen[id] {
				delete(a.classes, id)
				registryChanged = true
			}
		}
		a.walked[r.ID] = w.started
		a.save("walks.json", a.walked)
		a.mounts[r.ID] = w.mounts
		a.save("mounts.json", a.mounts)
		a.mu.Unlock()
		targets := map[string]bool{}
		for _, target := range w.mounts {
			targets[shareOf(target)] = true
		}
		slog.Info("walk complete", "root", r.ID, "listed", w.listed, "skipped", w.skipped, "incomplete", w.incomplete, "targets", len(targets))
	}
	if registryChanged {
		a.mu.Lock()
		a.save("classes.json", a.classes)
		a.mu.Unlock()
	}
	return pageMessage{Type: "page", ID: m.ID, Cursor: w.cursor, Entries: entries, Incomplete: incomplete}
}

func (a *agent) principals(m message) any {
	emails := []string{}
	unique := map[string]bool{}
	for _, email := range m.Emails {
		email = strings.ToLower(email)
		if !unique[email] {
			unique[email] = true
			emails = append(emails, email)
		}
	}
	var found []Account
	for start := 0; start < len(emails); start += 50 {
		accounts, err := a.src.Accounts(ldapFilter(emails[start:min(start+50, len(emails))]))
		if err != nil {
			slog.Warn("principals failed", "code", codeOf(err))
			return failure(m.ID, codeOf(err), "directory lookup failed")
		}
		found = append(found, accounts...)
	}
	users := matchAccounts(emails, found)
	slog.Info("principals", "emails", len(emails), "users", len(users))
	return usersMessage{Type: "users", ID: m.ID, Users: users}
}

func (a *agent) access(m message) any {
	a.mu.Lock()
	ids := make([]string, 0, len(a.classes))
	registry := make(map[string]classEntry, len(a.classes))
	for id, entry := range a.classes {
		ids = append(ids, id)
		registry[id] = entry
	}
	walked := maps.Clone(a.walked)
	mounts := maps.Clone(a.mounts)
	a.mu.Unlock()
	slices.Sort(ids)
	readers := map[string][]int{}
	errs := []rootError{}
	for _, r := range a.cfg.Roots {
		if at, ok := walked[r.ID]; !ok || a.now().Sub(at) > snapshotAge {
			errs = append(errs, rootError{Root: r.ID, Code: "unavailable"})
			continue
		}
		failed := false
		fail := func(code string) {
			if !failed {
				errs = append(errs, rootError{Root: r.ID, Code: code})
				failed = true
			}
		}
		byTarget := map[string][]string{}
		for _, id := range ids {
			if registry[id].Root == r.ID {
				byTarget[registry[id].Target] = append(byTarget[registry[id].Target], id)
			}
		}
		for _, key := range slices.Sorted(maps.Keys(byTarget)) {
			sharePath := key
			if key == "" {
				if rootMount, ok := mounts[r.ID][""]; !ok || shareOf(rootMount) != shareOf(r.Path) {
					fail("unavailable")
					continue
				}
				sharePath = r.Path
			}
			share, err := a.src.Share(sharePath)
			if err != nil {
				fail(codeOf(err))
				continue
			}
			if supported(share) != nil {
				fail("unsupported")
				continue
			}
			shareACL, _, _ := readACL(share, binary.LittleEndian.Uint32(share[16:]))
			if slices.ContainsFunc(shareACL, func(item ace) bool { return item.sid == "S-1-3-4" && item.flags&0x08 == 0 }) {
				continue
			}
			server, _, _ := SplitUNC(sharePath)
			shareRights, err := a.src.Allowed(server, m.SIDs, [][]byte{share})
			if err != nil {
				fail(codeOf(err))
				continue
			}
			var passing []int
			var passingSIDs []string
			for k, row := range shareRights {
				if row[0] {
					passing = append(passing, k)
					passingSIDs = append(passingSIDs, m.SIDs[k])
				}
			}
			if len(passing) == 0 {
				continue
			}
			descriptors := make([][]byte, 0, len(byTarget[key]))
			for _, id := range byTarget[key] {
				descriptors = append(descriptors, registry[id].SD)
			}
			matrix, err := a.src.Allowed(server, passingSIDs, descriptors)
			if err != nil {
				fail(codeOf(err))
				continue
			}
			for j, id := range byTarget[key] {
				for k, index := range passing {
					if matrix[k][j] {
						readers[id] = append(readers[id], index)
					}
				}
			}
		}
	}
	classes := make([]classReaders, 0, len(ids))
	for _, id := range ids {
		classes = append(classes, classReaders{Class: id, Readers: append([]int{}, readers[id]...)})
	}
	slog.Info("access", "users", len(m.SIDs), "classes", len(classes), "errors", errs)
	return rightsMessage{Type: "rights", ID: m.ID, Classes: classes, Errors: errs}
}

func (a *agent) read(ctx context.Context, m message, t *transfer, frame func([]byte) error) any {
	refuse := func(code string) any {
		slog.Warn("read failed", "code", code, "root", m.Root, "path", m.Path)
		return failure(m.ID, code, "read failed: "+code)
	}
	r, ok := a.root(m.Root)
	if !ok {
		return refuse("bad_request")
	}
	if _, err := validPath(m.Path); err != nil {
		return refuse("bad_request")
	}
	if excluded(r.Exclude, m.Path) || m.Size > int64(a.cfg.Limits.MaxFileMB)<<20 {
		return refuse("not_found")
	}
	a.mu.Lock()
	mounts := a.mounts[r.ID]
	a.mu.Unlock()
	if len(mounts) == 0 {
		return refuse("unavailable")
	}
	target, rest, key := physical(mounts, r.Path, m.Path)
	if rest == "" {
		return refuse("not_found")
	}
	now := a.now()
	if a.cfg.Limits.ReadWindow != "" {
		start, end, err := parseWindow(a.cfg.Limits.ReadWindow)
		minute := now.Hour()*60 + now.Minute()
		open := minute >= start && minute < end
		if start > end {
			open = minute >= start || minute < end
		}
		if err != nil || !open {
			return refuse("limit")
		}
	}
	select {
	case a.slots <- struct{}{}:
	default:
		return refuse("busy")
	}
	defer func() { <-a.slots }()
	day := now.Format(time.DateOnly)
	a.mu.Lock()
	if a.quota.Day != day {
		a.quota = quota{Day: day}
	}
	if a.quota.Bytes+m.Size > int64(a.cfg.Limits.MaxGBPerDay)<<30 {
		a.mu.Unlock()
		return refuse("limit")
	}
	a.quota.Bytes += m.Size
	a.save("quota.json", a.quota)
	a.mu.Unlock()
	var sent int64
	defer func() {
		a.mu.Lock()
		if a.quota.Day == day && sent < m.Size {
			a.quota.Bytes -= m.Size - sent
			a.save("quota.json", a.quota)
		}
		a.mu.Unlock()
	}()
	f, err := a.src.Open(target, strings.ReplaceAll(rest, "/", `\`))
	if err != nil {
		return refuse(codeOf(err))
	}
	defer f.Close()
	before, err := f.Info()
	if err != nil {
		return refuse(codeOf(err))
	}
	if fmt.Sprintf("%016x", before.ID^bind(key)) != m.File || before.Size != m.Size || before.Modified.UnixMilli() != m.Modified {
		return refuse("changed")
	}
	buffer := make([]byte, 4+chunkSize)
	binary.BigEndian.PutUint32(buffer, uint32(m.ID))
	hash := sha256.New()
	bytesPerSecond := int64(a.cfg.Limits.MaxMbit) * 125000
	for sent < before.Size {
		if ctx.Err() != nil {
			return nil
		}
		for sent-t.acked.Load() >= ackWindow {
			select {
			case <-t.notify:
			case <-ctx.Done():
				return nil
			}
		}
		n := int(min(chunkSize, before.Size-sent))
		read, err := f.ReadAt(buffer[4:4+n], sent)
		if read < n && (err == nil || errors.Is(err, io.EOF)) {
			return refuse("changed")
		}
		if read < n {
			return refuse(codeOf(err))
		}
		select {
		case <-time.After(a.limiter.delay(time.Now(), n, bytesPerSecond)):
		case <-ctx.Done():
			return nil
		}
		hash.Write(buffer[4 : 4+n])
		err = frame(buffer[:4+n])
		sent += int64(n)
		if err != nil {
			return nil
		}
	}
	after, err := f.Info()
	if err != nil || after.ID != before.ID || after.Size != before.Size || !after.Modified.Equal(before.Modified) {
		return refuse("changed")
	}
	return doneMessage{Type: "done", ID: m.ID, SHA256: hex.EncodeToString(hash.Sum(nil))}
}

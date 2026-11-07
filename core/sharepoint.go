package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	need         = 0x31021
	fullMask     = 0x7FFFFFFFFFFFFFFF
	cellLife     = 840 * time.Second
	snapshotLife = 240 * time.Second
	fullBusy     = 10 * time.Minute
	maxBody      = 64 << 20
	listSelect   = "Id,BaseType,Hidden,IsCatalog,NoCrawl,IrmEnabled,EnableModeration,ReadSecurity,HasUniqueRoleAssignments,DefaultDisplayFormUrl,RootFolder/ServerRelativeUrl"
	rowSelect    = "Id,UniqueId,FileRef,FSObjType,HasUniqueRoleAssignments,Created,AuthorId,OData__UIVersion,OData__Level,OData__ModerationStatus"
	webSelect    = "Id,ServerRelativeUrl,HasUniqueRoleAssignments,NoCrawl"
)

var (
	siteRoots  *x509.CertPool
	pageTime   = 60 * time.Second
	accessTime = 300 * time.Second
	retryPause = func(ctx context.Context, wait time.Duration) error {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	errCursor     = errors.New("cursor")
	errBadRequest = errors.New("bad request")
	guidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	fieldKey      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	fieldTypes    = map[string]bool{"Text": true, "Note": true, "Number": true, "Integer": true, "Currency": true, "DateTime": true, "Boolean": true, "Choice": true, "MultiChoice": true, "URL": true}
	everyone      = map[string]bool{"c:0(.s|true": true, "c:0!.s|windows": true, "c:0+.w|s-1-1-0": true, "c:0+.w|s-1-5-11": true}
)

type num int64

func (n *num) UnmarshalJSON(data []byte) error {
	text := string(data)
	if strings.HasPrefix(text, `"`) {
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	*n = num(value)
	return err
}

type wireWeb struct {
	ID      string `json:"Id"`
	URL     string `json:"ServerRelativeUrl"`
	Unique  *bool  `json:"HasUniqueRoleAssignments"`
	NoCrawl *bool
}

type wireList struct {
	ID           string `json:"Id"`
	BaseType     *num
	Hidden       *bool
	IsCatalog    *bool
	NoCrawl      *bool
	IrmEnabled   *bool
	Moderation   *bool `json:"EnableModeration"`
	ReadSecurity *num
	Unique       *bool  `json:"HasUniqueRoleAssignments"`
	Form         string `json:"DefaultDisplayFormUrl"`
	RootFolder   struct{ ServerRelativeUrl string }
}

type wireRow struct {
	ID          *num `json:"Id"`
	UniqueID    string
	FileRef     string
	FSObjType   *num
	Unique      *bool `json:"HasUniqueRoleAssignments"`
	Created     string
	Modified    string
	AuthorID    *num `json:"AuthorId"`
	Attachments *bool
	Title       *string
	UIVersion   *num `json:"OData__UIVersion"`
	Level       *num `json:"OData__Level"`
	Status      *num `json:"OData__ModerationStatus"`
	File        *struct {
		Length           *num
		TimeLastModified string
	}
	AttachmentFiles []struct{ FileName, ServerRelativeUrl string }
	values          map[string]json.RawMessage
}

type wireChange struct {
	Token   struct{ StringValue string } `json:"ChangeToken"`
	ListID  string                       `json:"ListId"`
	WebID   string                       `json:"WebId"`
	ItemID  json.RawMessage              `json:"ItemId"`
	UserID  json.RawMessage              `json:"UserId"`
	GroupID json.RawMessage              `json:"GroupId"`
}

type spWeb struct {
	ID, URL, Parent, Scope string
	Skipped                bool
}

type spField struct{ Key, Title string }

type spList struct {
	ID, Web, Root, Form, Scope          string
	Library, Moderation, Owner, Skipped bool
	Fields                              []spField
	Entries                             map[string]spEntry
}

type spEntry struct {
	Item, Version, Size, Created, Modified int64
	ID                                     uint64
	UniqueID, Name, Scope, Owner, Class    string
	Sig, URL, Title                        string
}

type pathRef struct {
	list  *spList
	entry spEntry
	dup   bool
}

type baseline struct {
	site, token, path, origin string
	webs                      map[string]spWeb
	lists                     map[string]*spList
	paths                     map[string]pathRef
	partial                   bool
}

type spWalk struct {
	nonce      string
	page       int
	cursor     string
	started    time.Time
	cancel     context.CancelFunc
	until      atomic.Int64
	wake       chan struct{}
	done       chan struct{}
	old        *baseline
	base       *baseline
	err        error
	entries    []pageEntry
	deleted    []string
	incomplete []string
}

type siteRoot struct {
	base     *baseline
	full     *spWalk
	changes  *spWalk
	fullSeen time.Time
	webs     map[string]bool
	digest   string
	digestTo time.Time
	snap     *snapshot
}

type cell struct {
	mask uint64
	at   time.Time
}

type sites struct {
	src    Source
	client *http.Client
	mu     sync.Mutex
	roots  map[string]*siteRoot
	cells  map[string]cell
}

type siteUser struct {
	ID         int64
	Login, SID string
	Admin      bool
}

type principal struct {
	ID    int64
	Login string
	Type  int64
}

type assignment struct {
	Member  principal
	Members []principal
	Mask    uint64
}

type scopeGrants struct {
	Assignments []assignment
	hash        string
}

type snapshot struct {
	base   *baseline
	at     time.Time
	users  []siteUser
	scopes map[string]*scopeGrants
}

func newSites(src Source) *sites {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: siteRoots},
		Protocols:             protocols,
		MaxConnsPerHost:       4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
	}
	refuseRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &sites{src: src, client: &http.Client{Transport: transport, CheckRedirect: refuseRedirect}, roots: map[string]*siteRoot{}, cells: map[string]cell{}}
}

func sitePath(r root) string {
	site, _ := url.Parse(r.URL)
	return site.Path
}

func serverPath(r root) string {
	if p := sitePath(r); p != "" {
		return p
	}
	return "/"
}

func esc(serverRelative string) string {
	segments := strings.Split(serverRelative, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

func apiPath(web, rest string) string {
	return esc(strings.TrimSuffix(web, "/")) + "/_api/" + rest
}

func fileByURL(serverRelative string) string {
	return "web/GetFileByServerRelativeUrl('" + esc(strings.ReplaceAll(serverRelative, "'", "''")) + "')"
}

func within(p, base string) bool {
	return p == base || strings.HasPrefix(p, strings.TrimSuffix(base, "/")+"/")
}

func (s *sites) state(r root) *siteRoot {
	st := s.roots[r.ID]
	if st == nil {
		st = &siteRoot{webs: map[string]bool{sitePath(r): true}}
		s.roots[r.ID] = st
	}
	return st
}

func (s *sites) allowed(r root, req *http.Request) bool {
	site, _ := url.Parse(r.URL)
	p := req.URL.Path
	segments := strings.Split(p, "/")
	if req.URL.Scheme != "https" || req.URL.Host != site.Host || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || slices.Contains(segments, "..") || slices.Contains(segments, ".") {
		return false
	}
	if req.Method == http.MethodPost {
		return p == site.Path+"/_api/contextinfo" || p == site.Path+"/_api/site/getchanges"
	}
	if req.Method != http.MethodGet {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for web := range s.state(r).webs {
		if strings.HasPrefix(p, strings.TrimSuffix(web, "/")+"/_api/") {
			return true
		}
	}
	return false
}

func (s *sites) allow(r root, web string) {
	s.mu.Lock()
	s.state(r).webs[web] = true
	s.mu.Unlock()
}

func retryAfter(header string, wait int) time.Duration {
	delay := time.Duration(wait*5) * time.Second
	if seconds, err := strconv.Atoi(header); err == nil {
		delay = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(header); err == nil {
		delay = time.Until(at)
	}
	return min(max(delay, 0), 30*time.Second)
}

func (s *sites) do(ctx context.Context, r root, method, requestPath string, body []byte) (*http.Response, error) {
	site, _ := url.Parse(r.URL)
	raw, query, _ := strings.Cut(requestPath, "?")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return nil, errors.New("invalid request path")
	}
	target := (&url.URL{Scheme: "https", Host: site.Host, Path: decoded, RawPath: raw, RawQuery: query}).String()
	digest := ""
	if method == http.MethodPost && strings.HasSuffix(decoded, "/_api/site/getchanges") {
		if digest, err = s.digest(ctx, r); err != nil {
			return nil, err
		}
	}
	waits, rejected := 0, false
	for {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil || !s.allowed(r, req) {
			slog.Error("request outside the allow list", "root", r.ID, "method", method)
			return nil, errors.New("request outside the allow list")
		}
		token, err := s.src.Negotiate(r.SPN)
		if err != nil {
			return nil, fmt.Errorf("%w: kerberos for %s: %v", ErrUnavailable, r.SPN, err)
		}
		req.Header.Set("Authorization", "Negotiate "+token)
		req.Header.Set("Accept", "application/json;odata=nometadata")
		req.Header.Set("X-FORMS_BASED_AUTH_ACCEPTED", "f")
		req.Header.Set("User-Agent", "Thero-Connect/"+version)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json;odata=verbose")
			if digest != "" {
				req.Header.Set("X-RequestDigest", digest)
			}
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, s.failed(r, fmt.Errorf("%w: %v", ErrUnavailable, err))
		}
		status := resp.StatusCode
		if status >= 200 && status < 300 {
			return resp, nil
		}
		text, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		switch {
		case status >= 300 && status < 400:
			return nil, s.failed(r, fmt.Errorf("%w: redirect %d to %s", ErrUnavailable, status, resp.Header.Get("Location")))
		case status == http.StatusUnauthorized && !rejected:
			rejected = true
			continue
		case status == http.StatusUnauthorized:
			return nil, s.failed(r, fmt.Errorf("%w: Kerberos ticket rejected for %s; offered: %s; check SPN, clock and Extended Protection", ErrUnavailable, r.SPN, strings.Join(resp.Header.Values("WWW-Authenticate"), ", ")))
		case status == http.StatusForbidden && resp.Header.Get("X-FORMS_BASED_AUTH_REQUIRED") != "":
			return nil, s.failed(r, fmt.Errorf("%w: zone requires forms login", ErrUnavailable))
		case status == http.StatusForbidden:
			return nil, s.failed(r, ErrDenied)
		case status == http.StatusNotFound:
			return nil, ErrNotFound
		case status == http.StatusBadRequest:
			return nil, s.failed(r, errBadRequest)
		case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
			if waits == 2 {
				return nil, s.failed(r, fmt.Errorf("%w: throttled", ErrBusy))
			}
			waits++
			if err := retryPause(ctx, retryAfter(resp.Header.Get("Retry-After"), waits)); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrBusy, err)
			}
			continue
		case status == http.StatusInternalServerError && (bytes.Contains(text, []byte("SPQueryThrottledException")) || bytes.Contains(text, []byte("-2147024860"))):
			return nil, s.failed(r, fmt.Errorf("%w: list view threshold", ErrBusy))
		}
		return nil, s.failed(r, fmt.Errorf("status %d", status))
	}
}

func (s *sites) failed(r root, err error) error {
	slog.Warn("sharepoint request failed", "root", r.ID, "error", err)
	return err
}

func (s *sites) get(ctx context.Context, r root, method, requestPath string, body []byte, target any) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	resp, err := s.do(ctx, r, method, requestPath, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if len(data) > maxBody {
		return s.failed(r, errors.New("response over 64 MiB"))
	}
	return json.Unmarshal(data, target)
}

func (s *sites) digest(ctx context.Context, r root) (string, error) {
	s.mu.Lock()
	st := s.state(r)
	if st.digest != "" && time.Now().Before(st.digestTo) {
		defer s.mu.Unlock()
		return st.digest, nil
	}
	s.mu.Unlock()
	var info struct {
		FormDigestValue          string
		FormDigestTimeoutSeconds *num
	}
	if err := s.get(ctx, r, http.MethodPost, apiPath(sitePath(r), "contextinfo"), nil, &info); err != nil {
		return "", err
	}
	if info.FormDigestValue == "" || info.FormDigestTimeoutSeconds == nil {
		return "", errors.New("invalid form digest")
	}
	s.mu.Lock()
	st.digest, st.digestTo = info.FormDigestValue, time.Now().Add(time.Duration(*info.FormDigestTimeoutSeconds-60)*time.Second)
	s.mu.Unlock()
	return info.FormDigestValue, nil
}

func (s *sites) lists(ctx context.Context, r root, web, id string, target any) error {
	base := apiPath(web, "web/lists")
	if id != "" {
		base += "(guid'" + id + "')"
	}
	err := s.get(ctx, r, http.MethodGet, base+"?$select="+listSelect+"&$expand=RootFolder", nil, target)
	if !errors.Is(err, errBadRequest) {
		return err
	}
	return s.get(ctx, r, http.MethodGet, base+"?$select="+strings.Replace(listSelect, ",ReadSecurity", "", 1)+"&$expand=RootFolder", nil, target)
}

func validToken(token, site string) bool {
	fields := strings.Split(token, ";")
	if len(fields) != 5 || fields[0] != "1" || fields[1] != "1" || strings.ToLower(fields[2]) != site {
		return false
	}
	_, ticks := strconv.ParseUint(fields[3], 10, 64)
	_, number := strconv.ParseUint(fields[4], 10, 64)
	return ticks == nil && number == nil
}

func millis(text string) int64 {
	at, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return 0
	}
	return max(0, at.UnixMilli())
}

func fileID(unique, name string, version int64) uint64 {
	sum := sha256.Sum256([]byte(unique + "\x00" + name))
	return uint64(binary.BigEndian.Uint32(sum[:4]))<<32 | uint64(uint32(version))
}

func originOf(siteURL string) string {
	site, err := url.Parse(siteURL)
	if err != nil || site.Scheme != "https" && site.Scheme != "http" || site.Host == "" || strings.ContainsAny(siteURL, " \t\r\n") {
		return ""
	}
	return site.Scheme + "://" + site.Host
}

func link(origin, serverRelative, suffix string) string {
	address := origin + esc(serverRelative) + suffix
	if origin == "" || serverRelative == "" || len(address) > 2048 || strings.ContainsAny(address, " \t\r\n") {
		return ""
	}
	return address
}

func rowQuery(l *spList) string {
	if l.Library {
		return "$select=" + rowSelect + ",File/Length,File/TimeLastModified&$expand=File"
	}
	fields := ""
	for _, field := range l.Fields {
		fields += "," + field.Key
	}
	return "$select=" + rowSelect + ",Modified,Attachments,Title,AttachmentFiles/FileName,AttachmentFiles/ServerRelativeUrl" + fields + "&$expand=AttachmentFiles"
}

func show(value any) string {
	switch v := value.(type) {
	case string:
		return strings.ReplaceAll(v, "\r\n", "\n")
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "Yes"
		}
		return "No"
	case []any:
		parts := []string{}
		for _, item := range v {
			if text := show(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		address, _ := v["Url"].(string)
		description, _ := v["Description"].(string)
		if address == "" {
			return ""
		}
		return description + " (" + address + ")"
	}
	return ""
}

func render(title string, fields []spField, values map[string]json.RawMessage) string {
	var out strings.Builder
	out.WriteString("# " + title + "\n\n")
	for _, field := range fields {
		var value any
		if json.Unmarshal(values[field.Key], &value) != nil {
			continue
		}
		if text := show(value); text != "" {
			out.WriteString("- " + field.Title + ": " + text + "\n")
		}
	}
	return out.String()
}

func titleOf(row wireRow, item int64) string {
	title := ""
	if row.Title != nil {
		title = *row.Title
	}
	if strings.TrimSpace(title) == "" {
		return "Item " + strconv.FormatInt(item, 10)
	}
	if runes := []rune(title); len(runes) > 255 {
		return string(runes[:255])
	}
	return title
}

func describe(b *baseline, l *spList, row wireRow) (spEntry, bool) {
	e := spEntry{UniqueID: strings.ToLower(row.UniqueID), Created: millis(row.Created)}
	if row.ID != nil {
		e.Item = int64(*row.ID)
	}
	if row.UIVersion != nil {
		e.Version = int64(*row.UIVersion)
	}
	status := int64(0)
	if row.Status != nil {
		status = int64(*row.Status)
	}
	ok := row.ID != nil && row.Unique != nil && row.FSObjType != nil && *row.FSObjType == 0 && row.UIVersion != nil && row.Level != nil &&
		e.Version > 0 && e.Version%512 == 0 && *row.Level == 1 && (!l.Moderation || row.Status != nil && status == 0)
	e.ID = fileID(e.UniqueID, "", e.Version)
	stamp := row.Modified
	if l.Library {
		ok = ok && row.File != nil && row.File.Length != nil
		if row.File != nil {
			stamp = row.File.TimeLastModified
		}
		if ok {
			e.Size = int64(*row.File.Length)
		}
		e.URL = link(b.origin, row.FileRef, "")
	} else {
		e.Title = titleOf(row, e.Item)
		e.Size = int64(len(render(e.Title, l.Fields, row.values)))
		e.URL = link(b.origin, l.Form, "?ID="+strconv.FormatInt(e.Item, 10))
	}
	e.Modified = millis(stamp)
	if ok {
		e.Sig = fmt.Sprintf("%s %t %d %d %d %s", e.UniqueID, *row.Unique, e.Version, int64(*row.Level), status, stamp)
	}
	return e, ok
}

func scopeOf(l *spList, row wireRow, folders map[string]wireRow) string {
	if row.Unique == nil || row.ID == nil {
		return ""
	}
	if *row.Unique {
		return fmt.Sprintf("i:%s:%d", l.ID, int64(*row.ID))
	}
	for dir := path.Dir(row.FileRef); dir != l.Root; dir = path.Dir(dir) {
		folder, ok := folders[dir]
		if !ok || !strings.HasPrefix(dir, l.Root+"/") || folder.Unique == nil || folder.ID == nil {
			return ""
		}
		if *folder.Unique {
			return fmt.Sprintf("i:%s:%d", l.ID, int64(*folder.ID))
		}
	}
	return l.Scope
}

func spClass(root, site, scope, owner string) string {
	sum := sha256.Sum256([]byte("thero-connect/sharepoint/1\x00" + root + "\x00" + site + "\x00" + scope + "\x00" + owner))
	return hex.EncodeToString(sum[:])[:32]
}

func (b *baseline) relative(serverRelative string) (string, bool) {
	return strings.CutPrefix(serverRelative, strings.TrimSuffix(b.path, "/")+"/")
}

func (b *baseline) ref(p string) (pathRef, bool) {
	if b == nil {
		return pathRef{}, false
	}
	ref, ok := b.paths[p]
	return ref, ok
}

func (b *baseline) scopePath(scope string) string {
	kind, rest, _ := strings.Cut(scope, ":")
	list, item, _ := strings.Cut(rest, ":")
	if kind == "w" {
		return apiPath(b.webs[rest].URL, "web")
	}
	listPath := apiPath(b.webs[b.lists[list].Web].URL, "web/lists(guid'"+list+"')")
	if kind == "l" {
		return listPath
	}
	return listPath + "/items(" + item + ")"
}

func (b *baseline) index() int {
	count := map[string]int{}
	for _, l := range b.lists {
		for p := range l.Entries {
			count[strings.ToLower(p)]++
		}
	}
	b.paths = map[string]pathRef{}
	duplicates := 0
	for _, l := range b.lists {
		for p, e := range l.Entries {
			ref := pathRef{list: l, entry: e, dup: count[strings.ToLower(p)] > 1}
			b.paths[p] = ref
			if ref.dup {
				duplicates++
			}
		}
	}
	return duplicates
}

func (ref pathRef) page(p string) pageEntry {
	e := ref.entry
	entry := pageEntry{Path: p, File: fmt.Sprintf("%016x", e.ID), Size: e.Size, Created: e.Created, Modified: e.Modified, URL: e.URL, Title: e.Title}
	if e.Class != "" && !ref.dup {
		class := e.Class
		entry.Class = &class
	}
	return entry
}

type spRun struct {
	s                                         *sites
	r                                         root
	ctx                                       context.Context
	w                                         *spWalk
	old, b                                    *baseline
	maxFile                                   int64
	incremental                               bool
	incomplete                                []string
	listed, skipped, webs, lists, attachments int
}

func (w *spWalk) gate(ctx context.Context) error {
	for time.Now().UnixNano() >= w.until.Load() {
		select {
		case <-w.wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func (x *spRun) get(requestPath string, target any) error {
	if err := x.w.gate(x.ctx); err != nil {
		return err
	}
	return x.s.get(x.ctx, x.r, http.MethodGet, requestPath, nil, target)
}

func (x *spRun) fail(rel string) {
	x.incomplete = append(x.incomplete, rel)
	x.b.partial = true
}

func (x *spRun) keep(web string) {
	if !x.incremental {
		return
	}
	for id, w := range x.old.webs {
		if within(w.URL, web) {
			x.b.webs[id] = w
		}
	}
	for id, l := range x.old.lists {
		if within(x.old.webs[l.Web].URL, web) {
			x.b.lists[id] = l
		}
	}
}

func (x *spRun) drop(web string) {
	for id, l := range x.b.lists {
		if within(x.b.webs[l.Web].URL, web) {
			delete(x.b.lists, id)
		}
	}
	for id, w := range x.b.webs {
		if within(w.URL, web) {
			delete(x.b.webs, id)
		}
	}
}

func (x *spRun) full() error {
	var site struct {
		ID    string                       `json:"Id"`
		URL   string                       `json:"Url"`
		Path  string                       `json:"ServerRelativeUrl"`
		Token struct{ StringValue string } `json:"CurrentChangeToken"`
	}
	if err := x.get(apiPath(sitePath(x.r), "site?$select=Id,Url,ServerRelativeUrl,CurrentChangeToken"), &site); err != nil {
		return err
	}
	if site.Path != serverPath(x.r) {
		return fmt.Errorf("%w: not a site collection URL", ErrUnavailable)
	}
	id := strings.ToLower(site.ID)
	if !guidPattern.MatchString(id) || !validToken(site.Token.StringValue, id) {
		return errors.New("invalid site id or change token")
	}
	x.b = &baseline{site: id, token: site.Token.StringValue, path: site.Path, origin: originOf(site.URL), webs: map[string]spWeb{}, lists: map[string]*spList{}}
	var web wireWeb
	if err := x.get(apiPath(site.Path, "web?$select="+webSelect), &web); err != nil {
		return err
	}
	if err := x.visit(web, ""); err != nil {
		return err
	}
	return x.finish()
}

func (x *spRun) visit(web wireWeb, parent string) error {
	id := strings.ToLower(web.ID)
	rel, below := x.b.relative(web.URL)
	valid := guidPattern.MatchString(id) && web.Unique != nil && web.NoCrawl != nil
	if parent == "" && (!valid || web.URL != x.b.path || !*web.Unique) {
		return errors.New("invalid root web")
	}
	if parent != "" && !below {
		return nil
	}
	if !valid {
		x.fail(rel)
		x.keep(web.URL)
		return nil
	}
	scope := x.b.webs[parent].Scope
	if *web.Unique {
		scope = "w:" + id
	}
	record := spWeb{ID: id, URL: web.URL, Parent: parent, Scope: scope, Skipped: *web.NoCrawl}
	x.b.webs[id] = record
	if record.Skipped {
		return nil
	}
	x.s.allow(x.r, web.URL)
	x.webs++
	var lists struct {
		Value []wireList `json:"value"`
	}
	var children struct {
		Value []wireWeb `json:"value"`
	}
	err := x.w.gate(x.ctx)
	if err == nil {
		err = x.s.lists(x.ctx, x.r, web.URL, "", &lists)
	}
	if err == nil {
		err = x.get(apiPath(web.URL, "web/webs?$select="+webSelect), &children)
	}
	if err != nil && parent == "" {
		return err
	}
	if err != nil {
		x.fail(rel)
		x.keep(web.URL)
		return nil
	}
	for _, l := range lists.Value {
		x.readList(l, record)
	}
	for _, child := range children.Value {
		x.visit(child, id)
	}
	return nil
}

func (x *spRun) readList(wire wireList, web spWeb) {
	id := strings.ToLower(wire.ID)
	rel, below := x.b.relative(wire.RootFolder.ServerRelativeUrl)
	if !guidPattern.MatchString(id) {
		if below && rel != "" {
			x.fail(rel)
		}
		return
	}
	l := &spList{ID: id, Web: web.ID, Root: wire.RootFolder.ServerRelativeUrl, Form: wire.Form, Skipped: true, Entries: map[string]spEntry{}}
	x.b.lists[id] = l
	if !below || rel == "" {
		return
	}
	if wire.BaseType == nil || wire.Hidden == nil || wire.IsCatalog == nil || wire.NoCrawl == nil || wire.IrmEnabled == nil || wire.Moderation == nil || wire.Unique == nil {
		x.fail(rel)
		x.restore(id)
		return
	}
	l.Library = *wire.BaseType == 1
	l.Moderation = *wire.Moderation
	l.Owner = !l.Library && (wire.ReadSecurity == nil || *wire.ReadSecurity != 1)
	l.Scope = web.Scope
	if *wire.Unique {
		l.Scope = "l:" + id
	}
	l.Skipped = *wire.Hidden || *wire.IsCatalog || *wire.NoCrawl || *wire.IrmEnabled || excluded(x.r.Exclude, rel)
	if l.Skipped {
		return
	}
	x.lists++
	if err := x.items(l, web); err != nil {
		l.Entries = map[string]spEntry{}
		x.fail(rel)
		x.restore(id)
	}
}

func (x *spRun) restore(id string) {
	if !x.incremental {
		return
	}
	if previous, ok := x.old.lists[id]; ok {
		x.b.lists[id] = previous
	}
}

func (x *spRun) items(l *spList, web spWeb) error {
	listPath := apiPath(web.URL, "web/lists(guid'"+l.ID+"')")
	top := 5000
	if !l.Library {
		top = 1000
		var fields struct {
			Value []struct{ EntityPropertyName, Title, TypeAsString string } `json:"value"`
		}
		if err := x.get(listPath+"/fields?$filter=Hidden%20eq%20false%20and%20ReadOnlyField%20eq%20false&$select=EntityPropertyName,Title,TypeAsString", &fields); err != nil {
			return err
		}
		for _, field := range fields.Value {
			if len(l.Fields) < 40 && field.EntityPropertyName != "Title" && fieldTypes[field.TypeAsString] && fieldKey.MatchString(field.EntityPropertyName) {
				l.Fields = append(l.Fields, spField{Key: field.EntityPropertyName, Title: field.Title})
			}
		}
	}
	var rows []wireRow
	last := int64(0)
	for {
		query := listPath + "/items?" + rowQuery(l) + "&$orderby=Id&$top=" + strconv.Itoa(top)
		if last > 0 {
			query += "&$skiptoken=Paged=TRUE%26p_ID=" + strconv.FormatInt(last, 10)
		}
		var page struct {
			Value []json.RawMessage `json:"value"`
		}
		if err := x.get(query, &page); err != nil {
			return err
		}
		for _, raw := range page.Value {
			var key struct {
				ID *num `json:"Id"`
			}
			if json.Unmarshal(raw, &key) != nil || key.ID == nil || int64(*key.ID) <= last {
				return errors.New("invalid item id")
			}
			last = int64(*key.ID)
			var row wireRow
			if json.Unmarshal(raw, &row) != nil {
				x.skipped++
				continue
			}
			if !l.Library {
				json.Unmarshal(raw, &row.values)
			}
			rows = append(rows, row)
		}
		if len(page.Value) < top {
			break
		}
	}
	x.entries(l, rows)
	return nil
}

func (x *spRun) skip(rel string, size int64) bool {
	_, err := validPath(rel)
	return err != nil || excluded(x.r.Exclude, rel) || size > x.maxFile
}

func (x *spRun) entries(l *spList, rows []wireRow) {
	folders := map[string]wireRow{}
	for _, row := range rows {
		if row.FSObjType != nil && *row.FSObjType == 1 {
			folders[row.FileRef] = row
		}
	}
	for _, row := range rows {
		if row.FSObjType != nil && *row.FSObjType == 1 {
			continue
		}
		rel, below := x.b.relative(row.FileRef)
		if !l.Library {
			rel += ".md"
		}
		e, published := describe(x.b, l, row)
		if !below || !strings.HasPrefix(row.FileRef, l.Root+"/") || x.skip(rel, e.Size) || l.Library && strings.HasSuffix(strings.ToLower(rel), ".aspx") {
			x.skipped++
			continue
		}
		e.Scope = scopeOf(l, row, folders)
		if l.Owner && row.AuthorID != nil {
			e.Owner = strconv.FormatInt(int64(*row.AuthorID), 10)
		}
		if published && e.Scope != "" && (!l.Owner || e.Owner != "") {
			e.Class = spClass(x.r.ID, x.b.site, e.Scope, e.Owner)
		}
		l.Entries[rel] = e
		x.listed++
		if published && !l.Library && row.Attachments != nil && *row.Attachments {
			x.attach(l, row, e)
		}
	}
}

func (x *spRun) attach(l *spList, row wireRow, item spEntry) {
	prefix := l.Root + "/Attachments/" + strconv.FormatInt(item.Item, 10) + "/"
	for _, file := range row.AttachmentFiles {
		rel, below := x.b.relative(file.ServerRelativeUrl)
		name, under := strings.CutPrefix(file.ServerRelativeUrl, prefix)
		if !under || !below || name != file.FileName || strings.ContainsAny(name, "#%/") || x.skip(rel, 0) {
			x.skipped++
			continue
		}
		e := item
		e.Name, e.Title = name, ""
		e.ID = fileID(item.UniqueID, name, item.Version)
		e.URL = link(x.b.origin, file.ServerRelativeUrl, "")
		if old, ok := x.old.ref(rel); ok && old.list.ID == l.ID && old.entry.Name == name && old.entry.Item == item.Item && old.entry.Sig == item.Sig {
			e.Size, e.Modified = old.entry.Size, old.entry.Modified
		} else {
			var props struct {
				Length           *num
				TimeLastModified string
			}
			if err := x.get(apiPath(x.b.webs[l.Web].URL, fileByURL(file.ServerRelativeUrl)+"?$select=Length,TimeLastModified"), &props); err != nil || props.Length == nil {
				x.skipped++
				continue
			}
			e.Size, e.Modified = int64(*props.Length), millis(props.TimeLastModified)
		}
		if e.Size > x.maxFile {
			x.skipped++
			continue
		}
		l.Entries[rel] = e
		x.attachments++
	}
}

func changeQuery(token string) map[string]any {
	query := map[string]any{"__metadata": map[string]string{"type": "SP.ChangeQuery"}}
	for _, name := range []string{"Add", "Update", "DeleteObject", "Rename", "Move", "Restore", "SystemUpdate", "RoleAssignmentAdd", "RoleAssignmentDelete", "SecurityPolicy", "Item", "List", "Web", "Site"} {
		query[name] = true
	}
	query["ChangeTokenStart"] = map[string]any{"__metadata": map[string]string{"type": "SP.ChangeToken"}, "StringValue": token}
	return map[string]any{"query": query}
}

func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

func guidOf(text string) string {
	text = strings.ToLower(text)
	if text == "00000000-0000-0000-0000-000000000000" {
		return ""
	}
	return text
}

func (x *spRun) changes() error {
	old := x.old
	token := old.token
	var log []wireChange
	for {
		if err := x.w.gate(x.ctx); err != nil {
			return err
		}
		body, _ := json.Marshal(changeQuery(token))
		var page struct {
			Value []wireChange `json:"value"`
		}
		err := x.s.get(x.ctx, x.r, http.MethodPost, apiPath(sitePath(x.r), "site/getchanges"), body, &page)
		if errors.Is(err, ErrBusy) || errors.Is(err, ErrUnavailable) {
			return err
		}
		if err != nil {
			return errCursor
		}
		if len(page.Value) == 0 {
			break
		}
		log = append(log, page.Value...)
		token = page.Value[len(page.Value)-1].Token.StringValue
		if len(log) > 5000 || !validToken(token, old.site) {
			return errCursor
		}
	}
	lists, webs := map[string]bool{}, map[string]bool{}
	for _, change := range log {
		listID, webID := guidOf(change.ListID), guidOf(change.WebID)
		_, knownWeb := old.webs[webID]
		switch {
		case listID != "":
			l, known := old.lists[listID]
			if known && l.Skipped && present(change.ItemID) {
				continue
			}
			if known {
				lists[listID] = true
				continue
			}
			if !knownWeb {
				return errCursor
			}
			webs[webID] = true
		case present(change.UserID) || present(change.GroupID):
		case webID != "" && knownWeb:
			webs[webID] = true
		default:
			return errCursor
		}
	}
	x.b = &baseline{site: old.site, token: token, path: old.path, origin: old.origin, webs: maps.Clone(old.webs), lists: maps.Clone(old.lists)}
	var walked []string
	order := slices.SortedFunc(maps.Keys(webs), func(first, second string) int { return strings.Compare(old.webs[first].URL, old.webs[second].URL) })
	for _, id := range order {
		web := old.webs[id]
		if slices.ContainsFunc(walked, func(done string) bool { return within(web.URL, done) }) {
			continue
		}
		rel, _ := x.b.relative(web.URL)
		var wire wireWeb
		err := x.get(apiPath(web.URL, "web?$select="+webSelect), &wire)
		if errors.Is(err, ErrNotFound) {
			x.drop(web.URL)
			x.b.webs[id] = spWeb{ID: id, URL: web.URL, Parent: web.Parent, Skipped: true}
			walked = append(walked, web.URL)
			continue
		}
		if err != nil {
			x.fail(rel)
			continue
		}
		if strings.ToLower(wire.ID) != id {
			return errCursor
		}
		x.drop(web.URL)
		if err := x.visit(wire, web.Parent); err != nil {
			return errCursor
		}
		walked = append(walked, web.URL)
	}
	for _, id := range slices.Sorted(maps.Keys(lists)) {
		l := old.lists[id]
		web, ok := x.b.webs[l.Web]
		if !ok || slices.ContainsFunc(walked, func(done string) bool { return within(web.URL, done) }) {
			continue
		}
		rel, _ := x.b.relative(l.Root)
		var wire wireList
		err := x.w.gate(x.ctx)
		if err == nil {
			err = x.s.lists(x.ctx, x.r, web.URL, id, &wire)
		}
		if errors.Is(err, ErrNotFound) {
			x.b.lists[id] = &spList{ID: id, Web: l.Web, Root: l.Root, Skipped: true, Entries: map[string]spEntry{}}
			continue
		}
		if err != nil {
			x.fail(rel)
			continue
		}
		x.readList(wire, web)
	}
	return x.finish()
}

func (x *spRun) finish() error {
	if err := x.ctx.Err(); err != nil {
		return err
	}
	duplicates := x.b.index()
	x.w.entries = []pageEntry{}
	for _, p := range slices.Sorted(maps.Keys(x.b.paths)) {
		ref := x.b.paths[p]
		if before, ok := x.old.ref(p); x.incremental && ok && before.entry == ref.entry && before.dup == ref.dup {
			continue
		}
		x.w.entries = append(x.w.entries, ref.page(p))
	}
	x.w.deleted = []string{}
	if x.incremental {
		for _, p := range slices.Sorted(maps.Keys(x.old.paths)) {
			if _, ok := x.b.paths[p]; !ok {
				x.w.deleted = append(x.w.deleted, p)
			}
		}
	}
	x.w.incomplete = append([]string{}, x.incomplete...)
	x.w.base = x.b
	slog.Info("site walk computed", "root", x.r.ID, "changes", x.incremental, "listed", x.listed, "skipped", x.skipped, "incomplete", len(x.incomplete), "lists", x.lists, "webs", x.webs, "attachments", x.attachments, "duplicates", duplicates, "entries", len(x.w.entries), "deleted", len(x.w.deleted))
	return nil
}

func (s *sites) start(a *agent, r root, old *baseline, changes bool) *spWalk {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	ctx, cancel := context.WithCancel(context.Background())
	w := &spWalk{nonce: hex.EncodeToString(nonce), started: a.now(), cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{}), old: old}
	x := &spRun{s: s, r: r, ctx: ctx, w: w, old: old, maxFile: int64(a.cfg.Limits.MaxFileMB) << 20, incremental: changes}
	go func() {
		defer close(w.done)
		if changes {
			w.err = x.changes()
		} else {
			w.err = x.full()
		}
	}()
	return w
}

func cut[T any](items *[]T) []T {
	n := min(pageSize, len(*items))
	taken := (*items)[:n:n]
	*items = (*items)[n:]
	return taken
}

func (a *agent) siteWalk(m message, r root) any {
	s := a.sites
	s.mu.Lock()
	st := s.state(r)
	slot := &st.full
	if m.Changes {
		slot = &st.changes
	}
	if m.Cursor == "" {
		if m.Changes && st.full != nil && a.now().Sub(st.fullSeen) < fullBusy {
			s.mu.Unlock()
			return failure(m.ID, "busy", "full walk running")
		}
		if m.Changes && (st.base == nil || st.base.partial) {
			s.mu.Unlock()
			return failure(m.ID, "cursor", "no complete baseline")
		}
		if *slot != nil {
			(*slot).cancel()
		}
		if !m.Changes && st.changes != nil {
			st.changes.cancel()
			st.changes = nil
		}
		*slot = s.start(a, r, st.base, m.Changes)
	}
	w := *slot
	if w == nil || m.Cursor != w.cursor {
		s.mu.Unlock()
		return failure(m.ID, "cursor", "unknown walk cursor")
	}
	if !m.Changes {
		st.fullSeen = a.now()
	}
	s.mu.Unlock()
	w.until.Store(time.Now().Add(pageTime).UnixNano())
	select {
	case w.wake <- struct{}{}:
	default:
	}
	timer := time.NewTimer(pageTime)
	select {
	case <-w.done:
	case <-timer.C:
	}
	timer.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if *slot != w {
		return failure(m.ID, "cursor", "walk replaced")
	}
	select {
	case <-w.done:
	default:
		w.page++
		w.cursor = fmt.Sprintf("%s-%d", w.nonce, w.page)
		return pageMessage{Type: "page", ID: m.ID, Cursor: w.cursor, Entries: []pageEntry{}, Incomplete: []string{}}
	}
	if w.err != nil {
		*slot = nil
		code := codeOf(w.err)
		if errors.Is(w.err, errCursor) {
			code = "cursor"
		}
		if !m.Changes {
			a.mu.Lock()
			delete(a.walked, r.ID)
			a.save("walks.json", a.walked)
			a.mu.Unlock()
		}
		slog.Warn("site walk failed", "root", r.ID, "changes", m.Changes, "code", code, "error", w.err)
		return failure(m.ID, code, "root listing failed")
	}
	page := pageMessage{Type: "page", ID: m.ID, Entries: cut(&w.entries), Incomplete: cut(&w.incomplete)}
	if m.Changes {
		page.Deleted = cut(&w.deleted)
	}
	if len(w.entries) > 0 || len(w.incomplete) > 0 || len(w.deleted) > 0 {
		w.page++
		w.cursor = fmt.Sprintf("%s-%d", w.nonce, w.page)
		page.Cursor = w.cursor
		return page
	}
	*slot = nil
	if !m.Changes || st.base == w.old {
		st.base = w.base
	}
	if !m.Changes {
		a.mu.Lock()
		a.walked[r.ID] = w.started
		a.save("walks.json", a.walked)
		a.mu.Unlock()
	}
	return page
}

func (p principal) matches(person Member, u siteUser) bool {
	login := strings.ToLower(p.Login)
	switch {
	case p.Type < 0 || p.Type == 8:
		return false
	case everyone[login]:
		return true
	case p.Type == 1:
		return p.ID == u.ID
	case p.Type == 4:
		sid, ok := strings.CutPrefix(login, "c:0+.w|")
		return ok && slices.Contains(person.SIDs, sid)
	}
	return false
}

func (g *scopeGrants) mask(person Member, u siteUser) uint64 {
	if u.Admin {
		return fullMask
	}
	var mask uint64
	for _, item := range g.Assignments {
		member := func(p principal) bool { return p.matches(person, u) }
		if member(item.Member) || item.Member.Type == 8 && slices.ContainsFunc(item.Members, member) {
			mask |= item.Mask
		}
	}
	return mask
}

func (snap *snapshot) verified(person Member) (siteUser, bool) {
	var found []siteUser
	for _, u := range snap.users {
		if person.Login != "" && strings.ToLower(u.Login) == person.Login && u.SID == person.SID {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		return siteUser{}, false
	}
	return found[0], true
}

func (s *sites) members(ctx context.Context, r root, group int64) []principal {
	var wire struct {
		Value []struct {
			ID            *num `json:"Id"`
			LoginName     string
			PrincipalType *num
		} `json:"value"`
	}
	if s.get(ctx, r, http.MethodGet, apiPath(sitePath(r), "web/sitegroups/getbyid("+strconv.FormatInt(group, 10)+")/users?$select=Id,LoginName,PrincipalType"), nil, &wire) != nil {
		return nil
	}
	members := []principal{}
	for _, item := range wire.Value {
		if item.ID == nil {
			continue
		}
		member := principal{ID: int64(*item.ID), Login: item.LoginName, Type: -1}
		if item.PrincipalType != nil {
			member.Type = int64(*item.PrincipalType)
		}
		members = append(members, member)
	}
	return members
}

func (s *sites) grants(ctx context.Context, r root, b *baseline, scope string, admins []int64, groups map[int64][]principal) (*scopeGrants, error) {
	if web, ok := strings.CutPrefix(scope, "w:"); ok {
		var identity struct {
			ID string `json:"Id"`
		}
		if err := s.get(ctx, r, http.MethodGet, apiPath(b.webs[web].URL, "web?$select=Id"), nil, &identity); err != nil {
			return nil, err
		}
		if strings.ToLower(identity.ID) != web {
			return nil, errors.New("web replaced")
		}
	}
	var wire struct {
		Value []struct {
			Member struct {
				ID            *num `json:"Id"`
				LoginName     string
				PrincipalType *num
			}
			RoleDefinitionBindings []struct{ BasePermissions *struct{ High, Low *num } }
		} `json:"value"`
	}
	if err := s.get(ctx, r, http.MethodGet, b.scopePath(scope)+"/roleassignments?$expand=Member,RoleDefinitionBindings&$select=Member/Id,Member/LoginName,Member/PrincipalType,RoleDefinitionBindings/BasePermissions", nil, &wire); err != nil {
		return nil, err
	}
	g := &scopeGrants{}
	for _, item := range wire.Value {
		if item.Member.ID == nil || item.Member.PrincipalType == nil {
			return nil, errors.New("invalid role assignment")
		}
		granted := assignment{Member: principal{ID: int64(*item.Member.ID), Login: item.Member.LoginName, Type: int64(*item.Member.PrincipalType)}}
		for _, binding := range item.RoleDefinitionBindings {
			bits := binding.BasePermissions
			if bits == nil || bits.High == nil || bits.Low == nil || *bits.High < 0 || *bits.High > 0x7FFFFFFF || *bits.Low < 0 || *bits.Low > 0xFFFFFFFF {
				return nil, errors.New("invalid role binding")
			}
			granted.Mask |= uint64(*bits.High)<<32 | uint64(*bits.Low)
		}
		if granted.Member.Type == 8 {
			members, known := groups[granted.Member.ID]
			if !known {
				members = s.members(ctx, r, granted.Member.ID)
				groups[granted.Member.ID] = members
			}
			granted.Members = members
		}
		g.Assignments = append(g.Assignments, granted)
	}
	data, _ := json.Marshal(struct {
		Assignments []assignment
		Admins      []int64
	}{g.Assignments, admins})
	sum := sha256.Sum256(data)
	g.hash = hex.EncodeToString(sum[:])
	return g, nil
}

func (s *sites) snapshot(ctx context.Context, r root, b *baseline, scopes []string, now time.Time) (*snapshot, error) {
	s.mu.Lock()
	st := s.state(r)
	if snap := st.snap; snap != nil && snap.base == b && now.Sub(snap.at) < snapshotLife {
		s.mu.Unlock()
		return snap, nil
	}
	s.mu.Unlock()
	var identity struct {
		ID string `json:"Id"`
	}
	if err := s.get(ctx, r, http.MethodGet, apiPath(sitePath(r), "site?$select=Id"), nil, &identity); err != nil {
		return nil, err
	}
	if strings.ToLower(identity.ID) != b.site {
		return nil, fmt.Errorf("%w: site collection replaced", ErrUnavailable)
	}
	var users struct {
		Value []struct {
			ID          *num `json:"Id"`
			LoginName   string
			IsSiteAdmin *bool
			UserID      *struct {
				NameID string `json:"NameId"`
			} `json:"UserId"`
		} `json:"value"`
	}
	if err := s.get(ctx, r, http.MethodGet, apiPath(sitePath(r), "web/siteusers?$select=Id,LoginName,IsSiteAdmin,UserId"), nil, &users); err != nil {
		return nil, err
	}
	snap := &snapshot{base: b, at: now, scopes: map[string]*scopeGrants{}}
	admins := []int64{}
	for _, row := range users.Value {
		if row.ID == nil || row.IsSiteAdmin == nil || row.UserID == nil || row.UserID.NameID == "" || row.LoginName == "" {
			continue
		}
		snap.users = append(snap.users, siteUser{ID: int64(*row.ID), Login: row.LoginName, SID: strings.ToLower(row.UserID.NameID), Admin: *row.IsSiteAdmin})
		if *row.IsSiteAdmin {
			admins = append(admins, int64(*row.ID))
		}
	}
	slices.Sort(admins)
	groups := map[int64][]principal{}
	for _, scope := range scopes {
		if grants, err := s.grants(ctx, r, b, scope, admins, groups); err == nil {
			snap.scopes[scope] = grants
		}
	}
	s.mu.Lock()
	st.snap = snap
	s.mu.Unlock()
	return snap, nil
}

func (s *sites) permissions(ctx context.Context, r root, b *baseline, scope, login string) (uint64, error) {
	var bits struct{ High, Low *num }
	query := "?@u='" + url.QueryEscape(strings.ReplaceAll(login, "'", "''")) + "'"
	if err := s.get(ctx, r, http.MethodGet, b.scopePath(scope)+"/getusereffectivepermissions(@u)"+query, nil, &bits); err != nil {
		return 0, err
	}
	if bits.High == nil || bits.Low == nil || *bits.High < 0 || *bits.High > 0x7FFFFFFF || *bits.Low < 0 || *bits.Low > 0xFFFFFFFF {
		return 0, errors.New("invalid permission mask")
	}
	return uint64(*bits.High)<<32 | uint64(*bits.Low), nil
}

func (a *agent) siteAccess(ctx context.Context, r root, members []Member, membersErr error) ([]classReaders, string) {
	s := a.sites
	s.mu.Lock()
	b := s.state(r).base
	now := a.now()
	for key, c := range s.cells {
		if now.Sub(c.at) >= cellLife {
			delete(s.cells, key)
		}
	}
	s.mu.Unlock()
	if b == nil {
		return nil, "unavailable"
	}
	type class struct{ scope, owner string }
	registry := map[string]class{}
	for _, ref := range b.paths {
		if ref.entry.Class != "" && !ref.dup {
			registry[ref.entry.Class] = class{ref.entry.Scope, ref.entry.Owner}
		}
	}
	readers := map[string][]int{}
	report := func(code string) ([]classReaders, string) {
		classes := []classReaders{}
		for _, id := range slices.Sorted(maps.Keys(registry)) {
			classes = append(classes, classReaders{Class: id, Readers: append([]int{}, readers[id]...)})
		}
		return classes, code
	}
	a.mu.Lock()
	at, walked := a.walked[r.ID]
	a.mu.Unlock()
	if membersErr != nil || !walked || now.Sub(at) > snapshotAge {
		return report("unavailable")
	}
	scopes := map[string]bool{}
	for _, c := range registry {
		scopes[c.scope] = true
	}
	snap, err := s.snapshot(ctx, r, b, slices.Sorted(maps.Keys(scopes)), now)
	if errors.Is(err, ErrDenied) {
		return report("denied")
	}
	if err != nil {
		return report("unavailable")
	}
	type check struct {
		person            int
		scope, key, login string
	}
	users := make([]siteUser, len(members))
	granted := make([]map[string]bool, len(members))
	var checks []check
	cached := 0
	for k, person := range members {
		u, ok := snap.verified(person)
		if !ok {
			continue
		}
		users[k], granted[k] = u, map[string]bool{}
		sum := sha256.Sum256([]byte(strings.Join(slices.Sorted(slices.Values(person.SIDs)), ",")))
		for scope := range scopes {
			grants := snap.scopes[scope]
			if grants == nil || grants.mask(person, u)&need != need {
				continue
			}
			key := strings.Join([]string{strconv.FormatInt(u.ID, 10), u.Login, r.ID, scope, grants.hash, hex.EncodeToString(sum[:])}, "\x00")
			s.mu.Lock()
			hit, found := s.cells[key]
			s.mu.Unlock()
			if found {
				granted[k][scope] = hit.mask&need == need
				cached++
				continue
			}
			checks = append(checks, check{k, scope, key, u.Login})
		}
	}
	var mu sync.Mutex
	var denied atomic.Bool
	answered := 0
	jobs := make(chan check)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for c := range jobs {
				if ctx.Err() != nil || denied.Load() {
					continue
				}
				mask, err := s.permissions(ctx, r, b, c.scope, c.login)
				if errors.Is(err, ErrDenied) {
					denied.Store(true)
				}
				if err != nil {
					continue
				}
				mu.Lock()
				granted[c.person][c.scope] = mask&need == need
				answered++
				mu.Unlock()
				s.mu.Lock()
				s.cells[c.key] = cell{mask: mask, at: now}
				s.mu.Unlock()
			}
		})
	}
	for _, c := range checks {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	slog.Info("site access", "root", r.ID, "users", len(members), "classes", len(registry), "checks", answered, "cached", cached, "unchecked", len(checks)-answered, "denied", denied.Load())
	if denied.Load() {
		return report("denied")
	}
	for id, c := range registry {
		for k, u := range users {
			if granted[k][c.scope] && (c.owner == "" || c.owner == strconv.FormatInt(u.ID, 10)) {
				readers[id] = append(readers[id], k)
			}
		}
	}
	return report("")
}

type siteFile struct {
	s      *sites
	ctx    context.Context
	r      root
	b      *baseline
	ref    pathRef
	path   string
	body   io.ReadCloser
	text   []byte
	offset int64
}

func (s *sites) open(ctx context.Context, r root, p string) (File, error) {
	s.mu.Lock()
	b := s.state(r).base
	s.mu.Unlock()
	ref, ok := b.ref(p)
	if !ok || ref.dup {
		return nil, ErrNotFound
	}
	return &siteFile{s: s, ctx: ctx, r: r, b: b, ref: ref, path: p}, nil
}

func (f *siteFile) Info() (FileInfo, error) {
	l, e := f.ref.list, f.ref.entry
	web := f.b.webs[l.Web].URL
	var list wireList
	if err := f.s.lists(f.ctx, f.r, web, l.ID, &list); err != nil {
		return FileInfo{}, err
	}
	if list.Hidden == nil || list.NoCrawl == nil || list.IrmEnabled == nil || list.IsCatalog == nil || *list.Hidden || *list.NoCrawl || *list.IrmEnabled || *list.IsCatalog {
		return FileInfo{}, ErrNotFound
	}
	changed := FileInfo{Size: -1}
	if list.Moderation == nil {
		return changed, nil
	}
	current := *l
	current.Moderation = *list.Moderation
	var raw json.RawMessage
	if err := f.s.get(f.ctx, f.r, http.MethodGet, apiPath(web, "web/lists(guid'"+l.ID+"')/items("+strconv.FormatInt(e.Item, 10)+")?"+rowQuery(l)), nil, &raw); err != nil {
		return FileInfo{}, err
	}
	var row wireRow
	if json.Unmarshal(raw, &row) != nil {
		return changed, nil
	}
	json.Unmarshal(raw, &row.values)
	now, published := describe(f.b, &current, row)
	if !published || now.Sig != e.Sig {
		return changed, nil
	}
	size, modified := now.Size, now.Modified
	if e.Name != "" {
		var props struct {
			Length           *num
			TimeLastModified string
		}
		if err := f.s.get(f.ctx, f.r, http.MethodGet, apiPath(web, fileByURL(strings.TrimSuffix(f.b.path, "/")+"/"+f.path)+"?$select=Length,TimeLastModified"), nil, &props); err != nil {
			return FileInfo{}, err
		}
		if props.Length == nil {
			return changed, nil
		}
		size, modified = int64(*props.Length), millis(props.TimeLastModified)
	} else if !l.Library {
		f.text = []byte(render(now.Title, l.Fields, row.values))
	}
	if size != e.Size || modified != e.Modified {
		return changed, nil
	}
	return FileInfo{ID: e.ID, Size: size, Modified: time.UnixMilli(modified)}, nil
}

func (f *siteFile) ReadAt(p []byte, off int64) (int, error) {
	if off != f.offset {
		return 0, errors.New("non-sequential read")
	}
	if f.body == nil {
		l, e := f.ref.list, f.ref.entry
		switch {
		case !l.Library && e.Name == "":
			f.body = io.NopCloser(bytes.NewReader(f.text))
		case l.Library && !guidPattern.MatchString(e.UniqueID):
			return 0, ErrNotFound
		default:
			target := fileByURL(strings.TrimSuffix(f.b.path, "/") + "/" + f.path)
			if l.Library {
				target = "web/GetFileById('" + e.UniqueID + "')"
			}
			resp, err := f.s.do(f.ctx, f.r, http.MethodGet, apiPath(f.b.webs[l.Web].URL, target+"/$value"), nil)
			if err != nil {
				return 0, err
			}
			f.body = resp.Body
		}
	}
	n, err := io.ReadFull(f.body, p)
	f.offset += int64(n)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = io.EOF
	}
	return n, err
}

func (f *siteFile) Close() error {
	if f.body != nil {
		return f.body.Close()
	}
	return nil
}

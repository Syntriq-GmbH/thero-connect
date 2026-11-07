package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	readHigh, readLow = 176, 138612833
	t0                = "2026-11-01T10:00:00Z"
	aliceSID, bobSID  = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	carolSID, daveSID = "S-1-5-21-1-2-3-1003", "S-1-5-21-1-2-3-1004"
	domainUsers       = "c:0+.w|s-1-5-21-1-2-3-513"
	teamGroup         = "S-1-5-21-1-2-3-2001"
)

type farmRow struct {
	id          int
	props       map[string]any
	content     string
	attachments []farmAttachment
}

type farmAttachment struct{ name, url, content string }

type farmList struct {
	id    string
	root  string
	web   *farmWeb
	props map[string]any
	rows  []*farmRow
	next  int

	fields []map[string]any
}

type farmWeb struct {
	id, url string
	parent  *farmWeb
	props   map[string]any
	gone    bool
}

type farmRequest struct {
	method, host, path, query, body string
	header                          http.Header
}

type farmFault struct {
	status int
	header map[string]string
	body   string
}

type farm struct {
	t        *testing.T
	mu       sync.Mutex
	server   *httptest.Server
	site     map[string]any
	number   int
	nextID   int
	webs     []*farmWeb
	lists    []*farmList
	users    []map[string]any
	groups   map[int][]map[string]any
	roles    map[string][]map[string]any
	guep     map[string][2]int64
	changes  []map[string]any
	noRead   bool
	fault    func(r *http.Request) *farmFault
	delay    func(r *http.Request) time.Duration
	onValue  func()
	control  func(step string) bool
	chunked  bool
	requests []farmRequest
}

func guid(kind, n int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", kind, n)
}

func grantTo(id int, login string, principalType int, high, low int64) map[string]any {
	return map[string]any{
		"Member":                 map[string]any{"Id": id, "LoginName": login, "PrincipalType": principalType},
		"RoleDefinitionBindings": []any{map[string]any{"BasePermissions": map[string]any{"High": strconv.FormatInt(high, 10), "Low": strconv.FormatInt(low, 10)}}},
	}
}

func newFarm(t *testing.T, address string) *farm {
	f := &farm{t: t, groups: map[int][]map[string]any{}, roles: map[string][]map[string]any{}, guep: map[string][2]int64{}}
	f.server = httptest.NewUnstartedServer(f)
	if address != "" {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		f.server.Listener.Close()
		f.server.Listener = listener
	}
	f.server.StartTLS()
	t.Cleanup(f.verify)
	t.Cleanup(f.server.Close)
	f.site = map[string]any{"Id": guid(1, 1), "Url": f.server.URL + "/sites/hr", "ServerRelativeUrl": "/sites/hr"}
	root := &farmWeb{id: guid(2, 0), url: "/sites/hr"}
	root.props = map[string]any{"Id": root.id, "ServerRelativeUrl": root.url, "HasUniqueRoleAssignments": true, "NoCrawl": false}
	f.webs = append(f.webs, root)
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	siteRoots = pool
	t.Cleanup(func() { siteRoots = nil })
	return f
}

func (f *farm) root() *farmWeb {
	return f.webs[0]
}

func (f *farm) update(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

func (f *farm) token() string {
	return fmt.Sprintf("1;1;%s;%d;%d", guid(1, 1), 638000000000000000+f.number, f.number)
}

func (f *farm) change(c map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.number++
	c["ChangeToken"] = map[string]any{"StringValue": f.token()}
	f.changes = append(f.changes, c)
}

func (f *farm) web(parent *farmWeb, name string, unique bool) *farmWeb {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	w := &farmWeb{id: guid(2, f.nextID), url: parent.url + "/" + name, parent: parent}
	w.props = map[string]any{"Id": w.id, "ServerRelativeUrl": w.url, "HasUniqueRoleAssignments": unique, "NoCrawl": false}
	f.webs = append(f.webs, w)
	return w
}

func (f *farm) list(web *farmWeb, name string, baseType int) *farmList {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	l := &farmList{id: guid(3, f.nextID), root: web.url + "/" + name, web: web}
	l.props = map[string]any{
		"Id": l.id, "BaseType": baseType, "Hidden": false, "IsCatalog": false, "NoCrawl": false, "IrmEnabled": false, "EnableModeration": false,
		"ReadSecurity": 1, "HasUniqueRoleAssignments": false, "DefaultDisplayFormUrl": l.root + "/DispForm.aspx", "RootFolder": map[string]any{"ServerRelativeUrl": l.root},
	}
	f.lists = append(f.lists, l)
	return l
}

func (f *farm) row(l *farmList, props map[string]any) *farmRow {
	f.nextID++
	l.next++
	row := &farmRow{id: l.next}
	row.props = map[string]any{
		"Id": l.next, "UniqueId": guid(4, f.nextID), "FSObjType": 0, "HasUniqueRoleAssignments": false, "Created": t0, "Modified": t0, "AuthorId": 11,
		"OData__UIVersion": 512, "OData__Level": 1, "OData__ModerationStatus": 0,
	}
	maps.Copy(row.props, props)
	l.rows = append(l.rows, row)
	return row
}

func (f *farm) file(l *farmList, name, content string) *farmRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	row := f.row(l, map[string]any{"FileRef": l.root + "/" + name, "File": map[string]any{"Length": strconv.Itoa(len(content)), "TimeLastModified": t0}})
	row.content = content
	return row
}

func (f *farm) folder(l *farmList, name string) *farmRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.row(l, map[string]any{"FileRef": l.root + "/" + name, "FSObjType": 1})
}

func (f *farm) item(l *farmList, title string, values map[string]any) *farmRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	row := f.row(l, map[string]any{"Title": title, "Attachments": false})
	row.props["FileRef"] = fmt.Sprintf("%s/%d_.000", l.root, row.id)
	maps.Copy(row.props, values)
	return row
}

func (f *farm) attach(l *farmList, row *farmRow, name, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	row.props["Attachments"] = true
	row.attachments = append(row.attachments, farmAttachment{name: name, url: fmt.Sprintf("%s/Attachments/%d/%s", l.root, row.id, name), content: content})
}

func (f *farm) edit(row *farmRow, content string, version, level int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	stamp := time.Date(2026, 11, 2, 0, 0, f.nextID, 0, time.UTC).Format(time.RFC3339)
	row.content = content
	row.props["OData__UIVersion"], row.props["OData__Level"], row.props["Modified"] = version, level, stamp
	if _, ok := row.props["File"]; ok {
		row.props["File"] = map[string]any{"Length": strconv.Itoa(len(content)), "TimeLastModified": stamp}
	}
}

func (f *farm) person(src *fakeSource, id int, name, sid string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	login := `i:0#.w|corp\` + name
	f.users = append(f.users, map[string]any{"Id": id, "LoginName": login, "IsSiteAdmin": false, "UserId": map[string]any{"NameId": strings.ToLower(sid), "NameIdIssuer": "urn:office:idp:activedirectory"}})
	sids := []string{strings.ToLower(sid), "s-1-5-21-1-2-3-513"}
	for _, group := range groups {
		sids = append(sids, strings.ToLower(group))
	}
	if src.memberList == nil {
		src.memberList = map[string]Member{}
	}
	src.memberList[sid] = Member{Login: login, SID: strings.ToLower(sid), SIDs: sids}
}

func (f *farm) count(part string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, req := range f.requests {
		if strings.Contains(req.method+" "+req.path+"?"+req.query, part) {
			n++
		}
	}
	return n
}

func (f *farm) verify() {
	f.mu.Lock()
	defer f.mu.Unlock()
	host := strings.TrimPrefix(f.server.URL, "https://")
	for _, req := range f.requests {
		known := false
		for _, web := range f.webs {
			known = known || strings.HasPrefix(req.path, strings.TrimSuffix(web.url, "/")+"/_api/")
		}
		post := req.method == http.MethodPost && (req.path == "/sites/hr/_api/contextinfo" || req.path == "/sites/hr/_api/site/getchanges")
		if req.host != host || req.header.Get("X-HTTP-Method") != "" || !(req.method == http.MethodGet && known || post) {
			f.t.Errorf("request outside the allow list: %s %s%s", req.method, req.host, req.path)
		}
	}
}

func (f *farm) agent(src *fakeSource) *agent {
	cfg := config{Roots: []root{{ID: "intranet", URL: f.server.URL + "/sites/hr", SPN: "HTTP/127.0.0.1"}}, Limits: limits{MaxFileMB: 20, MaxGBPerDay: 50, MaxMbit: 100000}}
	a, err := newAgent(f.t.TempDir(), cfg, src)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		a.sites.mu.Lock()
		defer a.sites.mu.Unlock()
		for _, st := range a.sites.roots {
			for _, w := range []*spWalk{st.full, st.changes} {
				if w != nil {
					w.cancel()
				}
			}
		}
	})
	return a
}

var (
	listRoute  = regexp.MustCompile(`^web/lists\(guid'([0-9a-f-]+)'\)(/fields|/items|/items\((\d+)\))?$`)
	scopeRoute = regexp.MustCompile(`^web(?:/lists\(guid'([0-9a-f-]+)'\)(?:/items\((\d+)\))?)?/(roleassignments|getusereffectivepermissions\(@u\))$`)
	groupRoute = regexp.MustCompile(`^web/sitegroups/getbyid\((\d+)\)/users$`)
	byIDRoute  = regexp.MustCompile(`^web/GetFileById\('([0-9a-f-]+)'\)/\$value$`)
	byURLRoute = regexp.MustCompile(`^web/GetFileByServerRelativeUrl\('(.*)'\)(/\$value)?$`)
)

func (f *farm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if step, ok := strings.CutPrefix(r.URL.Path, "/_control/"); ok && r.Method == http.MethodPost {
		if f.control == nil || !f.control(step) {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, farmRequest{method: r.Method, host: r.Host, path: r.URL.Path, query: r.URL.RawQuery, body: string(body), header: r.Header.Clone()})
	delay := f.delay
	f.mu.Unlock()
	if delay != nil {
		time.Sleep(delay(r))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Negotiate "+base64.StdEncoding.EncodeToString([]byte("HTTP/127.0.0.1")) {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.fault != nil {
		if fault := f.fault(r); fault != nil {
			for name, value := range fault.header {
				w.Header().Set(name, value)
			}
			w.WriteHeader(fault.status)
			io.WriteString(w, fault.body)
			return
		}
	}
	var web *farmWeb
	for _, candidate := range f.webs {
		if strings.HasPrefix(r.URL.Path, candidate.url+"/_api/") && (web == nil || len(candidate.url) > len(web.url)) {
			web = candidate
		}
	}
	if web == nil || web.gone {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, web.url+"/_api/")
	query := r.URL.Query()
	send := func(value any) {
		json.NewEncoder(w).Encode(value)
	}
	values := func(items any) { send(map[string]any{"value": items}) }
	switch {
	case rest == "site" && web == f.root():
		site := maps.Clone(f.site)
		if _, ok := site["CurrentChangeToken"]; !ok {
			site["CurrentChangeToken"] = map[string]any{"StringValue": f.token()}
		}
		send(site)
	case rest == "contextinfo" && r.Method == http.MethodPost && web == f.root():
		send(map[string]any{"FormDigestValue": "digest-1", "FormDigestTimeoutSeconds": 1800})
	case rest == "site/getchanges" && r.Method == http.MethodPost && web == f.root():
		f.getChanges(w, r, body)
	case rest == "web":
		send(web.props)
	case rest == "web/webs":
		var children []any
		for _, child := range f.webs {
			if child.parent == web && !child.gone {
				children = append(children, child.props)
			}
		}
		values(children)
	case rest == "web/lists":
		if f.noRead && strings.Contains(query.Get("$select"), "ReadSecurity") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var lists []any
		for _, l := range f.lists {
			if l.web == web {
				lists = append(lists, f.listJSON(l))
			}
		}
		values(lists)
	case rest == "web/siteusers":
		values(f.users)
	case listRoute.MatchString(rest):
		f.listRequest(w, web, listRoute.FindStringSubmatch(rest), query)
	case scopeRoute.MatchString(rest):
		match := scopeRoute.FindStringSubmatch(rest)
		key := "w:" + web.id
		if match[1] != "" {
			key = "l:" + match[1]
		}
		if match[2] != "" {
			key = "i:" + match[1] + ":" + match[2]
		}
		if match[3] == "roleassignments" {
			values(append([]map[string]any{}, f.roles[key]...))
			return
		}
		login := strings.ReplaceAll(strings.Trim(query.Get("@u"), "'"), "''", "'")
		mask, ok := f.guep[login+"|"+key]
		if !ok {
			mask = [2]int64{readHigh, readLow}
		}
		send(map[string]any{"High": strconv.FormatInt(mask[0], 10), "Low": strconv.FormatInt(mask[1], 10)})
	case groupRoute.MatchString(rest):
		id, _ := strconv.Atoi(groupRoute.FindStringSubmatch(rest)[1])
		members, ok := f.groups[id]
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		values(members)
	case byIDRoute.MatchString(rest):
		unique := byIDRoute.FindStringSubmatch(rest)[1]
		for _, l := range f.lists {
			for _, row := range l.rows {
				if row.props["UniqueId"] == unique && l.web == web {
					f.value(w, row.content)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case byURLRoute.MatchString(rest):
		match := byURLRoute.FindStringSubmatch(rest)
		target := strings.ReplaceAll(match[1], "''", "'")
		for _, l := range f.lists {
			for _, row := range l.rows {
				for _, att := range row.attachments {
					if att.url != target || l.web != web {
						continue
					}
					if match[2] != "" {
						f.value(w, att.content)
						return
					}
					send(map[string]any{"Length": strconv.Itoa(len(att.content)), "TimeLastModified": t0})
					return
				}
			}
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *farm) value(w http.ResponseWriter, content string) {
	if f.onValue != nil {
		f.onValue()
		f.onValue = nil
	}
	if !f.chunked {
		io.WriteString(w, content)
		return
	}
	for start := 0; start < len(content); start += 1000 {
		io.WriteString(w, content[start:min(start+1000, len(content))])
		w.(http.Flusher).Flush()
	}
}

func (f *farm) listJSON(l *farmList) map[string]any {
	out := maps.Clone(l.props)
	if f.noRead {
		delete(out, "ReadSecurity")
	}
	return out
}

func (f *farm) rowJSON(l *farmList, row *farmRow) map[string]any {
	out := maps.Clone(row.props)
	if _, ok := out["AttachmentFiles"]; !ok && l.props["BaseType"] != 1 {
		files := []any{}
		for _, att := range row.attachments {
			files = append(files, map[string]any{"FileName": att.name, "ServerRelativeUrl": att.url})
		}
		out["AttachmentFiles"] = files
	}
	return out
}

func (f *farm) listRequest(w http.ResponseWriter, web *farmWeb, match []string, query url.Values) {
	var l *farmList
	for _, candidate := range f.lists {
		if candidate.id == match[1] && candidate.web == web {
			l = candidate
		}
	}
	if l == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	send := func(value any) { json.NewEncoder(w).Encode(value) }
	switch {
	case match[2] == "":
		if f.noRead && strings.Contains(query.Get("$select"), "ReadSecurity") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		send(f.listJSON(l))
	case match[2] == "/fields":
		send(map[string]any{"value": append([]map[string]any{}, l.fields...)})
	case match[3] != "":
		id, _ := strconv.Atoi(match[3])
		for _, row := range l.rows {
			if row.id == id {
				send(f.rowJSON(l, row))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		if query.Get("$orderby") != "Id" {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":"Microsoft.SharePoint.SPQueryThrottledException"}`)
			return
		}
		top, _ := strconv.Atoi(query.Get("$top"))
		after := 0
		if token := query.Get("$skiptoken"); token != "" {
			after, _ = strconv.Atoi(strings.TrimPrefix(token, "Paged=TRUE&p_ID="))
		}
		rows := slices.Clone(l.rows)
		slices.SortFunc(rows, func(a, b *farmRow) int { return a.id - b.id })
		page := []any{}
		for _, row := range rows {
			if row.id > after && len(page) < top {
				page = append(page, f.rowJSON(l, row))
			}
		}
		send(map[string]any{"value": page})
	}
}

func (f *farm) getChanges(w http.ResponseWriter, r *http.Request, body []byte) {
	if r.Header.Get("X-RequestDigest") != "digest-1" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var request struct {
		Query struct {
			ChangeTokenStart struct{ StringValue string }
		} `json:"query"`
	}
	json.Unmarshal(body, &request)
	fields := strings.Split(request.Query.ChangeTokenStart.StringValue, ";")
	if len(fields) != 5 || fields[2] != guid(1, 1) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":"invalid change token"}`)
		return
	}
	start, _ := strconv.Atoi(fields[4])
	page := []any{}
	for _, c := range f.changes {
		number, _ := strconv.Atoi(strings.Split(c["ChangeToken"].(map[string]any)["StringValue"].(string), ";")[4])
		if number > start && len(page) < 1000 {
			page = append(page, c)
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"value": page})
}

type sitePage struct {
	entries    map[string]pageEntry
	deleted    []string
	incomplete []string
	code       string
	pages      []pageMessage
}

func walkSite(t *testing.T, a *agent, changes bool) sitePage {
	t.Helper()
	result := sitePage{entries: map[string]pageEntry{}}
	cursor := ""
	for range 100000 {
		reply := a.walk(message{Type: "walk", ID: 1, Root: "intranet", Cursor: cursor, Changes: changes})
		if refusal, ok := reply.(errorMessage); ok {
			result.code = refusal.Code
			return result
		}
		page := reply.(pageMessage)
		result.pages = append(result.pages, page)
		for _, e := range page.Entries {
			if _, seen := result.entries[e.Path]; seen {
				t.Fatalf("path %s sent twice", e.Path)
			}
			result.entries[e.Path] = e
		}
		result.deleted = append(result.deleted, page.Deleted...)
		result.incomplete = append(result.incomplete, page.Incomplete...)
		for _, prefix := range page.Incomplete {
			if _, err := validPath(prefix); err != nil {
				t.Errorf("incomplete %q is not a valid path", prefix)
			}
		}
		if page.Cursor == "" {
			return result
		}
		cursor = page.Cursor
	}
	t.Fatal("walk did not end")
	return result
}

func classOfEntry(e pageEntry) string {
	if e.Class == nil {
		return "null"
	}
	return *e.Class
}

func readersByPath(t *testing.T, a *agent, sids []string, entries map[string]pageEntry) (map[string][]int, []rootError) {
	t.Helper()
	rights := a.access(message{Type: "access", ID: 2, SIDs: sids}).(rightsMessage)
	byClass := map[string][]int{}
	for _, c := range rights.Classes {
		byClass[c.Class] = c.Readers
	}
	readers := map[string][]int{}
	for p, e := range entries {
		if e.Class != nil {
			readers[p] = byClass[*e.Class]
		}
	}
	return readers, rights.Errors
}

func readSite(a *agent, e pageEntry) (string, string) {
	var data []byte
	reply := a.read(context.Background(), message{Type: "read", ID: 3, Root: "intranet", Path: e.Path, File: e.File, Size: e.Size, Modified: e.Modified}, openWindow(), func(frame []byte) error {
		data = append(data, frame[4:]...)
		return nil
	})
	return string(data), codeOfReply(reply)
}

func basicFarm(t *testing.T) (*farm, *fakeSource, *farmList) {
	f := newFarm(t, "")
	src := newFakeSource()
	f.person(src, 11, "alice", aliceSID, teamGroup)
	f.person(src, 12, "bob", bobSID)
	f.roles["w:"+f.root().id] = []map[string]any{grantTo(3, domainUsers, 4, readHigh, readLow)}
	docs := f.list(f.root(), "Shared Documents", 1)
	return f, src, docs
}

func TestClaims(t *testing.T) {
	person := Member{Login: `i:0#.w|corp\alice`, SID: "s-1-5-21-1-2-3-1001", SIDs: []string{"s-1-5-21-1-2-3-1001", "s-1-5-21-1-2-3-513", "s-1-5-21-1-2-3-2001", "s-1-5-32-545", "s-1-5-21-9-9-9-2001"}}
	u := siteUser{ID: 11, Login: `i:0#.w|corp\alice`, SID: "s-1-5-21-1-2-3-1001"}
	cases := []struct {
		id    int64
		login string
		kind  int64
		want  bool
	}{
		{11, `i:0#.w|corp\alice`, 1, true},
		{12, `i:0#.w|corp\alice`, 1, false},
		{11, `i:0#.w|corp\alice`, -1, false},
		{5, "c:0+.w|s-1-5-21-1-2-3-2001", 4, true},
		{5, "C:0+.W|S-1-5-21-1-2-3-2001", 4, true},
		{5, "c:0+.w|s-1-5-21-1-2-3-9999", 4, false},
		{5, "c:0+.w|s-1-5-21-1-2-3-2001", 1, false},
		{5, "c:0(.s|true", 4, true},
		{5, "c:0!.s|windows", 1, true},
		{5, "c:0+.w|s-1-1-0", 4, true},
		{5, "C:0+.W|S-1-5-11", 4, true},
		{5, "c:0(.s|true", -1, false},
		{5, "c:0(.s|true", 8, false},
		{5, "i:05.t|adfs|alice@corp.example", 1, false},
		{5, "i:0#.f|membership|alice", 1, false},
		{5, "c:0-.f|rolemanager|staff", 4, false},
		{5, "c:0+.w|s-1-5-32-545", 4, false},
		{5, "c:0+.w|s-1-5-21-9-9-9-2001", 4, false},
		{5, "c:0+.w|s-1-5-21-1-2-3-2001", 2, false},
		{5, "", 4, false},
	}
	for _, c := range cases {
		grants := invert([]assignment{{Member: principal{ID: c.id, Login: c.login, Type: c.kind}, Mask: 1}})
		if got := grants.mask(person, u) == 1; got != c.want {
			t.Errorf("%d %q type %d matched %v", c.id, c.login, c.kind, got)
		}
	}
	group := invert([]assignment{{Member: principal{ID: 50, Login: "Owners", Type: 8}, Members: []principal{{ID: 12, Login: `i:0#.w|corp\bob`, Type: 1}, {ID: 11, Login: `i:0#.w|corp\alice`, Type: 1}}, Mask: 3}})
	if group.mask(person, u) != 3 || group.mask(person, siteUser{ID: 13}) != 0 {
		t.Fatal("SharePoint group members match by row id")
	}
	nested := invert([]assignment{
		{Member: principal{ID: 50, Login: "Owners", Type: 8}, Members: []principal{{ID: 60, Login: "Nested", Type: 8}, {ID: 61, Login: "c:0(.s|true", Type: -1}, {ID: 5, Login: "c:0+.w|s-1-5-21-1-2-3-2001", Type: 4}}, Mask: 4},
		{Member: principal{ID: 11, Login: `i:0#.w|corp\alice`, Type: 1}, Mask: 1},
		{Member: principal{ID: 7, Login: "c:0!.s|windows", Type: 4}, Mask: 16},
		{Member: principal{ID: 11, Login: `i:0#.w|corp\alice`, Type: 1}, Members: []principal{{ID: 12, Type: 1}}, Mask: 32},
	})
	if got := nested.mask(person, u); got != 4|1|16|32 {
		t.Fatalf("combined mask %b", got)
	}
	if got := nested.mask(Member{SIDs: []string{"s-1-5-21-1-2-3-1002"}}, siteUser{ID: 12}); got != 16 {
		t.Fatalf("members of a non-group assignment matched: %b", got)
	}
}

func TestMasks(t *testing.T) {
	cases := []struct {
		name      string
		high, low uint64
		want      bool
	}{
		{"Read", 176, 138612833, true},
		{"Contribute", 432, 1011030767, true},
		{"Limited Access", 48, 134287360, false},
		{"View Only", 176, 138612801, false},
		{"custom without ViewFormPages", 176, 138608737, false},
		{"Full Control", 2147483647, 4294967295, true},
	}
	u := siteUser{ID: 11}
	for _, c := range cases {
		grants := invert([]assignment{{Member: principal{ID: 11, Type: 1}, Mask: c.high<<32 | c.low}})
		if got := grants.mask(Member{}, u)&need == need; got != c.want {
			t.Errorf("%s gives %v", c.name, got)
		}
	}
	if invert(nil).mask(Member{}, siteUser{ID: 11, Admin: true})&need != need {
		t.Error("site collection administrator lacks the need")
	}
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "alpha")
	f.update(func() {
		f.roles["w:"+f.root().id] = []map[string]any{grantTo(11, `i:0#.w|corp\alice`, 1, 176, 138612801), grantTo(12, `i:0#.w|corp\bob`, 1, 48, 134287360)}
		f.users[1]["IsSiteAdmin"] = true
	})
	a := f.agent(src)
	walk := walkSite(t, a, false)
	readers, errs := readersByPath(t, a, []string{aliceSID, bobSID}, walk.entries)
	if !slices.Equal(readers["Shared Documents/a.txt"], []int{1}) || len(errs) != 0 {
		t.Fatalf("readers %v errors %v", readers, errs)
	}
}

func TestVerifiedRow(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "alpha")
	f.person(src, 13, "carol", carolSID)
	f.person(src, 14, "dave", daveSID)
	f.update(func() {
		f.users[2]["UserId"] = map[string]any{"NameId": "s-1-5-21-1-2-3-7777"}
		delete(f.users[3], "UserId")
	})
	a := f.agent(src)
	walk := walkSite(t, a, false)
	readers, _ := readersByPath(t, a, []string{aliceSID, bobSID, carolSID, daveSID}, walk.entries)
	if !slices.Equal(readers["Shared Documents/a.txt"], []int{0, 1}) {
		t.Fatalf("readers %v", readers)
	}
	if f.count("carol") != 0 || f.count("dave") != 0 || f.count("alice") != 1 {
		t.Fatalf("permission checks for unverified rows: carol %d dave %d alice %d", f.count("carol"), f.count("dave"), f.count("alice"))
	}
}

func TestReaders(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.person(src, 13, "carol", carolSID)
	src.memberList["S-1-5-21-1-2-3-1005"] = Member{Login: `i:0#.w|corp\erin`, SID: "s-1-5-21-1-2-3-1005", SIDs: []string{"s-1-5-21-1-2-3-1005", "s-1-5-21-1-2-3-513"}}
	files := map[string]*farmRow{}
	for _, name := range []string{"spno", "stale", "group", "hidden", "gone", "notype", "flaky", "strings"} {
		files[name] = f.file(docs, name+".txt", name)
		f.update(func() { files[name].props["HasUniqueRoleAssignments"] = true })
	}
	scope := func(name string) string { return fmt.Sprintf("i:%s:%d", docs.id, files[name].id) }
	sub := f.web(f.root(), "teams", true)
	teamDocs := f.list(sub, "Docs", 1)
	f.file(teamDocs, "t.txt", "team")
	f.update(func() {
		f.roles[scope("spno")] = []map[string]any{grantTo(11, `i:0#.w|corp\alice`, 1, readHigh, readLow), grantTo(12, `i:0#.w|corp\bob`, 1, readHigh, readLow)}
		f.guep[`i:0#.w|corp\alice|`+scope("spno")] = [2]int64{48, 134287360}
		f.roles[scope("stale")] = []map[string]any{grantTo(30, "c:0+.w|"+strings.ToLower(teamGroup), 4, readHigh, readLow)}
		f.roles[scope("group")] = []map[string]any{grantTo(50, "Team Members", 8, readHigh, readLow)}
		f.groups[50] = []map[string]any{{"Id": 11, "LoginName": `i:0#.w|corp\alice`, "PrincipalType": 1}, {"Id": 99, "LoginName": `i:0#.w|corp\bob`, "PrincipalType": 1}, {"Id": 12, "LoginName": `i:0#.w|corp\bob`}}
		f.roles[scope("hidden")] = []map[string]any{grantTo(51, "Secret Members", 8, readHigh, readLow)}
		f.roles[scope("notype")] = []map[string]any{grantTo(11, `i:0#.w|corp\alice`, 1, readHigh, readLow), {"Member": map[string]any{"Id": 12, "LoginName": `i:0#.w|corp\bob`}, "RoleDefinitionBindings": []any{map[string]any{"BasePermissions": map[string]any{"High": "176", "Low": "138612833"}}}}}
		f.roles[scope("flaky")] = []map[string]any{grantTo(3, domainUsers, 4, readHigh, readLow)}
		f.roles[scope("strings")] = []map[string]any{grantTo(3, domainUsers, 4, readHigh, readLow)}
		f.roles["w:"+sub.id] = []map[string]any{grantTo(3, domainUsers, 4, readHigh, readLow)}
		f.fault = func(r *http.Request) *farmFault {
			switch {
			case strings.Contains(r.URL.Path, fmt.Sprintf("/items(%d)/roleassignments", files["gone"].id)):
				return &farmFault{status: http.StatusNotFound}
			case strings.Contains(r.URL.Path, fmt.Sprintf("/items(%d)/getusereffectivepermissions", files["flaky"].id)) && strings.Contains(r.URL.RawQuery, "bob"):
				return &farmFault{status: http.StatusInternalServerError}
			}
			return nil
		}
	})
	a := f.agent(src)
	walk := walkSite(t, a, false)
	f.update(func() { sub.props["Id"] = guid(2, 999) })
	sids := []string{aliceSID, bobSID, carolSID, "S-1-5-21-1-2-3-1005"}
	readers, errs := readersByPath(t, a, sids, walk.entries)
	want := map[string][]int{
		"Shared Documents/spno.txt": {1}, "Shared Documents/stale.txt": {0}, "Shared Documents/group.txt": {0}, "Shared Documents/hidden.txt": {},
		"Shared Documents/gone.txt": {}, "Shared Documents/notype.txt": {}, "Shared Documents/flaky.txt": {0, 2}, "Shared Documents/strings.txt": {0, 1, 2},
		"teams/Docs/t.txt": {},
	}
	for p, expected := range want {
		if !slices.Equal(readers[p], expected) {
			t.Errorf("%s readers %v, want %v", p, readers[p], expected)
		}
	}
	if len(errs) != 0 {
		t.Fatalf("errors %v", errs)
	}
	if f.count("getusereffectivepermissions(@u)?@u='i%3A0%23.w%7Ccorp%5Cerin'") != 0 {
		t.Fatal("a person without a site user row was checked")
	}
	f.update(func() {
		f.fault = func(r *http.Request) *farmFault {
			if strings.Contains(r.URL.Path, "getusereffectivepermissions") {
				return &farmFault{status: http.StatusForbidden}
			}
			return nil
		}
	})
	a.sites.cells = map[string]cell{}
	readers, errs = readersByPath(t, a, sids, walk.entries)
	if fmt.Sprint(errs) != "[{intranet denied}]" || slices.ContainsFunc(slices.Collect(maps.Values(readers)), func(r []int) bool { return len(r) > 0 }) {
		t.Fatalf("denied check gave %v %v", readers, errs)
	}
}

func TestAccessDeadline(t *testing.T) {
	f, src, docs := basicFarm(t)
	for i := range 12 {
		row := f.file(docs, fmt.Sprintf("f%02d.txt", i), "x")
		f.update(func() {
			row.props["HasUniqueRoleAssignments"] = true
			f.roles[fmt.Sprintf("i:%s:%d", docs.id, row.id)] = []map[string]any{grantTo(3, domainUsers, 4, readHigh, readLow)}
		})
	}
	a := f.agent(src)
	walk := walkSite(t, a, false)
	previous := accessTime
	accessTime = 600 * time.Millisecond
	t.Cleanup(func() { accessTime = previous })
	f.update(func() {
		f.delay = func(r *http.Request) time.Duration {
			if strings.Contains(r.URL.Path, "getusereffectivepermissions") {
				return 150 * time.Millisecond
			}
			return 0
		}
	})
	count := func(readers map[string][]int) int {
		n := 0
		for _, r := range readers {
			n += len(r)
		}
		return n
	}
	first, _ := readersByPath(t, a, []string{aliceSID, bobSID}, walk.entries)
	if count(first) == 0 || count(first) >= 24 {
		t.Fatalf("first access granted %d cells", count(first))
	}
	checks := f.count("getusereffectivepermissions")
	complete := 0
	for range 20 {
		readers, _ := readersByPath(t, a, []string{aliceSID, bobSID}, walk.entries)
		if complete = count(readers); complete == 24 {
			break
		}
	}
	if complete != 24 || f.count("getusereffectivepermissions") <= checks {
		t.Fatalf("cache did not fill: %d cells, %d checks", complete, f.count("getusereffectivepermissions"))
	}
	settled := f.count("getusereffectivepermissions")
	readersByPath(t, a, []string{aliceSID, bobSID}, walk.entries)
	if f.count("getusereffectivepermissions") != settled {
		t.Fatal("cached cells were checked again")
	}
	accessTime = 30 * time.Second
	a.now = func() time.Time { return time.Now().Add(cellLife + time.Second) }
	readers, _ := readersByPath(t, a, []string{aliceSID, bobSID}, walk.entries)
	if count(readers) != 24 || f.count("getusereffectivepermissions") != settled+24 {
		t.Fatalf("expired cells were not checked again: %d checks", f.count("getusereffectivepermissions")-settled)
	}
}

func TestReadOwnItems(t *testing.T) {
	f, src, _ := basicFarm(t)
	f.person(src, 13, "carol", carolSID)
	f.update(func() { f.users[2]["IsSiteAdmin"] = true })
	requests := f.list(f.root(), "Lists/Requests", 100)
	f.update(func() { requests.props["ReadSecurity"] = 2 })
	f.item(requests, "Alice asks", map[string]any{"AuthorId": 11})
	f.item(requests, "Bob asks", map[string]any{"AuthorId": 12})
	orphan := f.item(requests, "Nobody asks", nil)
	f.update(func() { delete(orphan.props, "AuthorId") })
	open := f.list(f.root(), "Lists/Open", 100)
	f.item(open, "Open item", map[string]any{"AuthorId": 11})
	a := f.agent(src)
	walk := walkSite(t, a, false)
	readers, _ := readersByPath(t, a, []string{aliceSID, bobSID, carolSID}, walk.entries)
	if !slices.Equal(readers["Lists/Requests/1_.000.md"], []int{0}) || !slices.Equal(readers["Lists/Requests/2_.000.md"], []int{1}) || !slices.Equal(readers["Lists/Open/1_.000.md"], []int{0, 1, 2}) {
		t.Fatalf("readers %v", readers)
	}
	if walk.entries["Lists/Requests/3_.000.md"].Class != nil {
		t.Fatal("item without author has a class")
	}
	f.update(func() { f.noRead = true })
	selected := f.count("ReadSecurity")
	walk = walkSite(t, a, false)
	readers, _ = readersByPath(t, a, []string{aliceSID, bobSID, carolSID}, walk.entries)
	if !slices.Equal(readers["Lists/Open/1_.000.md"], []int{0}) || f.count("ReadSecurity") != selected+1 {
		t.Fatalf("lists without ReadSecurity are not owner only: %v", readers)
	}
	walkSite(t, a, false)
	if _, code := readSite(a, walk.entries["Lists/Open/1_.000.md"]); code != "done" || f.count("ReadSecurity") != selected+1 {
		t.Fatalf("ReadSecurity asked again after a 400: read %s, %d requests", code, f.count("ReadSecurity")-selected)
	}
}

func TestVersionRule(t *testing.T) {
	n := func(v int64) *num { value := num(v); return &value }
	yes, no := true, false
	cases := []struct {
		version, level, status *num
		moderation             bool
		want                   bool
	}{
		{n(512), n(1), nil, false, true},
		{n(1024), n(1), n(0), true, true},
		{n(0), n(1), nil, false, false},
		{n(513), n(2), nil, false, false},
		{n(513), n(1), nil, false, false},
		{n(1024), n(2), n(0), true, false},
		{n(1024), n(1), n(2), true, false},
		{n(1024), n(1), n(1), true, false},
		{n(1024), n(1), n(4), true, false},
		{n(1024), n(1), nil, true, false},
		{nil, n(1), nil, false, false},
		{n(512), nil, nil, false, false},
	}
	for i, c := range cases {
		row := wireRow{ID: n(1), UniqueID: guid(4, 1), FSObjType: n(0), Unique: &no, UIVersion: c.version, Level: c.level, Status: c.status}
		if _, got := describe(&baseline{}, &spList{Moderation: c.moderation}, row); got != c.want {
			t.Errorf("case %d published %v", i, got)
		}
	}
	missing := wireRow{ID: n(1), FSObjType: n(0), UIVersion: n(512), Level: n(1)}
	if _, ok := describe(&baseline{}, &spList{}, missing); ok {
		t.Error("row without HasUniqueRoleAssignments is published")
	}
	missing = wireRow{ID: n(1), Unique: &yes, UIVersion: n(512), Level: n(1)}
	if _, ok := describe(&baseline{}, &spList{}, missing); ok {
		t.Error("row without FSObjType is published")
	}
	f, src, docs := basicFarm(t)
	draft := f.file(docs, "draft.txt", "published")
	f.edit(draft, "draft on top", 513, 2)
	tickets := f.list(f.root(), "Lists/Tickets", 100)
	pending := f.item(tickets, "Pending", nil)
	f.attach(tickets, pending, "a.txt", "attached")
	f.update(func() { pending.props["OData__UIVersion"] = 1 })
	moderated := f.list(f.root(), "Lists/Moderated", 100)
	f.update(func() { delete(moderated.props, "EnableModeration") })
	f.item(moderated, "Unknown", nil)
	walk := walkSite(t, f.agent(src), false)
	if e, ok := walk.entries["Shared Documents/draft.txt"]; !ok || e.Class != nil {
		t.Fatalf("draft on top: %+v", e)
	}
	if e, ok := walk.entries["Lists/Tickets/1_.000.md"]; !ok || e.Class != nil {
		t.Fatalf("draft item: %+v", e)
	}
	if _, ok := walk.entries["Lists/Tickets/Attachments/1/a.txt"]; ok {
		t.Fatal("attachment of a draft item listed")
	}
	if !slices.Equal(walk.incomplete, []string{"Lists/Moderated"}) || len(walk.entries) != 2 {
		t.Fatalf("incomplete %v entries %d", walk.incomplete, len(walk.entries))
	}
}

func TestScopeChain(t *testing.T) {
	f, src, docs := basicFarm(t)
	itemRow := f.file(docs, "item.txt", "x")
	file := f.file(docs, "A/B/nested.txt", "x")
	folderA := f.folder(docs, "A")
	folderB := f.folder(docs, "A/B")
	f.file(docs, "web.txt", "x")
	noFlag := f.file(docs, "noflag.txt", "x")
	orphan := f.file(docs, "Missing/orphan.txt", "x")
	listed := f.list(f.root(), "Unique", 1)
	f.file(listed, "list.txt", "x")
	sub := f.web(f.root(), "sub", false)
	inner := f.web(sub, "inner", true)
	subDocs := f.list(sub, "Docs", 1)
	innerDocs := f.list(inner, "Docs", 1)
	f.file(subDocs, "s.txt", "x")
	f.file(innerDocs, "i.txt", "x")
	brokenFolder := f.file(docs, "C/broken.txt", "x")
	folderC := f.folder(docs, "C")
	f.update(func() {
		itemRow.props["HasUniqueRoleAssignments"] = true
		folderA.props["HasUniqueRoleAssignments"] = true
		delete(noFlag.props, "HasUniqueRoleAssignments")
		listed.props["HasUniqueRoleAssignments"] = true
		delete(folderC.props, "HasUniqueRoleAssignments")
	})
	a := f.agent(src)
	walk := walkSite(t, a, false)
	site := guid(1, 1)
	want := map[string]string{
		"Shared Documents/item.txt":           spClass("intranet", site, fmt.Sprintf("i:%s:%d", docs.id, itemRow.id), ""),
		"Shared Documents/A/B/nested.txt":     spClass("intranet", site, fmt.Sprintf("i:%s:%d", docs.id, folderA.id), ""),
		"Shared Documents/web.txt":            spClass("intranet", site, "w:"+f.root().id, ""),
		"Unique/list.txt":                     spClass("intranet", site, "l:"+listed.id, ""),
		"sub/Docs/s.txt":                      spClass("intranet", site, "w:"+f.root().id, ""),
		"sub/inner/Docs/i.txt":                spClass("intranet", site, "w:"+inner.id, ""),
		"Shared Documents/noflag.txt":         "null",
		"Shared Documents/Missing/orphan.txt": "null",
		"Shared Documents/C/broken.txt":       "null",
	}
	for p, class := range want {
		if got := classOfEntry(walk.entries[p]); got != class {
			t.Errorf("%s class %s, want %s", p, got, class)
		}
	}
	if folderB.id < file.id || orphan.id == 0 || brokenFolder.id == 0 || len(walk.entries) != len(want) {
		t.Fatalf("entries %d", len(walk.entries))
	}
}

func TestSiteWalkPaging(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.update(func() {
		for i := range 12001 {
			f.nextID++
			docs.next++
			docs.rows = append(docs.rows, &farmRow{id: docs.next, content: "x", props: map[string]any{
				"Id": docs.next, "UniqueId": guid(4, f.nextID), "FileRef": fmt.Sprintf("/sites/hr/Shared Documents/f%05d.txt", i), "FSObjType": "0", "HasUniqueRoleAssignments": false,
				"Created": t0, "AuthorId": 11, "OData__UIVersion": 512, "OData__Level": 1, "OData__ModerationStatus": 0, "File": map[string]any{"Length": "1", "TimeLastModified": t0},
			}})
		}
	})
	tickets := f.list(f.root(), "Lists/Tickets", 100)
	for i := range 2500 {
		f.item(tickets, fmt.Sprintf("Ticket %d", i), nil)
	}
	a := f.agent(src)
	walk := walkSite(t, a, false)
	if len(walk.entries) != 14501 || walk.code != "" {
		t.Fatalf("entries %d code %s", len(walk.entries), walk.code)
	}
	for _, page := range walk.pages {
		if len(page.Entries) > pageSize {
			t.Fatalf("page of %d entries", len(page.Entries))
		}
	}
	if f.count(docs.id+"')/items?") != 3 || f.count("p_ID=5000") != 1 || f.count("p_ID=10000") != 1 || f.count(tickets.id+"')/items?") != 3 || f.count("$top=1000") != 3 {
		t.Fatalf("item requests: library %d, generic %d", f.count(docs.id+"')/items?"), f.count(tickets.id+"')/items?"))
	}
	previous := pageTime
	pageTime = 30 * time.Millisecond
	t.Cleanup(func() { pageTime = previous })
	f.update(func() { f.delay = func(*http.Request) time.Duration { return 20 * time.Millisecond } })
	slow := walkSite(t, a, false)
	empty := 0
	for _, page := range slow.pages {
		if len(page.Entries) == 0 && page.Cursor != "" {
			empty++
		}
	}
	if empty == 0 || len(slow.entries) != len(walk.entries) {
		t.Fatalf("slow walk: %d empty pages, %d entries", empty, len(slow.entries))
	}
	same := func(e pageEntry) string {
		return fmt.Sprint(e.Path, e.File, e.Size, e.Created, e.Modified, classOfEntry(e), e.URL, e.Title)
	}
	for p, e := range walk.entries {
		if same(slow.entries[p]) != same(e) {
			t.Fatalf("slow walk changed %s", p)
		}
	}
	if f.count("$orderby=Id") != f.count("/items?") {
		t.Fatal("an items query without $orderby=Id was sent")
	}
}

func TestSiteWalkSkips(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "keep.txt", "x")
	f.file(docs, "bad:name.txt", "x")
	f.file(docs, "page.aspx", "x")
	f.file(docs, "Drafts/~$tmp.docx", "x")
	big := f.file(docs, "big.bin", "x")
	f.file(docs, "Dup.txt", "one")
	f.file(docs, "dup.txt", "two")
	f.update(func() { big.props["File"] = map[string]any{"Length": strconv.Itoa(21 << 20), "TimeLastModified": t0} })
	hidden := f.web(f.root(), "hidden", false)
	f.update(func() { hidden.props["NoCrawl"] = true })
	f.file(f.list(hidden, "Docs", 1), "h.txt", "x")
	for _, flag := range []string{"Hidden", "IsCatalog", "NoCrawl", "IrmEnabled"} {
		l := f.list(f.root(), flag, 1)
		f.update(func() { l.props[flag] = true })
		f.file(l, "x.txt", "x")
	}
	f.file(f.list(f.root(), "Site Assets", 1), "logo.png", "x")
	outside := f.list(f.root(), "Outside", 1)
	f.update(func() { outside.props["RootFolder"] = map[string]any{"ServerRelativeUrl": "/sites/other/Outside"} })
	tickets := f.list(f.root(), "Lists/Tickets", 100)
	ticket := f.item(tickets, "Ticket", nil)
	f.attach(tickets, ticket, "ok.txt", "fine")
	f.attach(tickets, ticket, "hash#.txt", "x")
	f.attach(tickets, ticket, "pct%41.txt", "x")
	f.update(func() {
		ticket.attachments = append(ticket.attachments, farmAttachment{name: "elsewhere.txt", url: "/sites/hr/Lists/Tickets/Attachments/9/elsewhere.txt", content: "x"})
	})
	a := f.agent(src)
	a.cfg.Roots[0].Exclude = []string{"Site Assets", "~$*"}
	walk := walkSite(t, a, false)
	got := slices.Sorted(maps.Keys(walk.entries))
	want := []string{"Lists/Tickets/1_.000.md", "Lists/Tickets/Attachments/1/ok.txt", "Shared Documents/Dup.txt", "Shared Documents/dup.txt", "Shared Documents/keep.txt"}
	if !slices.Equal(got, want) || len(walk.incomplete) != 0 {
		t.Fatalf("entries %v incomplete %v", got, walk.incomplete)
	}
	if walk.entries["Shared Documents/Dup.txt"].Class != nil || walk.entries["Shared Documents/dup.txt"].Class != nil || walk.entries["Shared Documents/keep.txt"].Class == nil {
		t.Fatal("duplicate paths keep a class")
	}
	if _, code := readSite(a, walk.entries["Shared Documents/dup.txt"]); code != "not_found" {
		t.Fatalf("duplicate read answered %s", code)
	}
	if f.count("/sites/hr/hidden/_api/") != 0 {
		t.Fatal("skipped web listed")
	}
}

func TestSiteWalkIncomplete(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "x")
	sub := f.web(f.root(), "teams", false)
	f.file(f.list(sub, "Docs", 1), "t.txt", "x")
	broken := f.list(f.root(), "Broken", 1)
	f.file(broken, "b.txt", "x")
	f.update(func() {
		f.fault = func(r *http.Request) *farmFault {
			if r.URL.Path == "/sites/hr/teams/_api/web/lists" || strings.Contains(r.URL.Path, broken.id+"')/items") {
				return &farmFault{status: http.StatusInternalServerError}
			}
			return nil
		}
	})
	a := f.agent(src)
	walk := walkSite(t, a, false)
	if !slices.Equal(slices.Sorted(slices.Values(walk.incomplete)), []string{"Broken", "teams"}) || len(walk.entries) != 1 || walk.code != "" {
		t.Fatalf("incomplete %v entries %d", walk.incomplete, len(walk.entries))
	}
	if _, ok := a.walked["intranet"]; !ok || a.sites.roots["intranet"].base.partial != true {
		t.Fatal("walk with incomplete parts was not recorded as partial")
	}
	if walkSite(t, a, true).code != "cursor" {
		t.Fatal("partial baseline answered a changes walk")
	}
	f.update(func() {
		f.fault = func(r *http.Request) *farmFault {
			if r.URL.Path == "/sites/hr/_api/web/webs" {
				return &farmFault{status: http.StatusInternalServerError}
			}
			return nil
		}
	})
	if code := walkSite(t, a, false).code; code != "failed" {
		t.Fatalf("root web failure answered %s", code)
	}
	data, _ := os.ReadFile(filepath.Join(a.dir, "state", "walks.json"))
	if _, ok := a.walked["intranet"]; ok || strings.Contains(string(data), "intranet") {
		t.Fatal("failed walk kept walks.json entry")
	}
	f.update(func() {
		f.fault = nil
		f.site["CurrentChangeToken"] = map[string]any{"StringValue": "1;1;" + guid(1, 2) + ";1;1"}
	})
	if code := walkSite(t, a, false).code; code != "failed" {
		t.Fatalf("malformed change token answered %s", code)
	}
	f.update(func() { f.site["CurrentChangeToken"] = map[string]any{"StringValue": "garbage"} })
	if code := walkSite(t, a, false).code; code != "failed" {
		t.Fatalf("garbage change token answered %s", code)
	}
	f.update(func() { delete(f.site, "CurrentChangeToken"); f.site["ServerRelativeUrl"] = "/sites/hr/sub" })
	if code := walkSite(t, a, false).code; code != "unavailable" {
		t.Fatalf("a web URL answered %s", code)
	}
}

func TestMarkdown(t *testing.T) {
	f, src, _ := basicFarm(t)
	tickets := f.list(f.root(), "Lists/Tickets", 100)
	tickets.fields = []map[string]any{
		{"EntityPropertyName": "Title", "Title": "Title", "TypeAsString": "Text"},
		{"EntityPropertyName": "Description", "Title": "Description", "TypeAsString": "Note"},
		{"EntityPropertyName": "OData__x0020_Cost", "Title": "Cost", "TypeAsString": "Currency"},
		{"EntityPropertyName": "Amount", "Title": "Amount", "TypeAsString": "Number"},
		{"EntityPropertyName": "Count", "Title": "Count", "TypeAsString": "Integer"},
		{"EntityPropertyName": "Due", "Title": "Due", "TypeAsString": "DateTime"},
		{"EntityPropertyName": "Urgent", "Title": "Urgent", "TypeAsString": "Boolean"},
		{"EntityPropertyName": "Done", "Title": "Done", "TypeAsString": "Boolean"},
		{"EntityPropertyName": "Priority", "Title": "Priority", "TypeAsString": "Choice"},
		{"EntityPropertyName": "Tags", "Title": "Tags", "TypeAsString": "MultiChoice"},
		{"EntityPropertyName": "Link", "Title": "Link", "TypeAsString": "URL"},
		{"EntityPropertyName": "OwnerId", "Title": "Owner", "TypeAsString": "User"},
		{"EntityPropertyName": "CustomerId", "Title": "Customer", "TypeAsString": "Lookup"},
		{"EntityPropertyName": "Empty", "Title": "Empty", "TypeAsString": "Text"},
		{"EntityPropertyName": "bad-key", "Title": "Bad", "TypeAsString": "Text"},
	}
	f.item(tickets, "Printer on floor 3", map[string]any{
		"Description": "Paper jam\r\nagain", "OData__x0020_Cost": 12.5, "Amount": 1e21, "Count": 7, "Due": t0, "Urgent": true, "Done": false,
		"Priority": "High", "Tags": []any{"hardware", "floor 3"}, "Link": map[string]any{"Url": "https://help.corp.example/7", "Description": "Ticket"},
		"OwnerId": 11, "CustomerId": 4, "Empty": "", "bad-key": "x",
	})
	long := strings.Repeat("é", 300)
	f.item(tickets, long, nil)
	f.item(tickets, "  ", nil)
	a := f.agent(src)
	walk := walkSite(t, a, false)
	golden := "# Printer on floor 3\n\n- Description: Paper jam\nagain\n- Cost: 12.5\n- Amount: 1000000000000000000000\n- Count: 7\n- Due: 2026-11-01T10:00:00Z\n- Urgent: Yes\n- Done: No\n- Priority: High\n- Tags: hardware, floor 3\n- Link: Ticket (https://help.corp.example/7)\n"
	first := walk.entries["Lists/Tickets/1_.000.md"]
	data, code := readSite(a, first)
	if code != "done" || data != golden || first.Size != int64(len(golden)) || first.Title != "Printer on floor 3" {
		t.Fatalf("read %s %q size %d", code, data, first.Size)
	}
	second := walk.entries["Lists/Tickets/2_.000.md"]
	if second.Title != strings.Repeat("é", 255) {
		t.Fatalf("title has %d runes", len([]rune(second.Title)))
	}
	if data, _ := readSite(a, second); data != "# "+strings.Repeat("é", 255)+"\n\n" {
		t.Fatalf("long title rendered %q", data)
	}
	if walk.entries["Lists/Tickets/3_.000.md"].Title != "Item 3" {
		t.Fatal("empty title not replaced")
	}
	f.update(func() { tickets.rows[0].props["Priority"] = "Hugh" })
	if _, code := readSite(a, first); code != "done" {
		t.Fatalf("same size field edit answered %s", code)
	}
	f.update(func() { tickets.rows[0].props["Priority"] = "Lowest" })
	if _, code := readSite(a, first); code != "changed" {
		t.Fatalf("field edit answered %s", code)
	}
}

func TestLinks(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.update(func() { f.site["Url"] = "https://portal.corp.example/sites/hr" })
	f.file(docs, "Q1 report#2.pdf", "x")
	tickets := f.list(f.root(), "Lists/Tickets", 100)
	ticket := f.item(tickets, "Ticket", nil)
	f.attach(tickets, ticket, "a b.txt", "x")
	a := f.agent(src)
	walk := walkSite(t, a, false)
	want := map[string]string{
		"Shared Documents/Q1 report#2.pdf":    "https://portal.corp.example/sites/hr/Shared%20Documents/Q1%20report%232.pdf",
		"Lists/Tickets/1_.000.md":             "https://portal.corp.example/sites/hr/Lists/Tickets/DispForm.aspx?ID=1",
		"Lists/Tickets/Attachments/1/a b.txt": "https://portal.corp.example/sites/hr/Lists/Tickets/Attachments/1/a%20b.txt",
	}
	for p, link := range want {
		if walk.entries[p].URL != link || strings.Contains(walk.entries[p].URL, "%2F") {
			t.Errorf("%s link %q", p, walk.entries[p].URL)
		}
	}
	if walk.entries["Lists/Tickets/1_.000.md"].Title != "Ticket" || walk.entries["Shared Documents/Q1 report#2.pdf"].Title != "" {
		t.Fatal("titles")
	}
	f.update(func() { f.site["Url"] = "ftp://portal.corp.example/sites/hr" })
	for _, e := range walkSite(t, a, false).entries {
		if e.URL != "" {
			t.Fatalf("link %q from an ftp site URL", e.URL)
		}
	}
}

func TestChanges(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "keep.txt", "keep")
	edit := f.file(docs, "edit.txt", "v1")
	gone := f.file(docs, "gone.txt", "bye")
	folder := f.folder(docs, "A")
	child := f.file(docs, "A/child.txt", "c")
	other := f.list(f.root(), "Other", 1)
	moving := f.file(docs, "move.txt", "m")
	doomed := f.list(f.root(), "Doomed", 1)
	f.file(doomed, "d.txt", "d")
	hiding := f.list(f.root(), "Hiding", 1)
	f.file(hiding, "h.txt", "h")
	userInfo := f.list(f.root(), "_catalogs/users", 100)
	f.update(func() { userInfo.props["Hidden"] = true })
	sub := f.web(f.root(), "teams", false)
	f.file(f.list(sub, "Docs", 1), "t.txt", "t")
	a := f.agent(src)
	if walkSite(t, a, true).code != "cursor" {
		t.Fatal("changes without baseline")
	}
	if code := walkSite(t, a, false).code; code != "" {
		t.Fatal(code)
	}
	walked := a.walked["intranet"]
	if changes := walkSite(t, a, true); changes.code != "" || len(changes.entries) != 0 || len(changes.deleted) != 0 {
		t.Fatalf("no change gave %+v", changes)
	}
	added := f.file(docs, "new.txt", "new")
	f.edit(edit, "v2", 1024, 1)
	f.update(func() {
		docs.rows = slices.DeleteFunc(docs.rows, func(r *farmRow) bool { return r == gone })
		folder.props["FileRef"] = "/sites/hr/Shared Documents/B"
		child.props["FileRef"] = "/sites/hr/Shared Documents/B/child.txt"
		docs.rows = slices.DeleteFunc(docs.rows, func(r *farmRow) bool { return r == moving })
		moving.props["FileRef"] = "/sites/hr/Other/move.txt"
		other.rows = append(other.rows, moving)
		f.lists = slices.DeleteFunc(f.lists, func(l *farmList) bool { return l == doomed })
		hiding.props["IrmEnabled"] = true
	})
	for _, c := range []map[string]any{
		{"ListId": docs.id, "ItemId": added.id, "WebId": f.root().id}, {"ListId": docs.id, "ItemId": edit.id}, {"ListId": other.id, "ItemId": moving.id},
		{"ListId": doomed.id}, {"ListId": hiding.id}, {"ListId": userInfo.id, "ItemId": 4, "WebId": f.root().id}, {"UserId": 11}, {"GroupId": 50, "WebId": f.root().id},
	} {
		f.change(c)
	}
	before := f.count("/_api/web/webs")
	changes := walkSite(t, a, true)
	gotEntries := slices.Sorted(maps.Keys(changes.entries))
	if changes.code != "" || !slices.Equal(gotEntries, []string{"Other/move.txt", "Shared Documents/B/child.txt", "Shared Documents/edit.txt", "Shared Documents/new.txt"}) ||
		!slices.Equal(changes.deleted, []string{"Doomed/d.txt", "Hiding/h.txt", "Shared Documents/A/child.txt", "Shared Documents/gone.txt", "Shared Documents/move.txt"}) {
		t.Fatalf("diff %s entries %v deleted %v", changes.code, gotEntries, changes.deleted)
	}
	if f.count("/_api/web/webs") != before || a.walked["intranet"] != walked {
		t.Fatal("ignored changes re-walked a web or renewed walked")
	}
	body := f.requests[len(f.requests)-1].body
	for _, request := range f.requests {
		if strings.HasSuffix(request.path, "getchanges") {
			body = request.body
		}
	}
	if strings.Contains(body, "FetchLimit") || strings.Contains(body, `"File"`) || strings.Contains(body, `"Folder"`) || !strings.Contains(body, `"SecurityPolicy":true`) {
		t.Fatalf("getchanges body %s", body)
	}
	if again := walkSite(t, a, true); len(again.entries) != 0 || len(again.deleted) != 0 {
		t.Fatalf("committed changes repeated: %+v", again)
	}
	newList := f.list(sub, "Fresh", 1)
	f.file(newList, "fresh.txt", "f")
	f.change(map[string]any{"ListId": newList.id, "ItemId": 1, "WebId": sub.id})
	if got := walkSite(t, a, true); !slices.Equal(slices.Sorted(maps.Keys(got.entries)), []string{"teams/Fresh/fresh.txt"}) {
		t.Fatalf("new list in a known web: %v", got.entries)
	}
	f.change(map[string]any{"WebId": sub.id})
	if got := walkSite(t, a, true); got.code != "" || len(got.entries) != 0 || len(got.deleted) != 0 {
		t.Fatalf("web change without differences: %+v", got)
	}
	identity := f.count("GET /sites/hr/teams/_api/web?")
	f.change(map[string]any{"WebId": sub.id})
	f.change(map[string]any{"WebId": f.root().id})
	if got := walkSite(t, a, true); got.code != "" || len(got.entries) != 0 || len(got.deleted) != 0 || f.count("GET /sites/hr/teams/_api/web?") != identity {
		t.Fatalf("nested web changes: %+v, %d identity checks", got, f.count("GET /sites/hr/teams/_api/web?")-identity)
	}
	for _, c := range []map[string]any{{"WebId": guid(2, 777)}, {}, {"ListId": guid(3, 777), "WebId": guid(2, 777)}, {"ListId": "not-a-guid"}} {
		f.change(c)
		if code := walkSite(t, a, true).code; code != "cursor" {
			t.Fatalf("change %v answered %s", c, code)
		}
		walkSite(t, a, false)
	}
	f.update(func() { sub.props["Id"] = guid(2, 888) })
	f.change(map[string]any{"WebId": sub.id})
	if code := walkSite(t, a, true).code; code != "cursor" {
		t.Fatalf("replaced web answered %s", code)
	}
	walkSite(t, a, false)
	f.update(func() {
		sub.id = guid(2, 888)
		for range 5001 {
			f.number++
			f.changes = append(f.changes, map[string]any{"ListId": docs.id, "ItemId": 1, "ChangeToken": map[string]any{"StringValue": f.token()}})
		}
	})
	if code := walkSite(t, a, true).code; code != "cursor" {
		t.Fatalf("over 5000 changes answered %s", code)
	}
	walkSite(t, a, false)
	token := a.sites.roots["intranet"].base.token
	waits := 0
	previous := retryPause
	retryPause = func(context.Context, time.Duration) error { waits++; return nil }
	t.Cleanup(func() { retryPause = previous })
	f.update(func() {
		f.fault = func(r *http.Request) *farmFault {
			if strings.HasSuffix(r.URL.Path, "getchanges") {
				return &farmFault{status: http.StatusServiceUnavailable}
			}
			return nil
		}
	})
	f.change(map[string]any{"ListId": docs.id, "ItemId": 1})
	if code := walkSite(t, a, true).code; code != "busy" || waits != 2 || a.sites.roots["intranet"].base.token != token {
		t.Fatalf("throttled change log answered %s after %d waits", code, waits)
	}
	f.update(func() {
		f.fault = func(r *http.Request) *farmFault {
			if strings.Contains(r.URL.Path, docs.id+"')/items") {
				return &farmFault{status: http.StatusInternalServerError}
			}
			return nil
		}
	})
	if got := walkSite(t, a, true); got.code != "" || !slices.Equal(got.incomplete, []string{"Shared Documents"}) || len(got.deleted) != 0 {
		t.Fatalf("failed re-list: %+v", got)
	}
	if code := walkSite(t, a, true).code; code != "cursor" {
		t.Fatalf("after a failed re-list answered %s", code)
	}
	f.update(func() {
		f.fault = nil
		f.delay = func(r *http.Request) time.Duration { return 50 * time.Millisecond }
	})
	previousPage := pageTime
	pageTime = 20 * time.Millisecond
	t.Cleanup(func() { pageTime = previousPage })
	first := a.walk(message{Type: "walk", ID: 1, Root: "intranet"}).(pageMessage)
	if first.Cursor == "" {
		t.Fatal("slow full walk finished at once")
	}
	if code := walkSite(t, a, true).code; code != "busy" {
		t.Fatalf("changes during a full walk answered %s", code)
	}
	a.now = func() time.Time { return time.Now().Add(fullBusy + time.Second) }
	if code := walkSite(t, a, true).code; code != "cursor" {
		t.Fatalf("changes after an abandoned full walk answered %s", code)
	}
}

func TestChangesRootWebFailure(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "a")
	other := f.list(f.root(), "Lists/Other", 100)
	f.item(other, "Item", nil)
	hidden := f.list(f.root(), "Hidden", 1)
	f.update(func() { hidden.props["Hidden"] = true })
	sub := f.web(f.root(), "teams", false)
	f.file(f.list(sub, "Docs", 1), "t.txt", "t")
	a := f.agent(src)
	walkSite(t, a, false)
	f.change(map[string]any{"WebId": f.root().id})
	f.update(func() {
		f.fault = func(r *http.Request) *farmFault {
			if r.URL.Path == "/sites/hr/_api/web" {
				return &farmFault{status: http.StatusInternalServerError}
			}
			return nil
		}
	})
	got := walkSite(t, a, true)
	slices.Sort(got.incomplete)
	if got.code != "" || !slices.Equal(got.incomplete, []string{"Lists/Other", "Shared Documents", "teams/Docs"}) || len(got.deleted) != 0 {
		t.Fatalf("failed root web re-walk: %+v", got)
	}
	if code := walkSite(t, a, true).code; code != "cursor" {
		t.Fatalf("after a failed root web answered %s", code)
	}
}

func TestDigestRenewed(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "a")
	a := f.agent(src)
	walkSite(t, a, false)
	a.sites.roots["intranet"].digest, a.sites.roots["intranet"].digestTo = "rejected", time.Now().Add(time.Hour)
	f.file(docs, "b.txt", "b")
	f.change(map[string]any{"ListId": docs.id, "ItemId": 2})
	if got := walkSite(t, a, true); got.code != "" || len(got.entries) != 1 || f.count("contextinfo") != 1 || a.sites.roots["intranet"].digest != "digest-1" {
		t.Fatalf("stale digest: %+v, %d digests", got, f.count("contextinfo"))
	}
	f.update(func() {
		f.fault = func(r *http.Request) *farmFault {
			if strings.HasSuffix(r.URL.Path, "getchanges") {
				return &farmFault{status: http.StatusForbidden}
			}
			return nil
		}
	})
	calls := f.count("getchanges")
	if code := walkSite(t, a, true).code; code != "cursor" || f.count("contextinfo") != 2 || f.count("getchanges") != calls+2 {
		t.Fatalf("refused change log answered %s after %d digests and %d calls", code, f.count("contextinfo"), f.count("getchanges")-calls)
	}
}

func TestSnapshotDeadline(t *testing.T) {
	f, src, docs := basicFarm(t)
	for i := range 24 {
		row := f.file(docs, fmt.Sprintf("f%02d.txt", i), "x")
		f.update(func() {
			row.props["HasUniqueRoleAssignments"] = true
			f.roles[fmt.Sprintf("i:%s:%d", docs.id, row.id)] = []map[string]any{grantTo(3, domainUsers, 4, readHigh, readLow)}
		})
	}
	a := f.agent(src)
	walk := walkSite(t, a, false)
	previous := accessTime
	accessTime = 800 * time.Millisecond
	t.Cleanup(func() { accessTime = previous })
	f.update(func() {
		f.delay = func(r *http.Request) time.Duration {
			if strings.HasSuffix(r.URL.Path, "/roleassignments") {
				return 100 * time.Millisecond
			}
			return 0
		}
	})
	readers, errs := readersByPath(t, a, []string{aliceSID}, walk.entries)
	granted := 0
	for _, r := range readers {
		granted += len(r)
	}
	if len(errs) != 0 || granted == 0 || granted == 24 || a.sites.roots["intranet"].snap != nil {
		t.Fatalf("cut snapshot: %d readers, errors %v, cached %v", granted, errs, a.sites.roots["intranet"].snap != nil)
	}
	if f.count("/roleassignments") < 8 || f.count("/roleassignments") > 20 {
		t.Fatalf("snapshot did not run in parallel within half the deadline: %d calls", f.count("/roleassignments"))
	}
	accessTime = 30 * time.Second
	readers, _ = readersByPath(t, a, []string{aliceSID}, walk.entries)
	granted = 0
	for _, r := range readers {
		granted += len(r)
	}
	if granted != 24 || a.sites.roots["intranet"].snap == nil {
		t.Fatalf("complete snapshot gave %d readers", granted)
	}
}

func TestAccessShares(t *testing.T) {
	f, src, docs := basicFarm(t)
	for i := range 12 {
		row := f.file(docs, fmt.Sprintf("f%02d.txt", i), "x")
		f.update(func() {
			row.props["HasUniqueRoleAssignments"] = true
			f.roles[fmt.Sprintf("i:%s:%d", docs.id, row.id)] = []map[string]any{grantTo(3, domainUsers, 4, readHigh, readLow)}
		})
	}
	a := f.agent(src)
	a.cfg.Roots = append(a.cfg.Roots, root{ID: "second", URL: a.cfg.Roots[0].URL, SPN: a.cfg.Roots[0].SPN})
	walkSite(t, a, false)
	for cursor := a.walk(message{Type: "walk", ID: 1, Root: "second"}).(pageMessage).Cursor; cursor != ""; {
		cursor = a.walk(message{Type: "walk", ID: 1, Root: "second", Cursor: cursor}).(pageMessage).Cursor
	}
	previous := accessTime
	accessTime = 600 * time.Millisecond
	t.Cleanup(func() { accessTime = previous })
	f.update(func() {
		f.delay = func(r *http.Request) time.Duration {
			if strings.Contains(r.URL.Path, "getusereffectivepermissions") {
				return 150 * time.Millisecond
			}
			return 0
		}
	})
	rights := a.access(message{Type: "access", ID: 2, SIDs: []string{aliceSID, bobSID}}).(rightsMessage)
	rootOf := map[string]string{}
	for _, id := range []string{"intranet", "second"} {
		for _, ref := range a.sites.roots[id].base.paths {
			rootOf[ref.entry.Class] = id
		}
	}
	perRoot := map[string]int{}
	for _, c := range rights.Classes {
		perRoot[rootOf[c.Class]] += len(c.Readers)
	}
	if len(rights.Errors) != 0 || perRoot["intranet"] == 0 || perRoot["second"] == 0 {
		t.Fatalf("the first root used the whole deadline: readers %v, errors %v", perRoot, rights.Errors)
	}
}

func TestCellRefresh(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "a")
	a := f.agent(src)
	walk := walkSite(t, a, false)
	start := time.Now()
	a.now = func() time.Time { return start }
	readersByPath(t, a, []string{aliceSID}, walk.entries)
	checks := f.count("getusereffectivepermissions")
	a.now = func() time.Time { return start.Add(cellRefresh - time.Second) }
	readersByPath(t, a, []string{aliceSID}, walk.entries)
	if f.count("getusereffectivepermissions") != checks {
		t.Fatal("a young cell was checked again")
	}
	a.now = func() time.Time { return start.Add(cellRefresh) }
	readers, _ := readersByPath(t, a, []string{aliceSID}, walk.entries)
	if !slices.Equal(readers["Shared Documents/a.txt"], []int{0}) || f.count("getusereffectivepermissions") != checks+1 {
		t.Fatalf("an old cell was not refreshed: readers %v", readers)
	}
	for _, c := range a.sites.cells {
		if !c.at.Equal(start.Add(cellRefresh)) {
			t.Fatalf("cell stamped %v", c.at)
		}
	}
	a.now = func() time.Time { return start.Add(cellLife) }
	readersByPath(t, a, []string{aliceSID}, walk.entries)
	if f.count("getusereffectivepermissions") != checks+1 {
		t.Fatal("a refreshed cell expired with its first answer")
	}
}

func TestChangesCommit(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "a")
	a := f.agent(src)
	walkSite(t, a, false)
	for i := range 600 {
		f.file(docs, fmt.Sprintf("n%03d.txt", i), "n")
	}
	f.change(map[string]any{"ListId": docs.id, "ItemId": 2})
	first := a.walk(message{Type: "walk", ID: 1, Root: "intranet", Changes: true}).(pageMessage)
	if len(first.Entries) != pageSize || first.Cursor == "" {
		t.Fatalf("first page %d entries", len(first.Entries))
	}
	again := walkSite(t, a, true)
	if len(again.entries) != 600 {
		t.Fatalf("abandoned walk committed: %d entries again", len(again.entries))
	}
	f.file(docs, "late.txt", "l")
	f.change(map[string]any{"ListId": docs.id, "ItemId": 1000})
	previous := pageTime
	pageTime = 20 * time.Millisecond
	t.Cleanup(func() { pageTime = previous })
	f.update(func() { f.delay = func(*http.Request) time.Duration { return 30 * time.Millisecond } })
	running := a.walk(message{Type: "walk", ID: 1, Root: "intranet", Changes: true}).(pageMessage)
	full := a.walk(message{Type: "walk", ID: 1, Root: "intranet"}).(pageMessage)
	if running.Cursor == "" || len(running.Entries) != 0 || full.Cursor == "" {
		t.Fatalf("running changes page %+v", running)
	}
	if reply := a.walk(message{Type: "walk", ID: 1, Root: "intranet", Changes: true, Cursor: running.Cursor}); codeOfReply(reply) != "cursor" {
		t.Fatalf("canceled changes walk answered %s", codeOfReply(reply))
	}
	for cursor := full.Cursor; cursor != ""; {
		cursor = a.walk(message{Type: "walk", ID: 1, Root: "intranet", Cursor: cursor}).(pageMessage).Cursor
	}
	if got := walkSite(t, a, true); len(got.entries) != 0 || len(got.deleted) != 0 {
		t.Fatalf("after the full walk: %+v", got)
	}
	stale := a.walk(message{Type: "walk", ID: 1, Root: "intranet"}).(pageMessage)
	a.now = func() time.Time { return time.Now().Add(fullBusy + time.Second) }
	f.change(map[string]any{"ListId": docs.id, "ItemId": 1})
	late := a.walk(message{Type: "walk", ID: 1, Root: "intranet", Changes: true}).(pageMessage)
	if stale.Cursor == "" || late.Cursor == "" {
		t.Fatal("walks finished at once")
	}
	for cursor := stale.Cursor; cursor != ""; {
		cursor = a.walk(message{Type: "walk", ID: 1, Root: "intranet", Cursor: cursor}).(pageMessage).Cursor
	}
	committed := a.sites.roots["intranet"].base
	for cursor := late.Cursor; cursor != ""; {
		cursor = a.walk(message{Type: "walk", ID: 1, Root: "intranet", Changes: true, Cursor: cursor}).(pageMessage).Cursor
	}
	if a.sites.roots["intranet"].base != committed {
		t.Fatal("a changes walk started before a full walk replaced its baseline")
	}
}

func TestSiteRead(t *testing.T) {
	f, src, docs := basicFarm(t)
	content := strings.Repeat("abcdefghij", 3*chunkSize/10+7)
	current := f.file(docs, "current.txt", content)
	draftBefore := f.file(docs, "before.txt", "published")
	draftDuring := f.file(docs, "during.txt", "published")
	sameSize := f.file(docs, "same.txt", "aaaa")
	broken := f.file(docs, "broken.txt", "x")
	tickets := f.list(f.root(), "Lists/Tickets", 100)
	ticket := f.item(tickets, "Ticket", nil)
	f.attach(tickets, ticket, "notes.txt", "attached notes")
	locked := f.list(f.root(), "Locked", 1)
	f.file(locked, "l.txt", "l")
	a := f.agent(src)
	walk := walkSite(t, a, false)
	f.update(func() { f.chunked = true })
	if data, code := readSite(a, walk.entries["Shared Documents/current.txt"]); code != "done" || data != content {
		t.Fatalf("current file %s, %d bytes", code, len(data))
	}
	if data, code := readSite(a, walk.entries["Lists/Tickets/Attachments/1/notes.txt"]); code != "done" || data != "attached notes" {
		t.Fatalf("attachment %s %q", code, data)
	}
	if data, code := readSite(a, walk.entries["Lists/Tickets/1_.000.md"]); code != "done" || data != "# Ticket\n\n" {
		t.Fatalf("item %s %q", code, data)
	}
	f.edit(draftBefore, "draft....", 513, 2)
	f.update(func() {
		f.onValue = func() {
			draftDuring.content = "draft"
			draftDuring.props["OData__UIVersion"], draftDuring.props["OData__Level"] = 513, 2
		}
	})
	f.edit(sameSize, "bbbb", 512, 1)
	f.update(func() { broken.props["HasUniqueRoleAssignments"] = true })
	for p, want := range map[string]string{"before.txt": "changed", "during.txt": "changed", "same.txt": "changed", "broken.txt": "changed"} {
		if data, code := readSite(a, walk.entries["Shared Documents/"+p]); code != want || data == "draft" {
			t.Errorf("%s answered %s", p, code)
		}
	}
	for _, flag := range []string{"IrmEnabled", "NoCrawl", "Hidden"} {
		f.update(func() { locked.props[flag] = true })
		if _, code := readSite(a, walk.entries["Locked/l.txt"]); code != "not_found" {
			t.Errorf("list now %s answered %s", flag, code)
		}
		f.update(func() { locked.props[flag] = false })
	}
	if _, code := readSite(a, pageEntry{Path: "Shared Documents/unknown.txt", File: "0000000000000000"}); code != "not_found" {
		t.Fatalf("unknown path answered %s", code)
	}
	f.update(func() { current.content = content[:len(content)-3] })
	if _, code := readSite(a, walk.entries["Shared Documents/current.txt"]); code != "changed" {
		t.Fatalf("short body answered %s", code)
	}
	f.update(func() { current.content = content + "tail" })
	if _, code := readSite(a, walk.entries["Shared Documents/current.txt"]); code != "changed" {
		t.Fatalf("long body answered %s", code)
	}
	a.cfg.Limits.ReadWindow = "00:00-00:00"
	if _, code := readSite(a, walk.entries["Lists/Tickets/1_.000.md"]); code != "limit" {
		t.Fatalf("closed window answered %s", code)
	}
	a.cfg.Limits.ReadWindow = ""
	a.quota = quota{Day: time.Now().Format(time.DateOnly), Bytes: 50 << 30}
	if _, code := readSite(a, walk.entries["Lists/Tickets/1_.000.md"]); code != "limit" {
		t.Fatalf("quota answered %s", code)
	}
	a.quota = quota{}
	a.slots <- struct{}{}
	a.slots <- struct{}{}
	if _, code := readSite(a, walk.entries["Lists/Tickets/1_.000.md"]); code != "busy" {
		t.Fatalf("full slots answered %s", code)
	}
	<-a.slots
	<-a.slots
	if f.count("$value") == 0 || f.count("GetFileById") == 0 {
		t.Fatal("content requests missing")
	}
}

func TestRequestRules(t *testing.T) {
	f, src, docs := basicFarm(t)
	f.file(docs, "a.txt", "x")
	a := f.agent(src)
	r := a.cfg.Roots[0]
	var waits []time.Duration
	previous := retryPause
	retryPause = func(_ context.Context, wait time.Duration) error { waits = append(waits, wait); return nil }
	t.Cleanup(func() { retryPause = previous })
	for _, client := range []*http.Client{a.sites.client, a.sites.stream} {
		if client.Transport.(*http.Transport).Proxy != nil || client.CheckRedirect == nil || client.Jar != nil {
			t.Fatal("site client uses a proxy, follows redirects or keeps cookies")
		}
	}
	get := func() error {
		return a.sites.get(context.Background(), r, http.MethodGet, "/sites/hr/_api/web?$select=Id", nil, &struct{}{})
	}
	fault := func(make func(n int) *farmFault) {
		calls := 0
		f.update(func() {
			f.requests = nil
			f.fault = func(*http.Request) *farmFault { calls++; return make(calls) }
		})
	}
	src.negotiateErr = nil
	fault(func(int) *farmFault {
		return &farmFault{status: http.StatusUnauthorized, header: map[string]string{"WWW-Authenticate": "NTLM"}}
	})
	if err := get(); codeOf(err) != "unavailable" || f.count("GET") != 2 || !strings.Contains(err.Error(), "HTTP/127.0.0.1") {
		t.Fatalf("401 gave %v after %d requests", err, f.count("GET"))
	}
	elsewhere := atomic.Int32{}
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	fault(func(int) *farmFault {
		return &farmFault{status: http.StatusFound, header: map[string]string{"Location": other.URL + "/sites/hr/_api/web"}}
	})
	if err := get(); codeOf(err) != "unavailable" || elsewhere.Load() != 0 || f.count("GET") != 1 {
		t.Fatalf("redirect gave %v", err)
	}
	fault(func(int) *farmFault {
		return &farmFault{status: http.StatusForbidden, header: map[string]string{"X-FORMS_BASED_AUTH_REQUIRED": "https://x/login"}}
	})
	if err := get(); codeOf(err) != "unavailable" {
		t.Fatalf("forms login gave %v", err)
	}
	fault(func(int) *farmFault { return &farmFault{status: http.StatusForbidden} })
	if err := get(); codeOf(err) != "denied" {
		t.Fatalf("403 gave %v", err)
	}
	fault(func(n int) *farmFault {
		if n == 1 {
			return &farmFault{status: http.StatusServiceUnavailable, header: map[string]string{"Retry-After": "100"}}
		}
		if n == 2 {
			return &farmFault{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "2"}}
		}
		return nil
	})
	if err := get(); err != nil || fmt.Sprint(waits) != "[30s 2s]" {
		t.Fatalf("Retry-After gave %v waits %v", err, waits)
	}
	waits = nil
	fault(func(int) *farmFault { return &farmFault{status: http.StatusServiceUnavailable} })
	if err := get(); codeOf(err) != "busy" || fmt.Sprint(waits) != "[5s 10s]" || f.count("GET") != 3 {
		t.Fatalf("throttling gave %v waits %v requests %d", err, waits, f.count("GET"))
	}
	waits = nil
	stamp := time.Now().Add(12 * time.Second).UTC().Format(http.TimeFormat)
	fault(func(n int) *farmFault {
		if n == 1 {
			return &farmFault{status: http.StatusServiceUnavailable, header: map[string]string{"Retry-After": stamp}}
		}
		return nil
	})
	if err := get(); err != nil || len(waits) != 1 || waits[0] < 9*time.Second || waits[0] > 12*time.Second {
		t.Fatalf("HTTP date Retry-After gave %v %v", err, waits)
	}
	fault(func(int) *farmFault {
		return &farmFault{status: http.StatusInternalServerError, body: `{"error":{"code":"-2147024860, Microsoft.SharePoint.SPQueryThrottledException"}}`}
	})
	if err := get(); codeOf(err) != "busy" || f.count("GET") != 1 {
		t.Fatalf("threshold gave %v after %d requests", err, f.count("GET"))
	}
	fault(func(int) *farmFault {
		return &farmFault{status: http.StatusOK, body: `{"value":"` + strings.Repeat("x", maxBody) + `"}`}
	})
	if err := get(); err == nil || codeOf(err) != "failed" {
		t.Fatalf("huge body gave %v", err)
	}
	fault(func(int) *farmFault { return nil })
	for _, p := range []string{"/sites/hr/Shared%20Documents/_api/web", "//sites/hr/_api/web", "/sites/hr/_api/../../x/_api/web", "/sites/hrx/_api/web", "/other/_api/web"} {
		if _, err := a.sites.do(context.Background(), r, http.MethodGet, p, nil); err == nil {
			t.Errorf("GET %s was sent", p)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, "MERGE"} {
		if _, err := a.sites.do(context.Background(), r, method, "/sites/hr/_api/web/lists", nil); err == nil {
			t.Errorf("%s was sent", method)
		}
	}
	evil, _ := http.NewRequest(http.MethodGet, "https://evil.example/sites/hr/_api/web", nil)
	plain, _ := http.NewRequest(http.MethodGet, "http"+strings.TrimPrefix(f.server.URL, "https")+"/sites/hr/_api/web", nil)
	if a.sites.allowed(r, evil) || a.sites.allowed(r, plain) {
		t.Fatal("another host or scheme is allowed")
	}
	if f.count("") != 0 {
		t.Fatalf("refused requests reached the farm: %d", f.count(""))
	}
	fault(func(int) *farmFault { return &farmFault{status: http.StatusUnauthorized} })
	reply := a.walk(message{Type: "walk", ID: 1, Root: "intranet"}).(errorMessage)
	if reply.Code != "unavailable" || reply.Message != "root listing failed" {
		t.Fatalf("walk error %+v", reply)
	}
	fault(func(int) *farmFault { return nil })
	walk := walkSite(t, a, false)
	fault(func(int) *farmFault {
		return &farmFault{status: http.StatusFound, header: map[string]string{"Location": "https://secret.corp.example/"}}
	})
	_, code := readSite(a, walk.entries["Shared Documents/a.txt"])
	readReply := a.read(context.Background(), message{Type: "read", ID: 3, Root: "intranet", Path: "Shared Documents/a.txt", File: walk.entries["Shared Documents/a.txt"].File, Size: 1, Modified: walk.entries["Shared Documents/a.txt"].Modified}, openWindow(), func([]byte) error { return nil }).(errorMessage)
	if code != "unavailable" || readReply.Message != "read failed: unavailable" {
		t.Fatalf("read error %s %+v", code, readReply)
	}
	src.negotiateErr = ErrUnavailable
	fault(func(int) *farmFault { return nil })
	if err := get(); codeOf(err) != "unavailable" || f.count("") != 0 {
		t.Fatalf("failed Negotiate gave %v", err)
	}
}

func TestSiteCheck(t *testing.T) {
	f, src, _ := basicFarm(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("roots:\n  - id: intranet\n    url: "+f.server.URL+"/sites/hr\n"), 0o600)
	previous := host
	host.Source = func(string, string, map[string]bool) (Source, error) { return src, nil }
	t.Cleanup(func() { host = previous })
	output := func() string {
		stdout := os.Stdout
		reader, writer, _ := os.Pipe()
		os.Stdout = writer
		check(dir)
		writer.Close()
		os.Stdout = stdout
		data, _ := io.ReadAll(reader)
		return string(data)
	}
	if out := output(); !strings.Contains(out, "ok   root intranet site\n") || !strings.Contains(out, "ok   root intranet site users\n") {
		t.Fatalf("check output %s", out)
	}
	f.update(func() { f.site["ServerRelativeUrl"] = "/sites/other" })
	if out := output(); !strings.Contains(out, "fail root intranet site: not a site collection URL (spn HTTP/127.0.0.1)") {
		t.Fatalf("check output %s", out)
	}
}

func docx(text string) string {
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	for name, body := range map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
		"_rels/.rels":         `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
		"word/document.xml":   `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>` + text + `</w:t></w:r></w:p></w:body></w:document>`,
	} {
		part, _ := archive.Create(name)
		part.Write([]byte(body))
	}
	archive.Close()
	return out.String()
}

func e2eFarm(t *testing.T, address string) (*farm, *fakeSource) {
	f := newFarm(t, address)
	src := newFakeSource()
	staff, stale := "S-1-5-21-1-2-3-3001", "S-1-5-21-1-2-3-3002"
	f.person(src, 11, "alice", aliceSID, staff)
	f.person(src, 12, "bob", bobSID, staff)
	f.person(src, 13, "carol", carolSID)
	f.update(func() { f.users[2]["UserId"] = map[string]any{"NameId": "s-1-5-21-1-2-3-9003"} })
	src.accountList = []Account{
		{SID: aliceSID, GUID: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d001", UPN: os.Getenv("SMB_E2E_ALICE"), Mail: os.Getenv("SMB_E2E_ALICE"), Enabled: true},
		{SID: bobSID, GUID: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d002", UPN: os.Getenv("SMB_E2E_BOB"), Mail: os.Getenv("SMB_E2E_BOB"), Enabled: true},
	}
	alice := grantTo(11, `i:0#.w|corp\alice`, 1, readHigh, readLow)
	unique := func(l *farmList, row *farmRow, grants ...map[string]any) {
		f.update(func() {
			row.props["HasUniqueRoleAssignments"] = true
			f.roles[fmt.Sprintf("i:%s:%d", l.id, row.id)] = grants
		})
	}
	f.update(func() {
		f.roles["w:"+f.root().id] = []map[string]any{grantTo(30, "c:0+.w|"+strings.ToLower(staff), 4, readHigh, readLow)}
	})
	private := f.list(f.root(), "Alice", 1)
	unique(private, f.file(private, "plan.docx", docx("Alice only: kestrel-7341")), alice)
	docs := f.list(f.root(), "Shared Documents", 1)
	handbook := f.file(docs, "handbook.txt", "Shared handbook: heron-2958")
	draft := f.file(docs, "draft.txt", "Published draft: osprey-1100")
	unique(docs, draft, alice)
	tickets := f.list(f.root(), "Tickets", 100)
	tickets.fields = []map[string]any{{"EntityPropertyName": "Description", "Title": "Description", "TypeAsString": "Note"}}
	tickets.next = 16
	ticket := f.item(tickets, "Printer on floor 3", map[string]any{"Description": "Ticket token wren-5512"})
	f.attach(tickets, ticket, "notes.txt", "Ticket notes: finch-3301")
	requests := f.list(f.root(), "Requests", 100)
	f.update(func() { requests.props["ReadSecurity"] = 2 })
	f.item(requests, "Alice request plover-4420", map[string]any{"AuthorId": 11})
	restricted := f.list(f.root(), "Restricted", 1)
	unique(restricted, f.file(restricted, "memo.txt", "Restricted memo: ibis-7781"), grantTo(31, "c:0+.w|"+strings.ToLower(stale), 4, readHigh, readLow))
	unique(restricted, f.file(restricted, "carol.txt", "Carol file: tern-6604"), grantTo(13, `i:0#.w|corp\carol`, 1, readHigh, readLow))
	f.control = func(step string) bool {
		switch step {
		case "delete-handbook":
			f.update(func() { docs.rows = slices.DeleteFunc(docs.rows, func(row *farmRow) bool { return row == handbook }) })
			f.change(map[string]any{"ListId": docs.id, "ItemId": handbook.id, "WebId": f.root().id})
		case "alice-only-handbook":
			unique(docs, handbook, alice)
			f.change(map[string]any{"ListId": docs.id, "ItemId": handbook.id, "WebId": f.root().id})
		case "draft-on-top":
			f.edit(draft, "Draft on top: osprey-9999-draft", 513, 2)
			f.change(map[string]any{"ListId": docs.id, "ItemId": draft.id, "WebId": f.root().id})
		default:
			return false
		}
		t.Logf("control step %s", step)
		return true
	}
	return f, src
}

func TestSharePointCycle(t *testing.T) {
	f, src := e2eFarm(t, "")
	a := f.agent(src)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: siteRoots}}}
	control := func(step string) {
		resp, err := client.Post(f.server.URL+"/_control/"+step, "application/json", nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("control %s: %v", step, err)
		}
		resp.Body.Close()
	}
	sids := []string{aliceSID, bobSID}
	walk := walkSite(t, a, false)
	tokens := map[string]string{
		"Alice/plan.docx": "kestrel-7341", "Shared Documents/handbook.txt": "heron-2958", "Shared Documents/draft.txt": "osprey-1100", "Tickets/17_.000.md": "wren-5512",
		"Tickets/Attachments/17/notes.txt": "finch-3301", "Requests/1_.000.md": "plover-4420", "Restricted/memo.txt": "ibis-7781", "Restricted/carol.txt": "tern-6604",
	}
	want := map[string][]int{
		"Alice/plan.docx": {0}, "Shared Documents/handbook.txt": {0, 1}, "Shared Documents/draft.txt": {0}, "Tickets/17_.000.md": {0, 1},
		"Tickets/Attachments/17/notes.txt": {0, 1}, "Requests/1_.000.md": {0}, "Restricted/memo.txt": {}, "Restricted/carol.txt": {},
	}
	readers, errs := readersByPath(t, a, sids, walk.entries)
	for p, token := range tokens {
		e := walk.entries[p]
		data, code := readSite(a, e)
		if !slices.Equal(readers[p], want[p]) || code != "done" || !strings.Contains(data, token) && !strings.HasSuffix(p, ".docx") || !strings.HasPrefix(e.URL, f.server.URL+"/") {
			t.Errorf("%s readers %v code %s link %s", p, readers[p], code, e.URL)
		}
	}
	plan, _ := readSite(a, walk.entries["Alice/plan.docx"])
	archive, err := zip.NewReader(strings.NewReader(plan), int64(len(plan)))
	if err != nil {
		t.Fatal(err)
	}
	document, _ := archive.Open("word/document.xml")
	text, _ := io.ReadAll(document)
	if !strings.Contains(string(text), "kestrel-7341") {
		t.Fatal("plan.docx lacks its token")
	}
	if len(errs) != 0 || len(walk.entries) != len(tokens) {
		t.Fatalf("errors %v entries %v", errs, slices.Sorted(maps.Keys(walk.entries)))
	}
	control("alice-only-handbook")
	changes := walkSite(t, a, true)
	readers, _ = readersByPath(t, a, sids, changes.entries)
	if !slices.Equal(slices.Sorted(maps.Keys(changes.entries)), []string{"Shared Documents/handbook.txt"}) || !slices.Equal(readers["Shared Documents/handbook.txt"], []int{0}) {
		t.Fatalf("alice-only-handbook: %v %v", changes.entries, readers)
	}
	control("draft-on-top")
	changes = walkSite(t, a, true)
	if e := changes.entries["Shared Documents/draft.txt"]; e.Class != nil || len(changes.entries) != 1 {
		t.Fatalf("draft-on-top: %+v", changes.entries)
	}
	if data, code := readSite(a, walk.entries["Shared Documents/draft.txt"]); code != "changed" || strings.Contains(data, "osprey-9999") {
		t.Fatalf("draft read %s %q", code, data)
	}
	control("delete-handbook")
	changes = walkSite(t, a, true)
	if !slices.Equal(changes.deleted, []string{"Shared Documents/handbook.txt"}) || len(changes.entries) != 0 {
		t.Fatalf("delete-handbook: %+v", changes)
	}
	resp, _ := client.Post(f.server.URL+"/_control/unknown", "application/json", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal("unknown control step accepted")
	}
	resp.Body.Close()
}

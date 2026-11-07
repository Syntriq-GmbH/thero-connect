package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestMain(m *testing.M) {
	plain := func(data []byte) ([]byte, error) { return data, nil }
	host = Platform{Protect: plain, Unprotect: plain}
	os.Exit(m.Run())
}

func TestLoadConfigServers(t *testing.T) {
	load := func(roots string) (config, error) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("principal: thero-connect@CORP.EXAMPLE\nroots:\n"+roots), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(dir)
	}
	cfg, err := load("  - id: a\n    path: \\\\FS01.corp.example\\a\n  - id: b\n    path: \\\\Files.Corp.Example\\b\n    server: samba\n  - id: c\n    path: \\\\files.corp.example\\c\n    server: samba\n  - id: d\n    path: \\\\fs02.corp.example\\d\n    server: windows\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Principal != "thero-connect@CORP.EXAMPLE" || !maps.Equal(cfg.samba, map[string]bool{"files.corp.example": true}) {
		t.Fatalf("principal %q, samba %v", cfg.Principal, cfg.samba)
	}
	refused := map[string]string{
		"unknown value":       "  - id: a\n    path: \\\\fs01.corp.example\\a\n    server: linux\n",
		"mixed host":          "  - id: a\n    path: \\\\fs01.corp.example\\a\n    server: samba\n  - id: b\n    path: \\\\FS01.corp.example\\b\n",
		"mixed host explicit": "  - id: a\n    path: \\\\fs01.corp.example\\a\n    server: windows\n  - id: b\n    path: \\\\fs01.corp.example\\b\n    server: samba\n",
	}
	for name, roots := range refused {
		if _, err := load(roots); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSiteConfig(t *testing.T) {
	load := func(roots string) (config, error) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("principal: thero-connect@CORP.EXAMPLE\nroots:\n"+roots), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(dir)
	}
	accepted := []struct {
		name, roots, url, spn string
	}{
		{"site", "  - id: a\n    url: https://intranet.corp.example/sites/hr\n", "https://intranet.corp.example/sites/hr", "HTTP/intranet.corp.example"},
		{"root site", "  - id: a\n    url: https://projects.corp.example\n", "https://projects.corp.example", "HTTP/projects.corp.example"},
		{"trailing slash", "  - id: a\n    url: https://Intranet.Corp.Example/sites/HR/\n", "https://intranet.corp.example/sites/HR", "HTTP/intranet.corp.example"},
		{"root slash", "  - id: a\n    url: https://projects.corp.example/\n", "https://projects.corp.example", "HTTP/projects.corp.example"},
		{"port", "  - id: a\n    url: https://SP01.corp.example:8443/sites/a\n", "https://sp01.corp.example:8443/sites/a", "HTTP/sp01.corp.example"},
		{"spn", "  - id: a\n    url: https://projects.corp.example\n    spn: HTTP/sp01.corp.example\n", "https://projects.corp.example", "HTTP/sp01.corp.example"},
		{"spn port", "  - id: a\n    url: https://projects.corp.example\n    spn: HTTP/sp01.corp.example:8443\n", "https://projects.corp.example", "HTTP/sp01.corp.example:8443"},
		{"ip literal", "  - id: a\n    url: https://10.0.0.5/sites/a\n", "https://10.0.0.5/sites/a", "HTTP/10.0.0.5"},
		{"escaped path", "  - id: a\n    url: https://intranet.corp.example/sites/team%20a\n", "https://intranet.corp.example/sites/team%20a", "HTTP/intranet.corp.example"},
		{"exclude", "  - id: a\n    url: https://intranet.corp.example/sites/hr\n    exclude:\n      - Site Assets\n      - Lists/Archive\n", "https://intranet.corp.example/sites/hr", "HTTP/intranet.corp.example"},
	}
	for _, c := range accepted {
		cfg, err := load(c.roots)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if r := cfg.Roots[0]; r.URL != c.url || r.SPN != c.spn || r.Path != "" || len(cfg.samba) != 0 {
			t.Errorf("%s: url %q, spn %q, path %q, samba %v", c.name, r.URL, r.SPN, r.Path, cfg.samba)
		}
	}
	cfg, err := load("  - id: a\n    url: https://a.corp.example/sites/x\n  - id: b\n    url: https://b.corp.example\n    spn: HTTP/b01.corp.example\n")
	if err != nil || cfg.Roots[0].SPN != "HTTP/a.corp.example" || cfg.Roots[1].SPN != "HTTP/b01.corp.example" {
		t.Fatalf("two sites: %+v, %v", cfg.Roots, err)
	}
	refused := []struct {
		name, roots, want string
	}{
		{"both", "  - id: a\n    url: https://a.corp.example\n    path: \\\\fs01\\a\n", "exactly one"},
		{"neither", "  - id: a\n    exclude:\n      - x\n", "exactly one"},
		{"http", "  - id: a\n    url: http://a.corp.example\n", "url must be https://host/path"},
		{"no scheme", "  - id: a\n    url: a.corp.example/sites/x\n", "url must be https://host/path"},
		{"opaque", "  - id: a\n    url: https:a.corp.example\n", "url must be https://host/path"},
		{"user info", "  - id: a\n    url: https://user@a.corp.example\n", "url must be https://host/path"},
		{"password", "  - id: a\n    url: https://user:secret@a.corp.example\n", "url must be https://host/path"},
		{"query", "  - id: a\n    url: https://a.corp.example/sites/x?a=1\n", "url must be https://host/path"},
		{"empty query", "  - id: a\n    url: https://a.corp.example/sites/x?\n", "url must be https://host/path"},
		{"fragment", "  - id: a\n    url: https://a.corp.example/sites/x#top\n", "url must be https://host/path"},
		{"empty fragment", "  - id: a\n    url: https://a.corp.example/sites/x#\n", "url must be https://host/path"},
		{"no host", "  - id: a\n    url: https:///sites/x\n", "url must be https://host/path"},
		{"port only", "  - id: a\n    url: https://:443/sites/x\n", "url must be https://host/path"},
		{"empty port", "  - id: a\n    url: https://a.corp.example:/sites/x\n", "url must be https://host/path"},
		{"bad port", "  - id: a\n    url: https://a.corp.example:https/sites/x\n", "url must be https://host/path"},
		{"double slash", "  - id: a\n    url: https://a.corp.example//sites/x\n", "single /"},
		{"only slashes", "  - id: a\n    url: https://a.corp.example//\n", "single /"},
		{"control", "  - id: a\n    url: \"https://a.corp.example/sites/\\tx\"\n", "url must be https://host/path"},
		{"server on site", "  - id: a\n    url: https://a.corp.example\n    server: windows\n", "server is only"},
		{"spn on share", "  - id: a\n    path: \\\\fs01\\a\n    spn: HTTP/fs01\n", "spn is only"},
		{"spn lower", "  - id: a\n    url: https://a.corp.example\n    spn: http/a.corp.example\n", "spn must look like"},
		{"spn service", "  - id: a\n    url: https://a.corp.example\n    spn: HOST/a.corp.example\n", "spn must look like"},
		{"spn realm", "  - id: a\n    url: https://a.corp.example\n    spn: HTTP/a.corp.example@CORP.EXAMPLE\n", "spn must look like"},
		{"spn empty host", "  - id: a\n    url: https://a.corp.example\n    spn: HTTP/\n", "spn must look like"},
		{"spn bad port", "  - id: a\n    url: https://a.corp.example\n    spn: \"HTTP/a.corp.example:\"\n", "spn must look like"},
		{"spn path", "  - id: a\n    url: https://a.corp.example\n    spn: HTTP/a.corp.example/x\n", "spn must look like"},
		{"bad exclude", "  - id: a\n    url: https://a.corp.example\n    exclude:\n      - \"[\"\n", "exclude"},
		{"duplicate id", "  - id: a\n    url: https://a.corp.example\n  - id: a\n    url: https://b.corp.example\n", "duplicate root id"},
		{"share then site", "  - id: a\n    path: \\\\fs01\\a\n  - id: b\n    url: https://b.corp.example\n", "config.yaml: roots must all be file shares or all SharePoint sites"},
		{"site then share", "  - id: a\n    url: https://a.corp.example\n  - id: b\n    path: \\\\fs01\\b\n", "config.yaml: roots must all be file shares or all SharePoint sites"},
		{"unknown field", "  - id: a\n    url: https://a.corp.example\n    site: x\n", "field site not found"},
	}
	for _, c := range refused {
		if _, err := load(c.roots); err == nil || !strings.Contains(err.Error(), "config.yaml: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

type fakeFile struct {
	data     []byte
	id       uint64
	modified time.Time
	changed  time.Time
	sd       []byte
	touch    bool
	handle   uint64
}

type fakeSource struct {
	mu              sync.Mutex
	files           map[string]*fakeFile
	shares          map[string][]byte
	accountList     []Account
	failures        map[string]error
	descriptorCalls int
	filters         []string
	authzCalls      [][]string
	tokens          map[string]Token
	memberList      map[string]Member
	negotiateErr    error
}

func newFakeSource() *fakeSource {
	return &fakeSource{files: map[string]*fakeFile{}, shares: map[string][]byte{}, failures: map[string]error{}}
}

func (s *fakeSource) add(unc, content string, sd []byte) *fakeFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := &fakeFile{data: []byte(content), id: uint64(len(s.files) + 1), modified: time.UnixMilli(1761990000000), changed: time.UnixMilli(1761990000000), sd: sd}
	s.files[unc] = f
	return f
}

func (s *fakeSource) List(dir string) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failures["list:"+dir]; err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var entries []Entry
	for unc, f := range s.files {
		rest, ok := strings.CutPrefix(unc, dir+`\`)
		if !ok {
			continue
		}
		name, _, nested := strings.Cut(rest, `\`)
		if seen[name] {
			continue
		}
		seen[name] = true
		if nested {
			entries = append(entries, Entry{Name: name, Dir: true})
			continue
		}
		entries = append(entries, Entry{Name: name, ID: f.id, Size: int64(len(f.data)), Created: f.modified, Modified: f.modified, Changed: f.changed})
	}
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return entries, nil
}

func (s *fakeSource) Descriptor(unc string) ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.descriptorCalls++
	if err := s.failures["descriptor:"+unc]; err != nil {
		return nil, 0, err
	}
	f := s.files[unc]
	if f == nil {
		return nil, 0, ErrNotFound
	}
	if f.handle != 0 {
		return f.sd, f.handle, nil
	}
	return f.sd, f.id, nil
}

func (s *fakeSource) Share(rootPath string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failures["share:"+rootPath]; err != nil {
		return nil, err
	}
	if sd, ok := s.shares[rootPath]; ok {
		return sd, nil
	}
	return readable("S-1-1-0"), nil
}

func (s *fakeSource) Accounts(filter string) ([]Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filters = append(s.filters, filter)
	if err := s.failures["accounts"]; err != nil {
		return nil, err
	}
	filter = strings.ToLower(filter)
	var found []Account
	for _, candidate := range s.accountList {
		values := append([]string{candidate.Mail, candidate.UPN}, candidate.Proxies...)
		for _, value := range values {
			if value != "" && strings.Contains(filter, "="+strings.ToLower(value)+")") {
				found = append(found, candidate)
				break
			}
		}
	}
	return found, nil
}

func (s *fakeSource) Allowed(server string, sids []string, descriptors [][]byte) ([][]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authzCalls = append(s.authzCalls, append([]string{server}, sids...))
	if err := s.failures["allowed:"+server]; err != nil {
		return nil, err
	}
	matrix := make([][]bool, len(sids))
	for k, sid := range sids {
		matrix[k] = make([]bool, len(descriptors))
		if s.failures["user:"+sid] != nil {
			continue
		}
		if token, ok := s.tokens[sid]; ok {
			for j, sd := range descriptors {
				matrix[k][j] = Grants(token, sd)
			}
			continue
		}
		for j, sd := range descriptors {
			dacl, _, _ := readACL(sd, binary.LittleEndian.Uint32(sd[16:]))
			allowed, denied := false, false
			for _, item := range dacl {
				if item.flags&0x08 != 0 || item.mask&0x1 == 0 || (item.sid != sid && item.sid != "S-1-1-0") {
					continue
				}
				allowed = allowed || item.kind == 0
				denied = denied || item.kind == 1
			}
			matrix[k][j] = allowed && !denied
		}
	}
	return matrix, nil
}

func (s *fakeSource) Open(rootPath, rel string) (File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unc := rootPath + `\` + rel
	if err := s.failures["open:"+unc]; err != nil {
		return nil, err
	}
	f := s.files[unc]
	if f == nil {
		return nil, ErrNotFound
	}
	return &fakeHandle{src: s, f: f}, nil
}

func (s *fakeSource) Members(sids []string) ([]Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failures["members"]; err != nil {
		return nil, err
	}
	members := make([]Member, len(sids))
	for i, sid := range sids {
		members[i] = s.memberList[sid]
	}
	return members, nil
}

func (s *fakeSource) Negotiate(spn string) (string, error) {
	if s.negotiateErr != nil {
		return "", s.negotiateErr
	}
	return base64.StdEncoding.EncodeToString([]byte(spn)), nil
}

type fakeHandle struct {
	src *fakeSource
	f   *fakeFile
}

func (h *fakeHandle) ReadAt(p []byte, off int64) (int, error) {
	h.src.mu.Lock()
	defer h.src.mu.Unlock()
	if h.f.touch {
		h.f.modified = h.f.modified.Add(time.Nanosecond)
	}
	return bytes.NewReader(h.f.data).ReadAt(p, off)
}

func (h *fakeHandle) Close() error {
	return nil
}

func (h *fakeHandle) Info() (FileInfo, error) {
	h.src.mu.Lock()
	defer h.src.mu.Unlock()
	return FileInfo{ID: h.f.id, Size: int64(len(h.f.data)), Modified: h.f.modified}, nil
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
	pin  string
}

func newCA(t *testing.T) testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Thero Connect CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(der)
	return testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), pin: hex.EncodeToString(sum[:])}
}

func (ca testCA) issue(t *testing.T, cn string, public any, validity time.Duration, usage x509.ExtKeyUsage) (*x509.Certificate, string) {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func linkServer(t *testing.T, ca testCA, handle func(r *http.Request, conn *websocket.Conn)) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, _ := ca.issue(t, "127.0.0.1", &key.PublicKey, time.Hour, x509.ExtKeyUsageServerAuth)
	clients := x509.NewCertPool()
	clients.AddCert(ca.cert)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(16 << 20)
		handle(r, conn)
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, ca.cert.Raw}, PrivateKey: key}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clients,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return "wss://" + server.Listener.Addr().String()
}

func enrollHandler(t *testing.T, ca testCA, machine string, validity time.Duration) func(r *http.Request, conn *websocket.Conn) {
	return func(r *http.Request, conn *websocket.Conn) {
		_, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		var request enrollMessage
		json.Unmarshal(data, &request)
		block, _ := pem.Decode([]byte(request.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || request.Type != "enroll" || request.Version != 1 || request.Client != version+" "+runtime.GOOS+"/"+runtime.GOARCH || request.Token != "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE" {
			reply, _ := json.Marshal(failure(0, "enroll", "token unknown"))
			conn.Write(r.Context(), websocket.MessageText, reply)
			return
		}
		_, cert := ca.issue(t, machine, csr.PublicKey, validity, x509.ExtKeyUsageClientAuth)
		reply, _ := json.Marshal(message{Type: "enrolled", Machine: machine, Cert: cert, CA: ca.pem})
		conn.Write(r.Context(), websocket.MessageText, reply)
		conn.Close(websocket.StatusNormalClosure, "")
	}
}

func enrolledAgent(t *testing.T, ca testCA, link string, cfg config, src Source, validity time.Duration) *agent {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, certPEM := ca.issue(t, "9f1c2d3e4b5a69788796a5b4c3d2e1f0", &key.PublicKey, validity, x509.ExtKeyUsageClientAuth)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	id := identity{URL: link, Machine: cert.Subject.CommonName, Key: der, Cert: certPEM, CA: ca.pem}
	if err := writeIdentity(dir, id); err != nil {
		t.Fatal(err)
	}
	a, err := newAgent(dir, cfg, src)
	if err != nil {
		t.Fatal(err)
	}
	a.id = id
	a.cert.Store(&tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert})
	return a
}

type frame struct {
	kind websocket.MessageType
	data []byte
}

func pump(ctx context.Context, conn *websocket.Conn) chan frame {
	frames := make(chan frame, 256)
	go func() {
		defer close(frames)
		for {
			kind, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			frames <- frame{kind, data}
		}
	}()
	return frames
}

func next(t *testing.T, frames chan frame) frame {
	select {
	case f, ok := <-frames:
		if !ok {
			t.Fatal("connection closed")
		}
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("no frame within 5 seconds")
	}
	return frame{}
}

func sendJSON(t *testing.T, conn *websocket.Conn, value any) {
	data, _ := json.Marshal(value)
	if err := conn.Write(context.Background(), websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}

func linkConfig() config {
	return config{Roots: []root{{ID: "finance", Path: `\\fs01\finance`}, {ID: "hr", Path: `\\fs01\hr`}}, Limits: limits{MaxFileMB: 20, MaxGBPerDay: 50, MaxMbit: 100000}}
}

type linkTest struct {
	ca       testCA
	agent    *agent
	conn     *websocket.Conn
	request  *http.Request
	frames   chan frame
	accepted chan *linkTest
	sessions chan websocket.StatusCode
}

func startLink(t *testing.T, src Source, validity time.Duration) *linkTest {
	ca := newCA(t)
	accepted := make(chan *linkTest, 1)
	release := make(chan struct{})
	link := linkServer(t, ca, func(r *http.Request, conn *websocket.Conn) {
		accepted <- &linkTest{conn: conn, request: r, frames: pump(r.Context(), conn)}
		<-release
	})
	t.Cleanup(func() { close(release) })
	a := enrolledAgent(t, ca, link, linkConfig(), src, validity)
	lt := &linkTest{ca: ca, agent: a, accepted: accepted, sessions: make(chan websocket.StatusCode, 1)}
	lt.connect(t)
	return lt
}

func (lt *linkTest) connect(t *testing.T) {
	go func() {
		status, _ := lt.agent.session(t.Context())
		lt.sessions <- status
	}()
	select {
	case server := <-lt.accepted:
		lt.conn, lt.request, lt.frames = server.conn, server.request, server.frames
	case <-time.After(5 * time.Second):
		t.Fatal("client did not connect")
	}
	var hello helloMessage
	json.Unmarshal(next(t, lt.frames).data, &hello)
	if hello.Type != "hello" || hello.Version != 1 || hello.Client != version+" "+runtime.GOOS+"/"+runtime.GOARCH || !slices.Equal(hello.Roots, []string{"finance", "hr"}) {
		t.Fatalf("unexpected hello %+v", hello)
	}
	sendJSON(t, lt.conn, message{Type: "welcome"})
}

func (lt *linkTest) close(t *testing.T, status websocket.StatusCode) websocket.StatusCode {
	lt.conn.Close(status, "")
	select {
	case ended := <-lt.sessions:
		return ended
	case <-time.After(5 * time.Second):
		t.Fatal("session did not end")
	}
	return 0
}

func TestEnrollPinsCA(t *testing.T) {
	ca := newCA(t)
	link := linkServer(t, ca, enrollHandler(t, ca, "9f1c2d3e4b5a69788796a5b4c3d2e1f0", 30*24*time.Hour))
	dir := t.TempDir()
	if _, err := enroll(t.Context(), dir, config{}, link, strings.Repeat("ab", 32), "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE"); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	if _, err := os.Stat(statePath(dir, "identity.bin")); err == nil {
		t.Fatal("identity written after a refused handshake")
	}
	machine, err := enroll(t.Context(), dir, config{}, link, ca.pin, "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE")
	if err != nil || machine != "9f1c2d3e4b5a69788796a5b4c3d2e1f0" {
		t.Fatalf("enroll = %q, %v", machine, err)
	}
	id, cert, err := readIdentity(dir)
	if err != nil || id.URL != link || id.Machine != machine || cert.Leaf.Subject.CommonName != machine || id.CA != ca.pem {
		t.Fatalf("identity %+v, %v", id, err)
	}
}

func TestEnrollError(t *testing.T) {
	ca := newCA(t)
	link := linkServer(t, ca, enrollHandler(t, ca, "9f1c2d3e4b5a69788796a5b4c3d2e1f0", 30*24*time.Hour))
	dir := t.TempDir()
	_, err := enroll(t.Context(), dir, config{}, link, ca.pin, "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ZZZZZ")
	if err == nil || !strings.Contains(err.Error(), "enroll") {
		t.Fatalf("enroll error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "identity.bin")); err == nil {
		t.Fatal("identity written after a refusal")
	}
}

func TestHelloAndWelcome(t *testing.T) {
	lt := startLink(t, newFakeSource(), 30*24*time.Hour)
	if cn := lt.request.TLS.PeerCertificates[0].Subject.CommonName; cn != "9f1c2d3e4b5a69788796a5b4c3d2e1f0" {
		t.Fatalf("client certificate CN %q", cn)
	}
	if status := lt.close(t, 4002); status != 4002 {
		t.Fatalf("session ended with %d", status)
	}
	refusing := linkServer(t, lt.ca, func(r *http.Request, conn *websocket.Conn) {
		conn.Read(r.Context())
		sendJSON(t, conn, failure(0, "version", "unsupported version"))
		conn.Close(4001, "")
	})
	refused := enrolledAgent(t, lt.ca, refusing, linkConfig(), newFakeSource(), 30*24*time.Hour)
	if status, err := refused.session(t.Context()); status != 4001 || err == nil {
		t.Fatalf("refused hello ended with %d, %v", status, err)
	}
}

func TestRequestsAnswered(t *testing.T) {
	src := newFakeSource()
	src.add(`\\fs01\finance\Reports\q1.pdf`, "q1", readable("S-1-5-21-1-2-3-1104"))
	src.accountList = []Account{{SID: "S-1-5-21-1-2-3-1104", GUID: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d7e8", Mail: "alice@example.com", Enabled: true}}
	lt := startLink(t, src, 30*24*time.Hour)
	sendJSON(t, lt.conn, message{Type: "walk", ID: 1, Root: "finance"})
	var page pageMessage
	json.Unmarshal(next(t, lt.frames).data, &page)
	if page.Type != "page" || page.ID != 1 || page.Cursor != "" || len(page.Entries) != 1 || page.Entries[0].Path != "Reports/q1.pdf" || page.Entries[0].Class == nil {
		t.Fatalf("page %+v", page)
	}
	sendJSON(t, lt.conn, message{Type: "principals", ID: 2, Emails: []string{"alice@example.com"}})
	var users usersMessage
	json.Unmarshal(next(t, lt.frames).data, &users)
	if users.Type != "users" || users.ID != 2 || len(users.Users) != 1 || users.Users[0].SID != "S-1-5-21-1-2-3-1104" {
		t.Fatalf("users %+v", users)
	}
	sendJSON(t, lt.conn, message{Type: "access", ID: 3, SIDs: []string{"S-1-5-21-1-2-3-1104"}})
	var rights rightsMessage
	json.Unmarshal(next(t, lt.frames).data, &rights)
	if rights.Type != "rights" || rights.ID != 3 || len(rights.Classes) != 1 || !slices.Equal(rights.Classes[0].Readers, []int{0}) || rights.Classes[0].Class != *page.Entries[0].Class {
		t.Fatalf("rights %+v", rights)
	}
	sendJSON(t, lt.conn, message{Type: "walk", ID: 4, Root: "missing"})
	var refusal errorMessage
	json.Unmarshal(next(t, lt.frames).data, &refusal)
	if refusal.Type != "error" || refusal.ID != 4 || refusal.Code != "bad_request" {
		t.Fatalf("refusal %+v", refusal)
	}
}

func TestReadAckWindow(t *testing.T) {
	src := newFakeSource()
	content := bytes.Repeat([]byte("0123456789abcdef"), 6<<20/16)
	f := src.add(`\\fs01\finance\big.bin`, string(content), readable("S-1-1-0"))
	lt := startLink(t, src, 30*24*time.Hour)
	sendJSON(t, lt.conn, message{Type: "read", ID: 7, Root: "finance", Path: "big.bin", File: "0000000000000001", Size: int64(len(content)), Modified: f.modified.UnixMilli()})
	var received []byte
	for len(received) < ackWindow {
		chunk := next(t, lt.frames)
		if chunk.kind != websocket.MessageBinary || binary.BigEndian.Uint32(chunk.data) != 7 {
			t.Fatalf("unexpected frame %s", chunk.data)
		}
		received = append(received, chunk.data[4:]...)
	}
	if len(received) != ackWindow {
		t.Fatalf("received %d bytes before the first ack", len(received))
	}
	select {
	case extra := <-lt.frames:
		t.Fatalf("frame of %d bytes beyond the ack window", len(extra.data))
	case <-time.After(300 * time.Millisecond):
	}
	sendJSON(t, lt.conn, message{Type: "ack", ID: 7, Bytes: int64(len(received))})
	for {
		chunk := next(t, lt.frames)
		if chunk.kind == websocket.MessageBinary {
			received = append(received, chunk.data[4:]...)
			continue
		}
		var done doneMessage
		json.Unmarshal(chunk.data, &done)
		sum := sha256.Sum256(content)
		if done.Type != "done" || done.ID != 7 || done.SHA256 != hex.EncodeToString(sum[:]) || !bytes.Equal(received, content) {
			t.Fatalf("done %+v after %d bytes", done, len(received))
		}
		return
	}
}

func TestCancelStopsRead(t *testing.T) {
	src := newFakeSource()
	content := bytes.Repeat([]byte("x"), 6<<20)
	big := src.add(`\\fs01\finance\big.bin`, string(content), readable("S-1-1-0"))
	small := src.add(`\\fs01\finance\small.txt`, "thero", readable("S-1-1-0"))
	lt := startLink(t, src, 30*24*time.Hour)
	sendJSON(t, lt.conn, message{Type: "read", ID: 7, Root: "finance", Path: "big.bin", File: "0000000000000001", Size: int64(len(content)), Modified: big.modified.UnixMilli()})
	next(t, lt.frames)
	sendJSON(t, lt.conn, message{Type: "cancel", ID: 7})
	sendJSON(t, lt.conn, message{Type: "read", ID: 8, Root: "finance", Path: "small.txt", File: "0000000000000002", Size: 5, Modified: small.modified.UnixMilli()})
	sendJSON(t, lt.conn, message{Type: "ack", ID: 7, Bytes: int64(len(content))})
	for {
		select {
		case f := <-lt.frames:
			if f.kind == websocket.MessageBinary {
				continue
			}
			var reply message
			json.Unmarshal(f.data, &reply)
			if reply.ID != 8 || reply.Type != "done" {
				t.Fatalf("unexpected reply %s", f.data)
			}
		case <-time.After(500 * time.Millisecond):
			return
		}
	}
}

func TestRenewSwapsCertificate(t *testing.T) {
	lt := startLink(t, newFakeSource(), 5*24*time.Hour)
	var renew renewMessage
	json.Unmarshal(next(t, lt.frames).data, &renew)
	block, _ := pem.Decode([]byte(renew.CSR))
	if renew.Type != "renew" || block == nil {
		t.Fatalf("expected renew, got %+v", renew)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fresh, freshPEM := lt.ca.issue(t, lt.agent.id.Machine, csr.PublicKey, 30*24*time.Hour, x509.ExtKeyUsageClientAuth)
	sendJSON(t, lt.conn, message{Type: "renewed", Cert: freshPEM})
	deadline := time.Now().Add(5 * time.Second)
	for lt.agent.cert.Load().Leaf.SerialNumber.Cmp(fresh.SerialNumber) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("certificate not swapped")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, stored, err := readIdentity(lt.agent.dir); err != nil || stored.Leaf.SerialNumber.Cmp(fresh.SerialNumber) != 0 {
		t.Fatalf("identity not stored: %v", err)
	}
	lt.close(t, 4002)
	lt.connect(t)
	if serial := lt.request.TLS.PeerCertificates[0].SerialNumber; serial.Cmp(fresh.SerialNumber) != 0 {
		t.Fatalf("reconnect presented serial %v", serial)
	}
	quiet(t, lt.frames, 200*time.Millisecond)
}

func quiet(t *testing.T, frames chan frame, wait time.Duration) {
	select {
	case f := <-frames:
		t.Fatalf("unexpected frame %s", f.data)
	case <-time.After(wait):
	}
}

func TestReconnectBackoff(t *testing.T) {
	var delay time.Duration
	var got []time.Duration
	for range 11 {
		delay = backoff(delay, time.Second, -1)
		got = append(got, delay/time.Second)
	}
	if want := []time.Duration{1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300}; !slices.Equal(got, want) {
		t.Fatalf("sequence %v", got)
	}
	if backoff(300*time.Second, time.Minute, 1006) != time.Second {
		t.Fatal("a session of 60 seconds did not reset the delay")
	}
	if backoff(time.Second, time.Second, 4001) != 300*time.Second || backoff(4*time.Second, time.Hour, 4001) != 300*time.Second {
		t.Fatal("close 4001 did not wait 300 seconds")
	}
}

func TestServerCertificateMustChainToCA(t *testing.T) {
	trusted := newCA(t)
	other := newCA(t)
	reached := false
	link := linkServer(t, other, func(r *http.Request, conn *websocket.Conn) { reached = true })
	a := enrolledAgent(t, trusted, link, linkConfig(), newFakeSource(), 30*24*time.Hour)
	if _, err := a.session(t.Context()); err == nil || reached {
		t.Fatalf("session against a foreign server: %v, reached %v", err, reached)
	}
	if _, err := enroll(t.Context(), t.TempDir(), config{}, link, trusted.pin, "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE"); err == nil {
		t.Fatal("enroll accepted a server of another CA")
	}
}

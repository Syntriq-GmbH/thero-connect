package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type enrollMessage struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	Token   string `json:"token"`
	CSR     string `json:"csr"`
	Machine string `json:"machine"`
	Client  string `json:"client"`
}

type helloMessage struct {
	Type    string   `json:"type"`
	Version int      `json:"version"`
	Client  string   `json:"client"`
	Machine string   `json:"machine"`
	Roots   []string `json:"roots"`
}

type pageMessage struct {
	Type       string      `json:"type"`
	ID         int64       `json:"id"`
	Cursor     string      `json:"cursor"`
	Entries    []pageEntry `json:"entries"`
	Incomplete []string    `json:"incomplete"`
}

type pageEntry struct {
	Path     string  `json:"path"`
	File     string  `json:"file"`
	Size     int64   `json:"size"`
	Created  int64   `json:"created"`
	Modified int64   `json:"modified"`
	Class    *string `json:"class"`
}

type usersMessage struct {
	Type  string `json:"type"`
	ID    int64  `json:"id"`
	Users []user `json:"users"`
}

type user struct {
	Email     string `json:"email"`
	SID       string `json:"sid"`
	GUID      string `json:"guid"`
	UPN       string `json:"upn"`
	Mail      string `json:"mail"`
	Enabled   bool   `json:"enabled"`
	Ambiguous bool   `json:"ambiguous"`
}

type rightsMessage struct {
	Type    string         `json:"type"`
	ID      int64          `json:"id"`
	Classes []classReaders `json:"classes"`
	Errors  []rootError    `json:"errors"`
}

type classReaders struct {
	Class   string `json:"class"`
	Readers []int  `json:"readers"`
}

type rootError struct {
	Root string `json:"root"`
	Code string `json:"code"`
}

type doneMessage struct {
	Type   string `json:"type"`
	ID     int64  `json:"id"`
	SHA256 string `json:"sha256"`
}

type renewMessage struct {
	Type string `json:"type"`
	CSR  string `json:"csr"`
}

type errorMessage struct {
	Type    string `json:"type"`
	ID      int64  `json:"id"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type message struct {
	Type     string   `json:"type"`
	ID       int64    `json:"id"`
	Root     string   `json:"root"`
	Cursor   string   `json:"cursor"`
	Path     string   `json:"path"`
	File     string   `json:"file"`
	Size     int64    `json:"size"`
	Modified int64    `json:"modified"`
	Bytes    int64    `json:"bytes"`
	Emails   []string `json:"emails"`
	SIDs     []string `json:"sids"`
	Machine  string   `json:"machine"`
	Cert     string   `json:"cert"`
	CA       string   `json:"ca"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

type identity struct {
	URL     string `json:"url"`
	Machine string `json:"machine"`
	Key     []byte `json:"key"`
	Cert    string `json:"cert"`
	CA      string `json:"ca"`
}

func httpClient(cfg config, tlsConfig *tls.Config) *http.Client {
	proxy := http.ProxyFromEnvironment
	if cfg.Proxy != "" {
		address, _ := url.Parse(cfg.Proxy)
		proxy = http.ProxyURL(address)
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: proxy, TLSClientConfig: tlsConfig}}
}

func newKey() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	host, _ := os.Hostname()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}}, key)
	if err != nil {
		return nil, "", err
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}

func parseCertificate(text string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func issued(text string, ca *x509.Certificate, key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	cert, err := parseCertificate(text)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("certificate does not match the key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, err
	}
	return cert, nil
}

func writeIdentity(dir string, id identity) error {
	data, err := json.Marshal(id)
	if err != nil {
		return err
	}
	sealed, err := protect(data)
	if err != nil {
		return err
	}
	return writeFile(statePath(dir, "identity.bin"), sealed)
}

func readIdentity(dir string) (identity, *tls.Certificate, error) {
	sealed, err := os.ReadFile(statePath(dir, "identity.bin"))
	if errors.Is(err, fs.ErrNotExist) {
		return identity{}, nil, errors.New("run enroll first")
	}
	if err != nil {
		return identity{}, nil, err
	}
	data, err := unprotect(sealed)
	if err != nil {
		return identity{}, nil, err
	}
	var id identity
	if err := json.Unmarshal(data, &id); err != nil {
		return identity{}, nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(id.Key)
	if err != nil {
		return identity{}, nil, err
	}
	leaf, err := parseCertificate(id.Cert)
	if err != nil {
		return identity{}, nil, err
	}
	return id, &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

func enroll(ctx context.Context, dir string, cfg config, link, pin, token string) (string, error) {
	address, err := url.Parse(link)
	if err != nil || address.Scheme != "wss" || address.Host == "" || address.Path != "" {
		return "", errors.New("-url must be wss://host[:port]")
	}
	if _, err := hex.DecodeString(pin); err != nil || len(pin) != 64 {
		return "", errors.New("-ca must be 64 hex characters")
	}
	key, csr, err := newKey()
	if err != nil {
		return "", err
	}
	verify := func(state tls.ConnectionState) error {
		for _, candidate := range state.PeerCertificates {
			sum := sha256.Sum256(candidate.Raw)
			if hex.EncodeToString(sum[:]) != pin {
				continue
			}
			roots := x509.NewCertPool()
			roots.AddCert(candidate)
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, DNSName: address.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}
		return errors.New("server certificate does not match the -ca fingerprint")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: verify}
	conn, _, err := websocket.Dial(ctx, link+"/enroll", &websocket.DialOptions{HTTPClient: httpClient(cfg, tlsConfig)})
	if err != nil {
		return "", err
	}
	defer conn.CloseNow()
	host, _ := os.Hostname()
	request, _ := json.Marshal(enrollMessage{Type: "enroll", Version: 1, Token: token, CSR: csr, Machine: host, Client: version})
	if err := conn.Write(ctx, websocket.MessageText, request); err != nil {
		return "", err
	}
	readCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, data, err := conn.Read(readCtx)
	if err != nil {
		return "", err
	}
	var reply message
	if err := json.Unmarshal(data, &reply); err != nil {
		return "", err
	}
	if reply.Type == "error" {
		return "", fmt.Errorf("enrollment refused: %s", reply.Code)
	}
	if reply.Type != "enrolled" {
		return "", fmt.Errorf("unexpected %q reply", reply.Type)
	}
	conn.Close(websocket.StatusNormalClosure, "")
	ca, err := parseCertificate(reply.CA)
	if err != nil {
		return "", err
	}
	if sum := sha256.Sum256(ca.Raw); hex.EncodeToString(sum[:]) != pin {
		return "", errors.New("issuing certificate does not match the -ca fingerprint")
	}
	cert, err := issued(reply.Cert, ca, key)
	if err != nil {
		return "", err
	}
	if cert.Subject.CommonName != reply.Machine {
		return "", errors.New("certificate does not name the machine")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := writeIdentity(dir, identity{URL: link, Machine: reply.Machine, Key: der, Cert: reply.Cert, CA: reply.CA}); err != nil {
		return "", err
	}
	slog.Info("enrolled", "machine", reply.Machine)
	return reply.Machine, nil
}

func backoff(delay, lasted time.Duration, status websocket.StatusCode) time.Duration {
	if status == 4001 {
		return 300 * time.Second
	}
	if delay == 0 || lasted >= time.Minute {
		return time.Second
	}
	return min(delay*2, 300*time.Second)
}

func serve(ctx context.Context, dir string, cfg config, src source) error {
	id, cert, err := readIdentity(dir)
	if err != nil {
		return err
	}
	a, err := newAgent(dir, cfg, src)
	if err != nil {
		return err
	}
	a.id = id
	a.cert.Store(cert)
	slog.Info("start", "version", version, "machine", id.Machine, "roots", len(cfg.Roots))
	var delay time.Duration
	for {
		started := time.Now()
		status, err := a.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("link closed", "code", int(status), "error", err)
		delay = backoff(delay, time.Since(started), status)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay*8/10 + mathrand.N(delay*4/10+1)):
		}
	}
}

func (a *agent) dial(ctx context.Context) (*websocket.Conn, error) {
	ca, err := parseCertificate(a.id.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	current := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return a.cert.Load(), nil }
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, GetClientCertificate: current}
	conn, _, err := websocket.Dial(ctx, a.id.URL+"/link", &websocket.DialOptions{HTTPClient: httpClient(a.cfg, tlsConfig)})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(16 << 20)
	return conn, nil
}

func (a *agent) session(ctx context.Context) (websocket.StatusCode, error) {
	if a.cert.Load().Leaf.NotAfter.Before(a.now()) {
		slog.Error("certificate expired, enroll again")
		return 4001, errors.New("certificate expired")
	}
	conn, err := a.dial(ctx)
	if err != nil {
		return -1, err
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	send := func(value any) error {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return conn.Write(ctx, websocket.MessageText, data)
	}
	host, _ := os.Hostname()
	roots := make([]string, 0, len(a.cfg.Roots))
	for _, r := range a.cfg.Roots {
		roots = append(roots, r.ID)
	}
	if err := send(helloMessage{Type: "hello", Version: 1, Client: version, Machine: host, Roots: roots}); err != nil {
		return websocket.CloseStatus(err), err
	}
	welcomeCtx, welcomeCancel := context.WithTimeout(ctx, 30*time.Second)
	defer welcomeCancel()
	_, data, err := conn.Read(welcomeCtx)
	if err != nil {
		return websocket.CloseStatus(err), err
	}
	var welcome message
	json.Unmarshal(data, &welcome)
	if welcome.Type != "welcome" {
		_, _, err := conn.Read(welcomeCtx)
		return websocket.CloseStatus(err), fmt.Errorf("link refused: %s", welcome.Code)
	}
	slog.Info("connected", "machine", a.id.Machine)
	a.mu.Lock()
	a.renewal = nil
	a.mu.Unlock()
	a.renew(send)
	go func() {
		ping := time.NewTicker(30 * time.Second)
		defer ping.Stop()
		renewal := time.NewTicker(time.Hour)
		defer renewal.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-renewal.C:
				a.renew(send)
			case <-ping.C:
				pingCtx, pingCancel := context.WithTimeout(ctx, 30*time.Second)
				err := conn.Ping(pingCtx)
				pingCancel()
				if err != nil {
					conn.CloseNow()
					return
				}
			}
		}
	}()
	var readsMu sync.Mutex
	reads := map[int64]*transfer{}
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			return websocket.CloseStatus(err), err
		}
		var m message
		if kind != websocket.MessageText || json.Unmarshal(data, &m) != nil {
			slog.Warn("ignored invalid frame")
			continue
		}
		switch m.Type {
		case "walk":
			go func() { send(a.walk(m)) }()
		case "principals":
			go func() { send(a.principals(m)) }()
		case "access":
			go func() { send(a.access(m)) }()
		case "read":
			readCtx, stop := context.WithCancel(ctx)
			t := &transfer{notify: make(chan struct{}, 1), stop: stop}
			readsMu.Lock()
			reads[m.ID] = t
			readsMu.Unlock()
			go func() {
				defer stop()
				reply := a.read(readCtx, m, t, func(frame []byte) error { return conn.Write(ctx, websocket.MessageBinary, frame) })
				readsMu.Lock()
				delete(reads, m.ID)
				readsMu.Unlock()
				if reply != nil {
					send(reply)
				}
			}()
		case "ack", "cancel":
			readsMu.Lock()
			t := reads[m.ID]
			readsMu.Unlock()
			if t == nil {
				continue
			}
			if m.Type == "cancel" {
				t.stop()
				continue
			}
			if m.Bytes > t.acked.Load() {
				t.acked.Store(m.Bytes)
			}
			select {
			case t.notify <- struct{}{}:
			default:
			}
		case "renewed":
			a.renewed(m)
		case "error":
			slog.Warn("server error", "id", m.ID, "code", m.Code)
			if m.Code == "renew" {
				a.mu.Lock()
				a.renewal = nil
				a.mu.Unlock()
			}
		default:
			slog.Warn("ignored message", "type", m.Type)
		}
	}
}

func (a *agent) renew(send func(any) error) {
	a.mu.Lock()
	due := a.renewal == nil && a.cert.Load().Leaf.NotAfter.Sub(a.now()) < 10*24*time.Hour
	a.mu.Unlock()
	if !due {
		return
	}
	key, csr, err := newKey()
	if err != nil {
		slog.Error("renewal failed", "error", err)
		return
	}
	a.mu.Lock()
	a.renewal = key
	a.mu.Unlock()
	if err := send(renewMessage{Type: "renew", CSR: csr}); err != nil {
		slog.Warn("renewal not sent", "error", err)
	}
}

func (a *agent) renewed(m message) {
	a.mu.Lock()
	key := a.renewal
	a.renewal = nil
	a.mu.Unlock()
	if key == nil {
		slog.Warn("unexpected renewed certificate")
		return
	}
	ca, err := parseCertificate(a.id.CA)
	if err != nil {
		slog.Error("renewal rejected", "error", err)
		return
	}
	cert, err := issued(m.Cert, ca, key)
	if err != nil {
		slog.Error("renewal rejected", "error", err)
		return
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		slog.Error("renewal rejected", "error", err)
		return
	}
	id := a.id
	id.Key = der
	id.Cert = m.Cert
	if err := writeIdentity(a.dir, id); err != nil {
		slog.Error("renewal not stored", "error", err)
		return
	}
	a.id = id
	a.cert.Store(&tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert})
	slog.Info("certificate renewed", "expires", cert.NotAfter)
}

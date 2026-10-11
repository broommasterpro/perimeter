package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"perimeter/internal/ca"
	"perimeter/internal/mux"
)

type fixture struct {
	root     *ca.CA
	hub      *Hub
	addr     string
	roots    *x509.CertPool
	ctx      context.Context
	app      *httptest.Server
	requests atomic.Uint64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	c, err := ca.New("root")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := ParseRegistry([]byte(`{"connectors":[{"id":"dc-1","apps":["wiki"]},{"id":"dc-2","apps":["other"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{root: c, hub: NewHub(reg), roots: x509.NewCertPool()}
	f.roots.AddCert(c.Cert)
	f.app = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.Path == "/slow" {
			w.Header().Set("Content-Length", "1000000")
			if _, err := io.WriteString(w, "first"); err != nil {
				panic(http.ErrAbortHandler)
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if _, err := io.WriteString(w, "internal app"); err != nil {
			panic(http.ErrAbortHandler)
		}
	}))
	cert, key, err := c.IssueServer("127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", ConnectorTLSConfig(c.Cert, pair))
	if err != nil {
		t.Fatal(err)
	}
	f.addr = listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	f.ctx = ctx
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				err := f.hub.Accept(ctx, conn.(*tls.Conn))
				if err == nil {
					t.Error("session ended without reason")
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		<-done
		if err := f.hub.Close(); err != nil {
			t.Error(err)
		}
		workers.Wait()
		f.app.Close()
	})
	return f
}
func (f *fixture) certificate(t *testing.T, id string, ttl time.Duration) tls.Certificate {
	t.Helper()
	cert, key, err := f.root.IssueConnector(id, ttl)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
func (f *fixture) run(t *testing.T, id string, ttl time.Duration) *Connector {
	t.Helper()
	c := &Connector{Address: f.addr, TLSConfig: &tls.Config{RootCAs: f.roots, ServerName: "127.0.0.1"}, Apps: map[string]string{"wiki": strings.TrimPrefix(f.app.URL, "http://"), "other": strings.TrimPrefix(f.app.URL, "http://")}, MinBackoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond}
	c.Certificate = func() (tls.Certificate, error) {
		cert, key, err := f.root.IssueConnector(id, ttl)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(cert, key)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	eventually(t, func() bool { f.hub.mu.Lock(); defer f.hub.mu.Unlock(); return f.hub.sessions[id] != nil })
	return c
}
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	end := time.Now().Add(6 * time.Second)
	for time.Now().Before(end) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition timed out")
}
func (f *fixture) get(t *testing.T) string {
	t.Helper()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return f.hub.Dial(ctx, "wiki") }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("http://wiki/")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return string(data)
}
func TestRegistry(t *testing.T) {
	for _, data := range []string{`{"oops":1}`, `{"connectors":[{"id":"","apps":[]}]}`, `{"connectors":[{"id":"x"},{"id":"x"}]}`, `{"connectors":[{"id":"x","apps":["127.0.0.1:80"]}]}`} {
		if _, err := ParseRegistry([]byte(data)); err == nil {
			t.Fatal("bad registry accepted")
		}
	}
}
func TestRegistryAndLocalAllowlist(t *testing.T) {
	f := newFixture(t)
	c := f.run(t, "dc-1", time.Minute)
	if got := f.get(t); got != "internal app" {
		t.Fatal(got)
	}
	cBefore := c.Opens.Load()
	if _, err := f.hub.Dial(f.ctx, "deploy"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if c.Opens.Load() != cBefore {
		t.Fatal("unregistered app opened")
	}
	f.hub.mu.Lock()
	s := f.hub.sessions["dc-1"]
	f.hub.mu.Unlock()
	st, err := s.OpenStream(f.ctx, "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer closeConnection(st)
	if err := st.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Read(make([]byte, 1)); err == nil {
		t.Fatal("local allowlist bypass")
	}
}
func TestReconnectRevokeExpiry(t *testing.T) {
	f := newFixture(t)
	c := f.run(t, "dc-1", 2*time.Second)
	if f.get(t) != "internal app" {
		t.Fatal("initial request")
	}
	eventually(t, func() bool { return c.Connections.Load() >= 2 })
	t.Logf("expiry forced fresh connection; connections=%d", c.Connections.Load())
	f.hub.mu.Lock()
	s := f.hub.sessions["dc-1"]
	f.hub.mu.Unlock()
	before := c.Connections.Load()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.Connections.Load() > before })
	eventually(t, func() bool { f.hub.mu.Lock(); defer f.hub.mu.Unlock(); return f.hub.sessions["dc-1"] != nil })
	if f.get(t) != "internal app" {
		t.Fatal("reconnect failed")
	}
	if err := f.hub.Revoke("dc-1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := f.hub.Dial(f.ctx, "wiki"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("revoked connector routed")
	}
	f.hub.Unrevoke("dc-1")
	eventually(t, func() bool { f.hub.mu.Lock(); defer f.hub.mu.Unlock(); return f.hub.sessions["dc-1"] != nil })
	if f.get(t) != "internal app" {
		t.Fatal("unrevoke failed")
	}
}
func TestReplacementAndRole(t *testing.T) {
	f := newFixture(t)
	dial := func(pair tls.Certificate) *mux.Session {
		t.Helper()
		conn, err := tls.Dial("tcp", f.addr, &tls.Config{RootCAs: f.roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		s := mux.NewSession(conn, mux.Config{})
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
		return s
	}
	first := dial(f.certificate(t, "dc-1", time.Minute))
	eventually(t, func() bool { f.hub.mu.Lock(); defer f.hub.mu.Unlock(); return f.hub.sessions["dc-1"] != nil })
	second := dial(f.certificate(t, "dc-1", time.Minute))
	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("old connector not replaced")
	}
	select {
	case <-second.Done():
		t.Fatal("new connector closed")
	default:
	}
	cert, key, err := f.root.Issue("user", "connector", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	user := dial(pair)
	select {
	case <-user.Done():
		t.Log("user with group connector rejected")
	case <-time.After(time.Second):
		t.Fatal("user registered as connector")
	}
}
func TestConnectorHasNoListener(t *testing.T) {
	data, err := os.ReadFile("connector.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "net.Listen") {
		t.Fatal("connector opens inbound listener")
	}
	entries, err := os.ReadDir("../../cmd/connector")
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") {
			data, err := os.ReadFile("../../cmd/connector/" + entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "net.Listen") {
				t.Fatal("connector command opens inbound listener")
			}
		}
	}
}

func TestFailureIsolation(t *testing.T) {
	f := newFixture(t)
	f.run(t, "dc-1", time.Minute)
	f.run(t, "dc-2", time.Minute)
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return f.hub.Dial(ctx, "wiki") }}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("http://wiki/slow")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.hub.Revoke("dc-1"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if closeErr != nil {
		t.Error(closeErr)
	}
	if readErr == nil || time.Since(started) > time.Second {
		t.Fatalf("mid-response error=%v delay=%v", readErr, time.Since(started))
	}
	other := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return f.hub.Dial(ctx, "other") }}
	defer other.CloseIdleConnections()
	client.Transport = other
	response, err = client.Get("http://other/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	closeErr = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if string(body) != "internal app" {
		t.Fatal(string(body))
	}
	t.Logf("mid-response failure: %v; unrelated connector still serves", readErr)
}

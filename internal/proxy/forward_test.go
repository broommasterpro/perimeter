package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"perimeter/internal/ca"
	"perimeter/internal/policy"
	"perimeter/internal/tunnel"
)

type fullFixture struct {
	client      *http.Client
	url, direct string
	hub         *tunnel.Hub
	connector   *tunnel.Connector
	requests    atomic.Uint64
	cancelled   chan struct{}
}

func fullProxy(t testing.TB) *fullFixture {
	t.Helper()
	f := &fullFixture{cancelled: make(chan struct{}, 1)}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.Path == "/wait" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			f.cancelled <- struct{}{}
			return
		}
		body := "real app: " + r.URL.Path + " user=" + r.Header.Get("X-Perimeter-User") + " group=" + r.Header.Get("X-Perimeter-Group") + " posture=" + r.Header.Get("X-Device-Posture")
		if _, err := io.WriteString(w, body); err != nil {
			panic(http.ErrAbortHandler)
		}
	}))
	t.Cleanup(app.Close)
	f.direct = app.URL
	root, err := ca.New("test-root")
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := root.IssueServer("127.0.0.1", time.Hour)
	serverPair := testPair(t, cert, key, err)
	registry, err := tunnel.ParseRegistry([]byte(`{"connectors":[{"id":"dc-1","apps":["payroll","wiki"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f.hub = tunnel.NewHub(registry)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tunnel.ConnectorTLSConfig(root.Cert, serverPair))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	hubDone := make(chan error, 1)
	go func() { hubDone <- f.hub.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-hubDone; err != nil {
			t.Error(err)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	cert, key, err = root.IssueConnector("dc-1", time.Minute)
	connectorPair := testPair(t, cert, key, err)
	f.connector = &tunnel.Connector{Address: listener.Addr().String(), TLSConfig: &tls.Config{RootCAs: roots}, Certificate: func() (tls.Certificate, error) { return connectorPair, nil }, Apps: map[string]string{"payroll": strings.TrimPrefix(app.URL, "http://"), "wiki": strings.TrimPrefix(app.URL, "http://")}, MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}
	connectorCtx, connectorCancel := context.WithCancel(ctx)
	connectorDone := make(chan error, 1)
	go func() { connectorDone <- f.connector.Run(connectorCtx) }()
	t.Cleanup(func() {
		connectorCancel()
		if err := <-connectorDone; err != nil {
			t.Error(err)
		}
	})
	ready := false
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
		stream, err := f.hub.Dial(ctx, "wiki")
		if err == nil {
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			ready = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ready {
		t.Fatal("connector not ready")
	}
	p, err := policy.Load("../../policy.json")
	if err != nil {
		t.Fatal(err)
	}
	config, err := NewTLSConfig(root.Cert, certFromPair(t, serverPair), keyFromPair(t, serverPair))
	if err != nil {
		t.Fatal(err)
	}
	f.url = "https://" + startServer(t, config, Handler(policy.NewStore(p), HeaderPosture{}, slog.New(slog.NewTextHandler(io.Discard, nil)), f.hub))
	cert, key, err = root.Issue("aisha", "finance", time.Minute)
	clientPair := testPair(t, cert, key, err)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientPair}, MinVersion: tls.VersionTLS13}, MaxConnsPerHost: 1}
	t.Cleanup(transport.CloseIdleConnections)
	f.client = &http.Client{Transport: transport, Timeout: 3 * time.Second}
	return f
}
func certFromPair(t testing.TB, pair tls.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
}
func keyFromPair(t testing.TB, pair tls.Certificate) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(pair.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func fullRequest(t testing.TB, f *fullFixture, path, posture string) (int, string, httptrace.GotConnInfo) {
	t.Helper()
	request, err := http.NewRequest("GET", f.url+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Device-Posture", posture)
	request.Header.Set("X-Perimeter-User", "admin")
	request.Header.Set("X-Perimeter-Group", "admin")
	var info httptrace.GotConnInfo
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(got httptrace.GotConnInfo) { info = got }}))
	response, err := f.client.Do(request)
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
	return response.StatusCode, string(data), info
}

func TestForwarding(t *testing.T) {
	f := fullProxy(t)
	good := `{"disk_encrypted":true,"firewall_on":true}`
	status, body, first := fullRequest(t, f, "/apps/payroll/report", good)
	if status != 200 || body != "real app: /report user=aisha group=finance posture=" {
		t.Fatalf("got %d %q", status, body)
	}
	beforeRequests, beforeOpens := f.requests.Load(), f.connector.Opens.Load()
	for _, path := range []string{"/apps/payroll", "/apps/deploy", "/apps/unknown"} {
		posture := good
		if path == "/apps/payroll" {
			posture = `{}`
		}
		status, body, next := fullRequest(t, f, path, posture)
		if status != 403 || body != "denied" || !next.Reused || next.Conn != first.Conn {
			t.Fatalf("denial/reuse: %d %q %+v", status, body, next)
		}
	}
	if f.requests.Load() != beforeRequests || f.connector.Opens.Load() != beforeOpens {
		t.Fatal("denied request reached connector or app")
	}
	t.Logf("real response=%q; denied requests added OPENs=%d app_requests=%d; same user connection reused", "real app: /report user=aisha group=finance posture=", f.connector.Opens.Load()-beforeOpens, f.requests.Load()-beforeRequests)
	if err := f.hub.Revoke("dc-1"); err != nil {
		t.Fatal(err)
	}
	status, body, _ = fullRequest(t, f, "/apps/payroll", good)
	if status != 503 || body != "unavailable" {
		t.Fatalf("unavailable: %d %q", status, body)
	}
}

func TestCancellationClosesBackend(t *testing.T) {
	f := fullProxy(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", f.url+"/apps/wiki/wait", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := response.Body.Close(); err != nil && !errors.Is(err, context.Canceled) {
		t.Error(err)
	}
	select {
	case <-f.cancelled:
		t.Log("user cancellation closed internal TCP connection")
	case <-time.After(time.Second):
		t.Fatal("backend did not see cancellation")
	}
}

func TestConnectorFailureThroughProxy(t *testing.T) {
	baseline := runtime.NumGoroutine()
	t.Run("active requests", func(t *testing.T) {
		broken, healthy := fullProxy(t), fullProxy(t)
		request, err := http.NewRequest("GET", broken.url+"/apps/wiki/wait", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := broken.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := broken.hub.Revoke("dc-1"); err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { _, err := io.ReadAll(response.Body); ended <- err }()
		select {
		case err := <-ended:
			if err == nil {
				t.Error("truncated response succeeded")
			}
			t.Logf("user response failed promptly: %v", err)
		case <-time.After(time.Second):
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
			<-ended
			t.Fatal("user response hung")
		}
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
		status, body, _ := fullRequest(t, healthy, "/apps/wiki/report", `{}`)
		if status != 200 || !strings.Contains(body, "real app:") {
			t.Fatalf("unrelated connector: %d %q", status, body)
		}
	})
	for end := time.Now().Add(2 * time.Second); runtime.NumGoroutine() > baseline && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		t.Fatalf("goroutines baseline=%d after=%d", baseline, got)
	}
	t.Logf("goroutines returned to baseline=%d", baseline)
}

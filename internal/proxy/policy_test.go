package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sync"
	"testing"
	"time"

	"perimeter/internal/policy"
)

type captureHandler struct {
	slog.Handler
	mu      sync.Mutex
	reasons []string
}

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == "reason" {
			h.reasons = append(h.reasons, a.Value.String())
		}
		return true
	})
	return nil
}

func (h *captureHandler) hasReason(reason string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, got := range h.reasons {
		if got == reason {
			return true
		}
	}
	return false
}

func policyClient(t *testing.T) (*http.Client, string, *policy.Store, *captureHandler) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	c := testCA(t, at)
	cert, key, err := c.IssueServer("127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := NewTLSConfig(c.Cert, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	conf.Time = func() time.Time { return at }
	p, err := policy.Load("../../policy.json")
	if err != nil {
		t.Fatal(err)
	}
	store := policy.NewStore(p)
	logs := &captureHandler{Handler: slog.NewJSONHandler(io.Discard, nil)}
	addr := startServer(t, conf, Handler(store, HeaderPosture{}, slog.New(logs), testUpstream(t)))
	cert, key, err = c.Issue("aisha", "finance", 0)
	pair := testPair(t, cert, key, err)
	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, Time: func() time.Time { return at }},
		MaxConnsPerHost: 1,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, "https://" + addr, store, logs
}

func policyRequest(t *testing.T, client *http.Client, url, posture string) (int, string, httptrace.GotConnInfo) {
	t.Helper()
	var connection httptrace.GotConnInfo
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Device-Posture", posture)
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { connection = info }}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return response.StatusCode, string(body), connection
}

func TestPolicyRequests(t *testing.T) {
	client, url, _, logs := policyClient(t)
	for _, tc := range []struct {
		name, path, posture string
		status              int
		body                string
	}{
		{"allow", "/apps/payroll", `{"disk_encrypted":true,"firewall_on":true}`, 200, "allowed: aisha -> payroll"},
		{"bad posture", "/apps/payroll", `{"disk_encrypted":false,"firewall_on":true}`, 403, "denied"},
		{"unknown app", "/apps/hr2", `{}`, 403, "denied"},
		{"outside path", "/other", `{}`, 403, "denied"},
		{"empty app", "/apps/", `{}`, 403, "denied"},
		{"extra path", "/apps/wiki/more", `{}`, 200, "allowed: aisha -> wiki"},
		{"missing posture", "/apps/payroll", "", 403, "denied"},
		{"malformed posture", "/apps/payroll", `{"disk_encrypted":true,`, 403, "denied"},
		{"wiki no posture", "/apps/wiki", "", 200, "allowed: aisha -> wiki"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := policyRequest(t, client, url+tc.path, tc.posture)
			if status != tc.status || body != tc.body {
				t.Fatalf("got %d %q", status, body)
			}
		})
	}
	if !logs.hasReason("missing posture: disk_encrypted") {
		t.Fatal("detailed denial not logged")
	}
	knownStatus, knownBody, _ := policyRequest(t, client, url+"/apps/payroll", `{}`)
	unknownStatus, unknownBody, _ := policyRequest(t, client, url+"/apps/hr2", `{}`)
	if knownStatus != unknownStatus || knownBody != unknownBody {
		t.Fatal("denial reveals app existence")
	}
}

func TestConnectionReuseAndReload(t *testing.T) {
	client, url, store, _ := policyClient(t)
	good := `{"disk_encrypted":true,"firewall_on":true}`
	status, body, first := policyRequest(t, client, url+"/apps/payroll", good)
	if status != 200 {
		t.Fatalf("initial: %d %q", status, body)
	}
	var original net.Conn = first.Conn
	if original == nil || first.Reused {
		t.Fatal("expected fresh initial connection")
	}
	status, body, second := policyRequest(t, client, url+"/apps/payroll", `{"disk_encrypted":false,"firewall_on":true}`)
	if status != 403 || body != "denied" || !second.Reused || second.Conn != original {
		t.Fatal("posture not reevaluated on same connection")
	}
	t.Logf("posture changed: first=200 second=%d reused=%v same_connection=%v", status, second.Reused, second.Conn == original)
	status, _, third := policyRequest(t, client, url+"/apps/payroll", good)
	if status != 200 || !third.Reused || third.Conn != original {
		t.Fatal("good posture did not restore access on same connection")
	}
	path := t.TempDir() + "/policy.json"
	if err := os.WriteFile(path, []byte(`{"rules":[{"app":"payroll","groups":["engineering"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	status, body, fourth := policyRequest(t, client, url+"/apps/payroll", good)
	if status != 403 || body != "denied" || !fourth.Reused || fourth.Conn != original {
		t.Fatal("reload did not revoke on same connection")
	}
	t.Logf("policy revoked: status=%d reused=%v same_connection=%v", status, fourth.Reused, fourth.Conn == original)
}

func TestConnectorRejectedByUserListener(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	c := testCA(t, at)
	cert, key, err := c.IssueServer("127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := NewTLSConfig(c.Cert, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	conf.Time = func() time.Time { return at }
	addr := startServer(t, conf)
	cert, key, err = c.IssueConnector("dc-1", time.Minute)
	pair := testPair(t, cert, key, err)
	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, Time: func() time.Time { return at }}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("https://" + addr + "/apps/wiki")
	if response != nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("connector received HTTP response")
	}
	if err == nil {
		t.Fatal("connector accepted as user")
	}
	t.Log(err)
}

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"perimeter/internal/ca"
	"perimeter/internal/policy"
)

func testCA(t testing.TB, at time.Time) *ca.CA {
	t.Helper()
	c, err := ca.New("perimeter-root")
	if err != nil {
		t.Fatal(err)
	}
	c.Now = func() time.Time { return at }
	return c
}

func testPair(t testing.TB, cert, key []byte, err error) tls.Certificate {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func startServer(t testing.TB, conf *tls.Config, handlers ...http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(listener.Addr().String(), conf)
	p, err := policy.Load("../../policy.json")
	if err != nil {
		t.Fatal(err)
	}
	server.Handler = Handler(policy.NewStore(p), HeaderPosture{}, nil, testUpstream(t))
	if len(handlers) > 0 {
		server.Handler = handlers[0]
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ServeTLS: %v", err)
		}
	})
	return listener.Addr().String()
}

func TestMTLS(t *testing.T) {
	// A shared future clock leaves room to issue an expired leaf under a fresh root.
	at := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	real, foreign := testCA(t, at), testCA(t, at)
	cert, key, err := real.IssueServer("127.0.0.1", time.Hour)
	serverPair := testPair(t, cert, key, err)
	serverConf, err := NewTLSConfig(real.Cert, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	serverConf.Time = func() time.Time { return at }
	addr := startServer(t, serverConf)

	cert, key, err = real.Issue("aisha", "finance", 0)
	valid := testPair(t, cert, key, err)
	real.Now = func() time.Time { return at.Add(-11 * time.Minute) }
	cert, key, err = real.Issue("aisha", "finance", 10*time.Minute)
	expired := testPair(t, cert, key, err)
	real.Now = func() time.Time { return at }
	expiredLeaf, err := x509.ParseCertificate(expired.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verification time=%s; expired NotAfter=%s", at.Format(time.RFC3339), expiredLeaf.NotAfter.Format(time.RFC3339))

	cert, key, err = foreign.Issue("aisha", "finance", 0)
	foreignPair := testPair(t, cert, key, err)
	cert, key, err = foreign.IssueServer("127.0.0.1", time.Hour)
	fakeConf, err := NewTLSConfig(real.Cert, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	fakeConf.Time = func() time.Time { return at }
	fakeAddr := startServer(t, fakeConf)
	roots := x509.NewCertPool()
	roots.AddCert(real.Cert)

	for _, tc := range []struct {
		name   string
		addr   string
		pair   *tls.Certificate
		wantOK bool
	}{
		{"valid", addr, &valid, true},
		{"no_card", addr, nil, false},
		{"expired", addr, &expired, false},
		{"foreign_CA", addr, &foreignPair, false},
		{"fake_proxy", fakeAddr, &valid, false},
		{"wrong_usage", addr, &serverPair, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, Time: func() time.Time { return at }}
			if tc.pair != nil {
				// Force presentation even if the advertised CA list does not match.
				conf.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return tc.pair, nil }
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", tc.addr, conf)
			if err != nil {
				if tc.name != "fake_proxy" {
					t.Fatalf("unexpected dial failure: %v", err)
				}
				var verification *tls.CertificateVerificationError
				if !errors.As(err, &verification) {
					t.Fatalf("expected certificate verification failure: %v", err)
				}
				t.Logf("dial rejected: %v", err)
				return
			}
			t.Cleanup(func() {
				// Rejected peers may already be gone; close TCP without a TLS closeNotify.
				if err := conn.NetConn().Close(); err != nil {
					t.Error(err)
				}
			})
			t.Log("dial succeeded; now sending an HTTP request")
			if conn.ConnectionState().Version != tls.VersionTLS13 {
				t.Fatal("not TLS 1.3")
			}
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			_, writeErr := io.WriteString(conn, "GET /apps/wiki HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
			if writeErr != nil {
				if tc.wantOK || tc.name == "fake_proxy" {
					t.Fatal(writeErr)
				}
				t.Logf("request write rejected: %v", writeErr)
				return
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if response != nil {
				t.Cleanup(func() {
					if err := response.Body.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			if !tc.wantOK {
				if err == nil || response != nil {
					t.Fatal("rejected client received an HTTP response")
				}
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					t.Fatalf("timed out instead of TLS rejection: %v", err)
				}
				if tc.name == "fake_proxy" {
					t.Fatal("fake proxy passed server verification")
				}
				t.Logf("first response read rejected: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || string(body) != "allowed: aisha -> wiki" {
				t.Fatalf("status=%d body=%q", response.StatusCode, body)
			}
			t.Logf("status=%d body=%q", response.StatusCode, body)
		})
	}
}

type directTestDialer string

func (d directTestDialer) Dial(ctx context.Context, app string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", string(d))
}
func testUpstream(t testing.TB) AppDialer {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.WriteString(w, "allowed: "+r.Header.Get("X-Perimeter-User")+" -> "+r.Host); err != nil {
			panic(http.ErrAbortHandler)
		}
	}))
	t.Cleanup(server.Close)
	return directTestDialer(strings.TrimPrefix(server.URL, "http://"))
}

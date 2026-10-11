package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"perimeter/internal/mux"
	"perimeter/internal/policy"
	"perimeter/internal/tunnel"
)

func NewTLSConfig(caCert *x509.Certificate, serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	if caCert == nil || !caCert.IsCA {
		return nil, errors.New("CA certificate is required")
	}
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || tunnel.HasConnectorRole(state.PeerCertificates[0]) {
				return errors.New("user certificate required")
			}
			return nil
		},
	}, nil
}

type PostureProvider interface {
	Posture(r *http.Request) policy.Posture
}

// HeaderPosture is INSECURE: clients can lie. Replace with verified, fresh,
// device-bound signed reports from the agent, not merely a different header.
type HeaderPosture struct{}

func (HeaderPosture) Posture(r *http.Request) policy.Posture {
	var posture policy.Posture
	decoder := json.NewDecoder(bytes.NewBufferString(r.Header.Get("X-Device-Posture")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&posture); err != nil {
		return policy.Posture{}
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return policy.Posture{}
	}
	return posture
}

type AppDialer interface {
	Dial(context.Context, string) (net.Conn, error)
}

func Handler(store *policy.Store, provider PostureProvider, logger *slog.Logger, dialers ...AppDialer) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := policy.Request{}
		decision := policy.Decision{Reason: "unverified identity"}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0 {
			cert := r.TLS.PeerCertificates[0]
			if !tunnel.HasConnectorRole(cert) && cert.Subject.CommonName != "" && len(cert.Subject.OrganizationalUnit) > 0 && cert.Subject.OrganizationalUnit[0] != "" {
				request.User, request.Group = cert.Subject.CommonName, cert.Subject.OrganizationalUnit[0]
				app, ok := strings.CutPrefix(r.URL.Path, "/apps/")
				decision.Reason = "invalid app path"
				app, _, _ = strings.Cut(app, "/")
				if ok && mux.ValidApp(app) {
					request.App = app
					decision.Reason = "posture provider unavailable"
					if provider != nil {
						request.Posture = provider.Posture(r)
						decision = store.Get().Evaluate(request)
					}
				}
			}
		}
		logger.Info("access decision", "user", request.User, "group", request.Group, "app", request.App, "allow", decision.Allow, "reason", decision.Reason)
		// Do not expose whether the app exists or why access was denied.
		status, body := http.StatusForbidden, "denied"
		if decision.Allow {
			if len(dialers) > 0 && dialers[0] != nil {
				forward(w, r, request, dialers[0], logger)
				return
			}
			status, body = http.StatusServiceUnavailable, "unavailable"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil {
			panic(http.ErrAbortHandler)
		}
	})
}

func NewServer(addr string, tlsConf *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		TLSConfig:         tlsConf,
		Handler:           Handler(nil, nil, nil),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

func forward(w http.ResponseWriter, r *http.Request, identity policy.Request, dialer AppDialer, logger *slog.Logger) {
	transport := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer.Dial(ctx, identity.App) }}
	defer transport.CloseIdleConnections()
	reverse := &httputil.ReverseProxy{
		Transport:  transport,
		BufferPool: responseBuffers{},
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(&url.URL{Scheme: "http", Host: identity.App})
			p.Out.Host = identity.App
			path := strings.TrimPrefix(p.In.URL.Path, "/apps/"+identity.App)
			if path == "" {
				path = "/"
			}
			p.Out.URL.Path = path
			p.Out.URL.RawPath = ""
			p.Out.Header.Del("X-Device-Posture")
			p.Out.Header.Del("X-Perimeter-User")
			p.Out.Header.Del("X-Perimeter-Group")
			p.Out.Header.Set("X-Perimeter-User", identity.User)
			p.Out.Header.Set("X-Perimeter-Group", identity.Group)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Debug("upstream unavailable", "app", identity.App, "error", err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := io.WriteString(w, "unavailable"); err != nil {
				panic(http.ErrAbortHandler)
			}
		},
	}
	reverse.ServeHTTP(w, r)
}

var responsePool = sync.Pool{New: func() any { return make([]byte, 32*1024) }}

type responseBuffers struct{}

func (responseBuffers) Get() []byte  { return responsePool.Get().([]byte) }
func (responseBuffers) Put(b []byte) { responsePool.Put(b) }

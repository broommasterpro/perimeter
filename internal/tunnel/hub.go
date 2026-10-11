package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"perimeter/internal/mux"
)

var ErrUnavailable = errors.New("connector unavailable")

type Hub struct {
	registry *Registry
	mu       sync.Mutex
	sessions map[string]*mux.Session
	revoked  map[string]bool
	closed   bool
}

func NewHub(r *Registry) *Hub {
	return &Hub{registry: r, sessions: make(map[string]*mux.Session), revoked: make(map[string]bool)}
}

func ConnectorTLSConfig(root *x509.Certificate, cert tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("verified connector certificate required")
		}
		_, err := ConnectorID(state.PeerCertificates[0])
		return err
	}}
}

func (h *Hub) Accept(ctx context.Context, conn *tls.Conn) error {
	handshake, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := conn.HandshakeContext(handshake)
	cancel()
	if err != nil {
		return errors.Join(err, conn.Close())
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return errors.Join(errors.New("unverified connector"), conn.Close())
	}
	cert := state.PeerCertificates[0]
	id, err := ConnectorID(cert)
	if err != nil {
		return errors.Join(err, conn.Close())
	}
	h.mu.Lock()
	if h.closed || h.revoked[id] || !h.registry.ids[id] || !time.Now().Before(cert.NotAfter) {
		h.mu.Unlock()
		return errors.Join(ErrUnavailable, conn.Close())
	}
	session := mux.NewSession(conn, mux.Config{Proxy: true})
	old := h.sessions[id]
	h.sessions[id] = session
	h.mu.Unlock()
	if old != nil {
		if err := old.Close(); err != nil {
			return err
		}
	}
	timer := time.NewTimer(time.Until(cert.NotAfter))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-timer.C:
		err = errors.New("connector certificate expired")
	case <-session.Done():
		err = session.Err()
	}
	closeErr := session.Close()
	h.mu.Lock()
	if h.sessions[id] == session {
		delete(h.sessions, id)
	}
	h.mu.Unlock()
	return errors.Join(err, closeErr)
}

func (h *Hub) Dial(ctx context.Context, app string) (net.Conn, error) {
	h.mu.Lock()
	var session *mux.Session
	if !h.closed {
		for _, id := range h.registry.apps[app] {
			if s := h.sessions[id]; s != nil && !h.revoked[id] {
				select {
				case <-s.Done():
					continue
				default:
					session = s
				}
				if session != nil {
					break
				}
			}
		}
	}
	h.mu.Unlock()
	if session == nil {
		return nil, ErrUnavailable
	}
	stream, err := session.OpenStream(ctx, app)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (h *Hub) Revoke(id string) error {
	h.mu.Lock()
	h.revoked[id] = true
	s := h.sessions[id]
	delete(h.sessions, id)
	h.mu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}
func (h *Hub) Unrevoke(id string) { h.mu.Lock(); delete(h.revoked, id); h.mu.Unlock() }
func (h *Hub) Close() error {
	h.mu.Lock()
	h.closed = true
	sessions := h.sessions
	h.sessions = make(map[string]*mux.Session)
	h.mu.Unlock()
	var err error
	for _, s := range sessions {
		err = errors.Join(err, s.Close())
	}
	return err
}

func (h *Hub) Serve(ctx context.Context, listener net.Listener) error {
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(stopped)
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			slog.Debug("listener shutdown", "error", err)
		}
	})
	defer func() {
		if !stop() {
			<-stopped
		}
		if err := h.Close(); err != nil {
			slog.Debug("hub shutdown", "error", err)
		}
		workers.Wait()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			closeConnection(conn)
			return errors.New("connector listener must use TLS")
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := h.Accept(ctx, tlsConn); err != nil {
				slog.Debug("connector session ended", "error", err)
			}
		}()
	}
}

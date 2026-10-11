package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"perimeter/internal/mux"
)

type Connector struct {
	Address                string
	TLSConfig              *tls.Config
	Certificate            func() (tls.Certificate, error)
	Apps                   map[string]string
	MinBackoff, MaxBackoff time.Duration
	Opens                  atomic.Uint64
	Connections            atomic.Uint64
}

func (c *Connector) Run(ctx context.Context) error {
	minimum, maximum := c.MinBackoff, c.MaxBackoff
	if minimum <= 0 {
		minimum = 500 * time.Millisecond
	}
	if maximum <= 0 {
		maximum = 30 * time.Second
	}
	if maximum < minimum {
		return errors.New("invalid backoff")
	}
	if c.TLSConfig == nil || c.Certificate == nil {
		return errors.New("TLS config and certificate callback required")
	}
	config := c.TLSConfig.Clone()
	config.MinVersion = tls.VersionTLS13
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := c.Certificate()
		return &cert, err
	}
	delay := minimum
	for ctx.Err() == nil {
		connectedAt := time.Time{}
		dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config}
		conn, err := dialer.DialContext(ctx, "tcp", c.Address)
		if err == nil {
			connectedAt = time.Now()
			c.Connections.Add(1)
			s := mux.NewSession(conn, mux.Config{})
			err = c.serve(ctx, s)
			if closeErr := s.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
		if ctx.Err() != nil {
			break
		}
		slog.Debug("connector disconnected", "error", err)
		if !connectedAt.IsZero() && time.Since(connectedAt) >= time.Second {
			delay = minimum
		}
		timer := time.NewTimer(delay/2 + time.Duration(rand.Int64N(int64(delay/2)+1)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		delay = min(delay*2, maximum)
	}
	return nil
}

func (c *Connector) serve(ctx context.Context, s *mux.Session) error {
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() {
		if err := s.Close(); err != nil {
			slog.Debug("connector shutdown", "error", err)
		}
	})
	defer func() {
		stop()
		if err := s.Close(); err != nil {
			slog.Debug("session close", "error", err)
		}
		workers.Wait()
	}()
	for {
		stream, err := s.AcceptStream(ctx)
		if err != nil {
			return err
		}
		c.Opens.Add(1)
		address, ok := c.Apps[stream.App()]
		if !ok {
			if err := stream.Close(); err != nil {
				return err
			}
			continue
		}
		workers.Add(1)
		go func() { defer workers.Done(); c.relay(ctx, stream, address) }()
	}
}

func closeConnection(conn net.Conn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Debug("connection close", "error", err)
	}
}

func (c *Connector) relay(ctx context.Context, stream *mux.Stream, address string) {
	defer closeConnection(stream)
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
	if err != nil {
		return
	}
	defer closeConnection(conn)
	stopped := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-stream.Done():
			closeConnection(conn)
		case <-ctx.Done():
			closeConnection(conn)
		case <-stopped:
		}
	}()
	defer func() { close(stopped); <-watchDone }()
	copied := make(chan error, 1)
	go func() {
		_, err := copyStream(conn, stream)
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		if err != nil {
			closeConnection(conn)
			closeConnection(stream)
		}
		copied <- err
	}()
	_, readErr := copyStream(stream, conn)
	if readErr == nil {
		readErr = stream.CloseWrite()
	}
	if readErr != nil {
		closeConnection(conn)
		closeConnection(stream)
	}
	if err := <-copied; err != nil {
		slog.Debug("stream relay", "error", err)
	}
}

var relayBuffers = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

func copyStream(dst io.Writer, src io.Reader) (int64, error) {
	buffer := relayBuffers.Get().(*[]byte)
	defer relayBuffers.Put(buffer)
	// Hide TCP's optional copy methods so they cannot allocate another buffer.
	return io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, *buffer)
}

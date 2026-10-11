package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"perimeter/internal/ca"
	"perimeter/internal/policy"
	"perimeter/internal/proxy"
	"perimeter/internal/tunnel"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	registry, err := tunnel.LoadRegistry("connectors.json")
	if err != nil {
		panic(err)
	}
	hub := tunnel.NewHub(registry)
	p, err := policy.Load("policy.json")
	if err != nil {
		panic(err)
	}
	store := policy.NewStore(p)
	c, err := ca.Load("ca.crt", "ca.key")
	if err != nil {
		panic(err)
	}
	cert, key, err := c.IssueServer("127.0.0.1", time.Hour)
	if err != nil {
		panic(err)
	}
	config, err := proxy.NewTLSConfig(c.Cert, cert, key)
	if err != nil {
		panic(err)
	}
	server := proxy.NewServer("127.0.0.1:8443", config)
	server.Handler = proxy.Handler(store, proxy.HeaderPosture{}, slog.Default(), hub)
	serverCertificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}
	connectorListener, err := tls.Listen("tcp", "127.0.0.1:8444", tunnel.ConnectorTLSConfig(c.Cert, serverCertificate))
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := connectorListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			slog.Error("connector listener close", "error", err)
		}
	}()
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		panic(err)
	}
	if _, err := os.Stdout.WriteString("listening on https://" + listener.Addr().String() + "\n"); err != nil {
		panic(errors.Join(err, listener.Close()))
	}
	connectorDone := make(chan error, 1)
	go func() { connectorDone <- hub.Serve(ctx, connectorListener) }()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeTLS(listener, "", "") }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-signals:
				if err := store.Reload("policy.json"); err != nil {
					slog.Error("policy reload rejected", "error", err)
				} else {
					slog.Info("policy reloaded")
				}
			case <-done:
				return
			}
		}
	}()
	defer func() { signal.Stop(signals); close(done); <-stopped }()

	select {
	case <-ctx.Done():
	case err := <-serverDone:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("user listener stopped", "error", err)
		}
		serverDone = nil
	case err := <-connectorDone:
		if err != nil {
			slog.Error("connector listener stopped", "error", err)
		}
		connectorDone = nil
	}
	cancel()
	if err := server.Close(); err != nil {
		slog.Error("server close", "error", err)
	}
	if serverDone != nil {
		if err := <-serverDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped", "error", err)
		}
	}
	if connectorDone != nil {
		if err := <-connectorDone; err != nil {
			slog.Error("hub stopped", "error", err)
		}
	}
}

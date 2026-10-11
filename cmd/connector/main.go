package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"perimeter/internal/mux"
	"perimeter/internal/tunnel"
)

func main() {
	address := flag.String("proxy", "127.0.0.1:8444", "proxy connector address")
	caPath := flag.String("ca", "ca.crt", "trusted CA certificate")
	certPath := flag.String("cert", "connector.crt", "connector certificate; reloaded on reconnect")
	keyPath := flag.String("key", "connector.key", "connector private key")
	appPath := flag.String("apps", "connector-apps.json", "local app name to address JSON map")
	flag.Parse()
	data, err := os.ReadFile(*caPath)
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		panic("invalid CA PEM")
	}
	data, err = os.ReadFile(*appPath)
	if err != nil {
		panic(err)
	}
	var apps map[string]string
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&apps); err != nil {
		panic(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		panic(errors.New("trailing app configuration"))
	}
	for app, address := range apps {
		if !mux.ValidApp(app) {
			panic("invalid app name")
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			panic(err)
		}
	}
	connector := &tunnel.Connector{Address: *address, TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, Apps: apps, Certificate: func() (tls.Certificate, error) { return tls.LoadX509KeyPair(*certPath, *keyPath) }}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := connector.Run(ctx); err != nil {
		panic(err)
	}
}

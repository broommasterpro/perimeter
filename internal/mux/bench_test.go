package mux

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
)

func benchmarkTransfer(b *testing.B, parallel int, multiplex bool) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			b.Error(err)
		}
	}()
	payload := make([]byte, 1024*1024)
	var clients []net.Conn
	var sessions []*Session
	var wg sync.WaitGroup
	if multiplex {
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		server, err := listener.Accept()
		if err != nil {
			b.Fatal(err)
		}
		a, c := NewSession(client, Config{Proxy: true}), NewSession(server, Config{})
		sessions = []*Session{a, c}
		for i := 0; i < parallel; i++ {
			x, y := openPair(b, a, c)
			clients = append(clients, x)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := io.Copy(io.Discard, y); err != nil && c.Err() == nil {
					b.Error(err)
				}
			}()
		}
	} else {
		for i := 0; i < parallel; i++ {
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			server, err := listener.Accept()
			if err != nil {
				b.Fatal(err)
			}
			clients = append(clients, client)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := io.Copy(io.Discard, server); err != nil {
					b.Error(err)
				}
				if err := server.Close(); err != nil {
					b.Error(err)
				}
			}()
		}
	}
	b.SetBytes(int64(len(payload) * parallel))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var writers sync.WaitGroup
		for _, conn := range clients {
			writers.Add(1)
			go func(conn net.Conn) {
				defer writers.Done()
				if err := writeAll(conn, payload); err != nil {
					b.Error(err)
				}
			}(conn)
		}
		writers.Wait()
	}
	b.StopTimer()
	for _, conn := range clients {
		if st, ok := conn.(*Stream); ok {
			if err := st.CloseWrite(); err != nil {
				b.Error(err)
			}
		} else {
			if err := conn.Close(); err != nil {
				b.Error(err)
			}
		}
	}
	wg.Wait()
	for _, s := range sessions {
		if err := s.Close(); err != nil {
			b.Error(err)
		}
	}
}
func BenchmarkMux1(b *testing.B)  { benchmarkTransfer(b, 1, true) }
func BenchmarkMux32(b *testing.B) { benchmarkTransfer(b, 32, true) }
func BenchmarkTCP1(b *testing.B)  { benchmarkTransfer(b, 1, false) }
func BenchmarkTCP32(b *testing.B) { benchmarkTransfer(b, 32, false) }
func BenchmarkOpen(b *testing.B) {
	a, c := pair(b, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		x, err := a.OpenStream(context.Background(), "app")
		if err != nil {
			b.Fatal(err)
		}
		y, err := c.AcceptStream(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		closeStream(b, x)
		closeStream(b, y)
	}
}

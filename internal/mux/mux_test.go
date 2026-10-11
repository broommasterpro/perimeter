package mux

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func pair(t testing.TB, max int) (*Session, *Session) {
	t.Helper()
	a, b := net.Pipe()
	left, right := NewSession(a, Config{Proxy: true, MaxStreams: max}), NewSession(b, Config{MaxStreams: max})
	t.Cleanup(func() {
		if err := left.Close(); err != nil {
			t.Error(err)
		}
		if err := right.Close(); err != nil {
			t.Error(err)
		}
	})
	return left, right
}
func openPair(t testing.TB, a, b *Session) (*Stream, *Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	x, err := a.OpenStream(ctx, "payroll")
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return x, y
}
func closeStream(t testing.TB, s *Stream) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}

func TestEchoHalfClose(t *testing.T) {
	a, b := pair(t, 0)
	x, y := openPair(t, a, b)
	done := make(chan error, 1)
	go func() {
		data, err := io.ReadAll(y)
		if err == nil {
			_, err = y.Write(data)
		}
		if err == nil {
			err = y.CloseWrite()
		}
		done <- err
	}()
	if _, err := x.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := x.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(x)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrent1000(t *testing.T) {
	a, b := pair(t, 1100)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 2000)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var workers sync.WaitGroup
		defer workers.Wait()
		for i := 0; i < 1000; i++ {
			st, err := b.AcceptStream(ctx)
			if err != nil {
				errs <- err
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				if _, err := io.Copy(st, st); err != nil {
					errs <- err
				}
				if err := st.CloseWrite(); err != nil {
					errs <- err
				}
			}()
		}
	}()
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := a.OpenStream(ctx, "payroll")
			if err != nil {
				errs <- err
				return
			}
			data := make([]byte, 1+(i*97)%32768)
			if _, err := rand.Read(data); err != nil {
				errs <- err
				return
			}
			if err := st.SetDeadline(time.Now().Add(40 * time.Second)); err != nil {
				errs <- err
				return
			}
			if _, err := st.Write(data); err != nil {
				errs <- err
				return
			}
			if err := st.CloseWrite(); err != nil {
				errs <- err
				return
			}
			got, err := io.ReadAll(st)
			if err != nil {
				errs <- err
				return
			}
			if sha256.Sum256(got) != sha256.Sum256(data) {
				errs <- errors.New("hash mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestFlowControl(t *testing.T) {
	a, b := pair(t, 0)
	x, y := openPair(t, a, b)
	defer closeStream(t, x)
	defer closeStream(t, y)
	if err := x.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := x.Write(make([]byte, 200000))
	var timeout net.Error
	if n != Window || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("wrote=%d err=%v", n, err)
	}
	t.Logf("stalled reader: Write accepted exactly %d bytes, then %v", n, err)
	u, v := openPair(t, a, b)
	defer closeStream(t, u)
	defer closeStream(t, v)
	if err := v.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Write([]byte("independent")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 11)
	if _, err := io.ReadFull(v, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "independent" {
		t.Fatal(string(got))
	}
	b.mu.Lock()
	size := y.buffer.Len()
	capacity := y.buffer.Cap()
	b.mu.Unlock()
	t.Logf("stalled stream buffered=%d capacity=%d; stream B completed", size, capacity)
	if size > Window || capacity > 2*Window {
		t.Fatal("unbounded receive buffer")
	}
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i % 251)
	}
	return len(p), nil
}

func TestTransfer100MB(t *testing.T) {
	a, b := pair(t, 0)
	x, y := openPair(t, a, b)
	const size = 100 * 1000 * 1000
	done := make(chan error, 1)
	sent := sha256.New()
	received := sha256.New()
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	stop, sampled := make(chan struct{}), make(chan uint64, 1)
	go func() {
		var peak uint64
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				sampled <- peak
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak {
					peak = m.HeapAlloc
				}
			}
		}
	}()
	go func() {
		_, err := io.CopyN(io.MultiWriter(x, sent), repeatingReader{}, size)
		if err == nil {
			err = x.CloseWrite()
		}
		done <- err
	}()
	n, err := io.Copy(received, y)
	close(stop)
	peak := <-sampled
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n != size || !bytes.Equal(sent.Sum(nil), received.Sum(nil)) {
		t.Fatal("transfer mismatch")
	}
	t.Logf("bytes=%d baseline_heap=%d sampled_peak_heap=%d", n, baseline.HeapAlloc, peak)
	if peak > baseline.HeapAlloc+32*1024*1024 {
		t.Fatal("heap grew by more than 32 MiB")
	}
}

func TestDeadlinesAndClose(t *testing.T) {
	baseline := runtime.NumGoroutine()
	a, b := pair(t, 0)
	x, y := openPair(t, a, b)
	if err := x.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := x.Read(make([]byte, 1))
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("deadline: %v", err)
	}
	if err := x.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Write(make([]byte, Window)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { _, err := x.Read(make([]byte, 1)); done <- err }()
	go func() { _, err := x.Write([]byte{1}); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("operation did not block: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("blocked operation succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("operation did not unblock")
		}
	}
	closeStream(t, y)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		t.Fatalf("goroutines before=%d after=%d", baseline, got)
	}
}

func TestProtocolViolations(t *testing.T) {
	for _, name := range []string{"oversized", "wrong opener", "unknown ID", "excess credit"} {
		t.Run(name, func(t *testing.T) {
			local, peer := net.Pipe()
			s := NewSession(local, Config{Proxy: name == "wrong opener"})
			defer func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
				if err := peer.Close(); err != nil {
					t.Error(err)
				}
			}()
			var err error
			switch name {
			case "oversized":
				var h [9]byte
				h[0] = Data
				binary.BigEndian.PutUint32(h[1:5], 1)
				binary.BigEndian.PutUint32(h[5:], MaxPayload+1)
				_, err = peer.Write(h[:])
			case "wrong opener":
				err = WriteFrame(peer, Frame{Open, 1, []byte("app")})
			case "unknown ID":
				err = WriteFrame(peer, Frame{Data, 1, []byte("x")})
			case "excess credit":
				err = WriteFrame(peer, Frame{Open, 1, []byte("app")})
				if err == nil {
					for i := 0; i < 5; i++ {
						err = WriteFrame(peer, Frame{Data, 1, make([]byte, MaxPayload)})
						if err != nil {
							break
						}
					}
				}
			}
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			select {
			case <-s.Done():
			case <-time.After(time.Second):
				t.Fatal("session did not close")
			}
			if !errors.Is(s.Err(), ErrProtocol) {
				t.Fatalf("got %v", s.Err())
			}
		})
	}
}

func TestKeepalive(t *testing.T) {
	a, b := net.Pipe()
	s := NewSession(a, Config{Proxy: true, Keepalive: 20 * time.Millisecond})
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-s.Done():
		t.Log(s.Err())
	case <-time.After(time.Second):
		t.Fatal("keepalive did not close")
	}
}

func TestWireExamples(t *testing.T) {
	var credit [4]byte
	binary.BigEndian.PutUint32(credit[:], 16384)
	for _, f := range []Frame{{Open, 1, []byte("payroll")}, {Data, 1, bytes.Repeat([]byte{0x41}, 100)}, {WindowUpdate, 1, credit[:]}, {CloseWrite, 1, nil}} {
		var b bytes.Buffer
		if err := WriteFrame(&b, f); err != nil {
			t.Fatal(err)
		}
		t.Logf("type=%d header=%x payload=%x", f.Type, b.Bytes()[:9], b.Bytes()[9:])
	}
	creditLeft, remaining := Window, 200000
	for remaining > 0 {
		if creditLeft == 0 {
			t.Log("BLOCKED: no credit; application reads 16384")
			creditLeft += 16384
		}
		n := min(remaining, MaxPayload, creditLeft)
		creditLeft -= n
		remaining -= n
		t.Log(fmt.Sprintf("sent=%d credit=%d remaining=%d", n, creditLeft, remaining))
	}
}

func TestStreamLimit(t *testing.T) {
	a, b := pair(t, 1)
	x, y := openPair(t, a, b)
	if _, err := a.OpenStream(context.Background(), "app"); err == nil {
		t.Fatal("local stream cap ignored")
	}
	closeStream(t, x)
	closeStream(t, y)
}

func TestIdleStreamMemory(t *testing.T) {
	a, b := pair(t, 1100)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	streams := make([]*Stream, 0, 2000)
	for i := 0; i < 1000; i++ {
		x, y := openPair(t, a, b)
		streams = append(streams, x, y)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("1000 logical streams, both endpoints: heap_delta=%d bytes, bytes_per_logical_stream=%.1f", after.HeapAlloc-before.HeapAlloc, float64(after.HeapAlloc-before.HeapAlloc)/1000)
	for _, st := range streams {
		closeStream(t, st)
	}
}

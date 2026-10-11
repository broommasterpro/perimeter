package mux

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	Open byte = iota + 1
	Data
	CloseWrite
	Reset
	WindowUpdate
	Ping
	Pong
	GoAway
	MaxPayload = 16 * 1024
	Window     = 64 * 1024
)

var ErrProtocol = errors.New("mux protocol error")

type Frame struct {
	Type    byte
	ID      uint32
	Payload []byte
}

func ReadFrame(r io.Reader) (Frame, error) {
	var h [9]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(h[5:])
	// Bound allocation before trusting an untrusted length.
	if n > MaxPayload {
		return Frame{}, ErrProtocol
	}
	f := Frame{Type: h[0], ID: binary.BigEndian.Uint32(h[1:5])}
	if !validHeader(f.Type, f.ID, int(n)) {
		return Frame{}, ErrProtocol
	}
	f.Payload = make([]byte, n)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, err
	}
	return f, nil
}

func validHeader(kind byte, id uint32, n int) bool {
	switch kind {
	case Open:
		return id%2 == 1 && n > 0 && n <= 128
	case Data:
		return id%2 == 1 && n > 0 && n <= MaxPayload
	case CloseWrite, Reset:
		return id%2 == 1 && n == 0
	case WindowUpdate:
		return id%2 == 1 && n == 4
	case Ping, Pong, GoAway:
		return id == 0 && n == 0
	}
	return false
}

func WriteFrame(w io.Writer, f Frame) error {
	if !validHeader(f.Type, f.ID, len(f.Payload)) {
		return ErrProtocol
	}
	var h [9]byte
	h[0] = f.Type
	binary.BigEndian.PutUint32(h[1:5], f.ID)
	binary.BigEndian.PutUint32(h[5:], uint32(len(f.Payload)))
	if err := writeAll(w, h[:]); err != nil {
		return err
	}
	return writeAll(w, f.Payload)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func ValidApp(app string) bool {
	if len(app) == 0 || len(app) > 128 {
		return false
	}
	for _, c := range app {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

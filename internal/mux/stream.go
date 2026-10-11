package mux

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"time"
)

type Stream struct {
	session                     *Session
	id                          uint32
	app                         string
	buffer                      bytes.Buffer
	sendCredit, receiveCredit   int
	localClosed, remoteClosed   bool
	err                         error
	readDeadline, writeDeadline time.Time
	done                        chan struct{}
	finished                    bool
}

func (s *Session) newStream(id uint32, app string) *Stream {
	return &Stream{session: s, id: id, app: app, sendCredit: Window, receiveCredit: Window, done: make(chan struct{})}
}
func (st *Stream) App() string           { return st.app }
func (st *Stream) Done() <-chan struct{} { return st.done }
func (st *Stream) finish() {
	if !st.finished {
		close(st.done)
		st.finished = true
	}
}

func wait(ch, done <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-ch:
			return nil
		case <-done:
			return net.ErrClosed
		}
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-done:
		return net.ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s := st.session
	for {
		s.mu.Lock()
		if st.err != nil {
			err := st.err
			s.mu.Unlock()
			return 0, err
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		if !st.readDeadline.IsZero() && !time.Now().Before(st.readDeadline) {
			s.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if st.buffer.Len() > 0 {
			n, err := st.buffer.Read(p)
			st.receiveCredit += n
			var credit [4]byte
			binary.BigEndian.PutUint32(credit[:], uint32(n))
			s.enqueue(Frame{WindowUpdate, st.id, credit[:]})
			if st.localClosed && st.remoteClosed && st.buffer.Len() == 0 {
				s.retire(st)
			}
			s.mu.Unlock()
			return n, err
		}
		if st.remoteClosed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		ch, deadline := s.changed, st.readDeadline
		s.mu.Unlock()
		if err := wait(ch, s.done, deadline); err != nil {
			return 0, err
		}
	}
}

func (st *Stream) Write(p []byte) (int, error) {
	s := st.session
	total := 0
	for len(p) > 0 {
		s.mu.Lock()
		if st.err != nil {
			err := st.err
			s.mu.Unlock()
			return total, err
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return total, err
		}
		if st.localClosed {
			s.mu.Unlock()
			return total, net.ErrClosed
		}
		if !st.writeDeadline.IsZero() && !time.Now().Before(st.writeDeadline) {
			s.mu.Unlock()
			return total, os.ErrDeadlineExceeded
		}
		if st.sendCredit > 0 && len(s.queue) < 1000 {
			n := min(len(p), MaxPayload, st.sendCredit)
			data := append([]byte(nil), p[:n]...)
			st.sendCredit -= n
			s.enqueue(Frame{Data, st.id, data})
			s.mu.Unlock()
			p = p[n:]
			total += n
			continue
		}
		ch, deadline := s.changed, st.writeDeadline
		s.mu.Unlock()
		if err := wait(ch, s.done, deadline); err != nil {
			return total, err
		}
	}
	return total, nil
}

func (st *Stream) CloseWrite() error {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.localClosed {
		return nil
	}
	if st.err != nil {
		return st.err
	}
	if s.err != nil {
		return s.err
	}
	st.localClosed = true
	if !s.enqueue(Frame{Type: CloseWrite, ID: st.id}) {
		return s.err
	}
	if st.remoteClosed && st.buffer.Len() == 0 {
		s.retire(st)
	}
	return nil
}

func (st *Stream) Close() error {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.finished {
		return nil
	}
	st.err = net.ErrClosed
	if s.err == nil {
		s.enqueue(Frame{Type: Reset, ID: st.id})
	}
	s.retire(st)
	return nil
}
func (st *Stream) LocalAddr() net.Addr  { return st.session.conn.LocalAddr() }
func (st *Stream) RemoteAddr() net.Addr { return st.session.conn.RemoteAddr() }
func (st *Stream) SetDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	st.readDeadline = t
	st.writeDeadline = t
	s.signal()
	return nil
}
func (st *Stream) SetReadDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	st.readDeadline = t
	s.signal()
	return nil
}
func (st *Stream) SetWriteDeadline(t time.Time) error {
	s := st.session
	s.mu.Lock()
	defer s.mu.Unlock()
	st.writeDeadline = t
	s.signal()
	return nil
}

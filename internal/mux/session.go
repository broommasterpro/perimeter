package mux

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

type Config struct {
	Proxy      bool
	MaxStreams int
	Keepalive  time.Duration
}

type Session struct {
	conn          net.Conn
	cfg           Config
	mu            sync.Mutex
	streams       map[uint32]*Stream
	recent        map[uint32]bool
	closedIDs     []uint32
	next, highest uint32
	queue         []Frame
	changed       chan struct{}
	done          chan struct{}
	accept        chan *Stream
	err           error
	lastFrame     time.Time
	wg            sync.WaitGroup
}

func NewSession(conn net.Conn, cfg Config) *Session {
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = 256
	}
	if cfg.Keepalive <= 0 {
		cfg.Keepalive = 10 * time.Second
	}
	s := &Session{conn: conn, cfg: cfg, streams: make(map[uint32]*Stream), recent: make(map[uint32]bool), next: 1, changed: make(chan struct{}), done: make(chan struct{}), accept: make(chan *Stream, cfg.MaxStreams), lastFrame: time.Now()}
	s.wg.Add(3)
	go s.readLoop()
	go s.writeLoop()
	go s.keepalive()
	return s
}

func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Err() error            { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Session) signal()               { close(s.changed); s.changed = make(chan struct{}) }
func (s *Session) fail(err error)        { s.mu.Lock(); defer s.mu.Unlock(); s.failLocked(err) }
func (s *Session) failLocked(err error) {
	if s.err != nil {
		return
	}
	s.err = errors.Join(err, s.conn.Close())
	close(s.done)
	for _, st := range s.streams {
		st.finish()
	}
	s.signal()
}
func (s *Session) Close() error { s.fail(net.ErrClosed); s.wg.Wait(); return nil }

func (s *Session) enqueue(f Frame) bool {
	if f.Type == WindowUpdate || f.Type == Ping || f.Type == Pong {
		for i := len(s.queue) - 1; i >= 0; i-- {
			pending := &s.queue[i]
			if pending.Type == f.Type && pending.ID == f.ID {
				if f.Type == WindowUpdate {
					credit := binary.BigEndian.Uint32(pending.Payload) + binary.BigEndian.Uint32(f.Payload)
					binary.BigEndian.PutUint32(pending.Payload, credit)
				}
				return true
			}
		}
	}
	if len(s.queue) >= 1000+3*s.cfg.MaxStreams+16 {
		s.failLocked(errors.New("mux control queue exhausted"))
		return false
	}
	s.queue = append(s.queue, f)
	s.signal()
	return true
}

func (s *Session) OpenStream(ctx context.Context, app string) (*Stream, error) {
	if !s.cfg.Proxy || !ValidApp(app) {
		return nil, ErrProtocol
	}
	for {
		s.mu.Lock()
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return nil, err
		}
		if len(s.streams) >= s.cfg.MaxStreams {
			s.mu.Unlock()
			return nil, errors.New("mux stream limit")
		}
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if len(s.queue) < 1000 {
			if s.next == 0 || s.next > 0xfffffffd {
				s.mu.Unlock()
				return nil, errors.New("mux stream IDs exhausted")
			}
			id := s.next
			s.next += 2
			st := s.newStream(id, app)
			s.streams[id] = st
			s.enqueue(Frame{Open, id, []byte(app)})
			s.mu.Unlock()
			return st, nil
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *Session) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.done:
		return nil, s.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Session) retire(st *Stream) {
	if _, ok := s.streams[st.id]; !ok {
		return
	}
	delete(s.streams, st.id)
	st.finish()
	// Only the last 4096 retired IDs tolerate late frames; older IDs are errors.
	s.recent[st.id] = true
	s.closedIDs = append(s.closedIDs, st.id)
	if len(s.closedIDs) > 4096 {
		delete(s.recent, s.closedIDs[0])
		s.closedIDs = s.closedIDs[1:]
	}
	s.signal()
}

func (s *Session) readLoop() {
	defer s.wg.Done()
	reader := bufio.NewReaderSize(s.conn, 32*1024)
	for {
		f, err := ReadFrame(reader)
		if err != nil {
			s.fail(err)
			return
		}
		s.mu.Lock()
		if s.err != nil {
			s.mu.Unlock()
			return
		}
		s.lastFrame = time.Now()
		err = s.receive(f)
		if err != nil {
			s.failLocked(err)
		}
		s.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (s *Session) receive(f Frame) error {
	switch f.Type {
	case Ping:
		s.enqueue(Frame{Type: Pong})
		return nil
	case Pong:
		return nil
	case GoAway:
		return net.ErrClosed
	case Open:
		if s.cfg.Proxy || f.ID <= s.highest || !ValidApp(string(f.Payload)) {
			return ErrProtocol
		}
		s.highest = f.ID
		st := s.newStream(f.ID, string(f.Payload))
		s.streams[f.ID] = st
		if len(s.streams) > s.cfg.MaxStreams {
			s.enqueue(Frame{Type: Reset, ID: f.ID})
			s.retire(st)
			return nil
		}
		select {
		case s.accept <- st:
		default:
			s.enqueue(Frame{Type: Reset, ID: f.ID})
			s.retire(st)
		}
		return nil
	}
	st, ok := s.streams[f.ID]
	if !ok {
		if s.recent[f.ID] {
			return nil
		}
		return ErrProtocol
	}
	switch f.Type {
	case Data:
		if st.remoteClosed || len(f.Payload) > st.receiveCredit {
			return ErrProtocol
		}
		st.receiveCredit -= len(f.Payload)
		if _, err := st.buffer.Write(f.Payload); err != nil {
			return err
		}
	case CloseWrite:
		if st.remoteClosed {
			return ErrProtocol
		}
		st.remoteClosed = true
		if st.localClosed && st.buffer.Len() == 0 {
			s.retire(st)
		}
	case Reset:
		st.err = errors.New("mux stream reset")
		s.retire(st)
	case WindowUpdate:
		n := binary.BigEndian.Uint32(f.Payload)
		if n == 0 || n > Window || st.sendCredit+int(n) > Window {
			return ErrProtocol
		}
		st.sendCredit += int(n)
	}
	s.signal()
	return nil
}

func (s *Session) writeLoop() {
	defer s.wg.Done()
	// One owner batches complete frames, flushing whenever the queue drains.
	writer := bufio.NewWriterSize(s.conn, 32*1024)
	for {
		s.mu.Lock()
		if s.err != nil {
			s.mu.Unlock()
			return
		}
		if len(s.queue) == 0 {
			changed := s.changed
			s.mu.Unlock()
			select {
			case <-changed:
			case <-s.done:
				return
			}
			continue
		}
		f := s.queue[0]
		s.queue[0] = Frame{}
		s.queue = s.queue[1:]
		s.signal()
		s.mu.Unlock()
		if err := WriteFrame(writer, f); err != nil {
			s.fail(err)
			return
		}
		s.mu.Lock()
		empty := len(s.queue) == 0
		s.mu.Unlock()
		if empty {
			if err := writer.Flush(); err != nil {
				s.fail(err)
				return
			}
		}
	}
}

func (s *Session) keepalive() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.Keepalive)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			if now.Sub(s.lastFrame) >= 3*s.cfg.Keepalive {
				s.failLocked(errors.New("mux keepalive timeout"))
			} else {
				s.enqueue(Frame{Type: Ping})
			}
			s.mu.Unlock()
		}
	}
}

package policy

import "sync/atomic"

type Store struct {
	current atomic.Pointer[Policy]
}

func NewStore(p *Policy) *Store {
	s := &Store{}
	s.current.Store(p)
	return s
}

func (s *Store) Get() *Policy {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

func (s *Store) Reload(path string) error {
	p, err := Load(path)
	if err != nil {
		return err
	}
	// Published policies are immutable, so readers need no request-level lock.
	s.current.Store(p)
	return nil
}

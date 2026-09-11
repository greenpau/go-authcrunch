// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package refresh

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type family struct {
	session Session
	revoked bool
	digests [][32]byte
}

// MemoryStore is bounded, volatile, and safe for concurrent use in one process.
// Cleanup is opportunistic; it starts no background goroutines. Restarts require
// reauthentication unless an embedding application retains this store.
type MemoryStore struct {
	closed                 bool
	mu                     sync.Mutex
	families               map[string]*family
	tokens                 map[[32]byte]*family
	capacity, maxRotations int
	now                    func() time.Time
}

// NewMemoryStore bounds both session count and retained digests per family.
func NewMemoryStore(capacity, maxRotations int) (*MemoryStore, error) {
	if capacity < 1 || maxRotations < 1 {
		return nil, fmt.Errorf("refresh store limits must be positive")
	}
	return &MemoryStore{families: make(map[string]*family), tokens: make(map[[32]byte]*family), capacity: capacity, maxRotations: maxRotations, now: time.Now}, nil
}

func (s *MemoryStore) cleanup(now int64) {
	for id, f := range s.families {
		if now >= f.session.AbsoluteExpiresAt {
			for _, d := range f.digests {
				delete(s.tokens, d)
			}
			delete(s.families, id)
		}
	}
}

// Create commits a staged initial issuance, including its access deadline.
func (s *MemoryStore) Create(ctx context.Context, v Session, accessExpiry int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := s.now().Unix()
	s.cleanup(now)
	if len(s.families) >= s.capacity {
		return ErrUnavailable
	}
	if _, ok := s.families[v.ID]; ok {
		return ErrUnavailable
	}
	if _, ok := s.tokens[v.Current]; ok {
		return ErrUnavailable
	}
	if v.ID == "" || v.Revision != 0 || now >= v.IdleExpiresAt || v.IdleExpiresAt > v.AbsoluteExpiresAt || accessExpiry <= now || accessExpiry > v.AbsoluteExpiresAt {
		return ErrInvalid
	}
	f := &family{session: cloneSession(v), digests: [][32]byte{v.Current}}
	s.families[v.ID], s.tokens[v.Current] = f, f
	return nil
}

func (s *MemoryStore) lookup(d [32]byte, b Binding) (*family, error) {
	f, ok := s.tokens[d]
	if !ok || f.session.Binding != b {
		return nil, ErrInvalid
	}
	if f.revoked {
		return nil, ErrInvalid
	}
	if f.session.Current != d {
		f.revoked = true
		return nil, ErrInvalid
	}
	now := s.now().Unix()
	if now >= f.session.IdleExpiresAt || now >= f.session.AbsoluteExpiresAt {
		f.revoked = true
		return nil, ErrInvalid
	}
	return f, nil
}

// Lookup authenticates a credential independently of access-token expiry.
func (s *MemoryStore) Lookup(ctx context.Context, d [32]byte, b Binding) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Session{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	f, err := s.lookup(d, b)
	if err != nil {
		return Session{}, err
	}
	return cloneSession(f.session), nil
}

// Rotate commits exactly one descendant; a competing old token revokes it.
func (s *MemoryStore) Rotate(ctx context.Context, previous Session, next [32]byte, idleExpiry, accessExpiry int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := s.lookup(previous.Current, previous.Binding)
	if err != nil {
		return err
	}
	if previous.ID != f.session.ID || previous.Revision != f.session.Revision {
		return ErrInvalid
	}
	now := s.now().Unix()
	if accessExpiry <= now {
		return ErrUnavailable
	}
	if idleExpiry <= now || idleExpiry > f.session.AbsoluteExpiresAt || accessExpiry > f.session.AbsoluteExpiresAt {
		return ErrInvalid
	}
	if len(f.digests) > s.maxRotations {
		f.revoked = true
		return ErrInvalid
	}
	if _, ok := s.tokens[next]; ok {
		return ErrUnavailable
	}
	f.session.Current = next
	f.session.Revision++
	f.session.IdleExpiresAt = idleExpiry
	f.digests = append(f.digests, next)
	s.tokens[next] = f
	return nil
}

// Revoke accepts current or spent credentials, making logout idempotent.
func (s *MemoryStore) Revoke(ctx context.Context, d [32]byte, b Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f, ok := s.tokens[d]; ok && f.session.Binding == b {
		f.revoked = true
	}
	return nil
}

// Close discards all families and prevents subsequent issuance or rotation.
func (s *MemoryStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.families, s.tokens = nil, nil
}

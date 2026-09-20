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

package tokenrefresh

import (
	"errors"
	"fmt"
	"sort"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

type persistentFamily struct {
	Session Session
	Digests [][32]byte
}

// ConfigurePersistentState restores this store before it is exposed to callers.
// Every mutation, including replay revocation, is then committed synchronously.
// Close only releases memory; the caller owns the underlying persistent store.
func (s *MemoryStore) ConfigurePersistentState(record *state.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record == nil || s.state != nil || s.closed || len(s.families) != 0 {
		return fmt.Errorf("refresh persistence must be configured before use")
	}
	var entries []persistentFamily
	if _, err := record.Decode(&entries); err != nil {
		return err
	}
	if len(entries) > s.capacity {
		return fmt.Errorf("persisted refresh capacity exceeded")
	}
	families := make(map[string]*family)
	tokens := make(map[[32]byte]*family)
	for _, entry := range entries {
		v := entry.Session
		if s.now().Unix() >= v.IdleExpiresAt || s.now().Unix() >= v.AbsoluteExpiresAt {
			continue
		}
		if v.ID == "" || v.IdleExpiresAt > v.AbsoluteExpiresAt || len(entry.Digests) == 0 || len(entry.Digests) > s.maxRotations+1 || uint64(len(entry.Digests)-1) != v.Revision || entry.Digests[len(entry.Digests)-1] != v.Current || families[v.ID] != nil {
			return fmt.Errorf("invalid persisted refresh family")
		}
		f := &family{session: v, digests: entry.Digests}
		families[v.ID] = f
		for _, d := range f.digests {
			if tokens[d] != nil {
				return fmt.Errorf("duplicate persisted refresh digest")
			}
			tokens[d] = f
		}
	}
	s.families, s.tokens, s.state = families, tokens, record
	return nil
}

func (s *MemoryStore) persist() error {
	if s.state == nil {
		return nil
	}
	entries := make([]persistentFamily, 0, len(s.families))
	for _, f := range s.families {
		entries = append(entries, persistentFamily{Session: f.session, Digests: f.digests})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Session.ID < entries[j].Session.ID })
	prepared, err := s.state.PrepareEncode(entries)
	if errors.Is(err, state.ErrCapacity) {
		return fmt.Errorf("%w: %w", ErrUnavailable, state.ErrCapacity)
	}
	if err != nil {
		s.closed = true
		return ErrUnavailable
	}
	if err := s.state.Save(prepared); err != nil {
		s.closed = true
		return ErrUnavailable
	}
	return nil
}

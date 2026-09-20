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

package cache

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type persistentSession struct {
	ID      string
	Created time.Time
	User    []byte
}

// ConfigurePersistentState restores completed sessions before the cache is used.
// Private evidence is stored explicitly; ordinary user JSON remains public-safe.
func (c *SessionCache) ConfigurePersistentState(record *state.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if record == nil || c.state != nil || len(c.Entries) != 0 {
		return fmt.Errorf("session persistence must be configured before use")
	}
	var entries []persistentSession
	if _, err := record.Decode(&entries); err != nil {
		return err
	}
	restored := make(map[string]*SessionCacheEntry)
	for _, entry := range entries {
		if parseCacheID(entry.ID) != nil {
			return fmt.Errorf("invalid persisted session ID")
		}
		u, err := user.UnmarshalSession(entry.User)
		if err != nil {
			return err
		}
		if u.Claims.ID != entry.ID || restored[entry.ID] != nil {
			return fmt.Errorf("invalid persisted session binding")
		}
		if u.Claims.Valid() != nil {
			continue
		}
		restored[entry.ID] = &SessionCacheEntry{sessionID: entry.ID, createdAt: entry.Created, user: u}
	}
	c.Entries, c.state = restored, record
	return nil
}
func (c *SessionCache) persist() error {
	if c.state == nil {
		return nil
	}
	entries := make([]persistentSession, 0, len(c.Entries))
	for id, e := range c.Entries {
		if e == nil || e.user == nil || e.user.Claims == nil || e.user.Claims.Valid() != nil {
			continue
		}
		data, err := e.user.MarshalSession()
		if err != nil {
			c.stateFailed = true
			return err
		}
		entries = append(entries, persistentSession{ID: id, Created: e.createdAt, User: data})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	data, err := c.state.PrepareEncode(entries)
	if errors.Is(err, state.ErrCapacity) {
		return err
	}
	if err != nil {
		c.stateFailed = true
		return err
	}
	if err := c.state.Save(data); err != nil {
		c.stateFailed = true
		return err
	}
	return nil
}

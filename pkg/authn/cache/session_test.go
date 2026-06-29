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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestSessionCacheGetRemovesNilUserEntry(t *testing.T) {
	c := NewSessionCache()
	sessionID := strings.Repeat("a", 32)
	c.Entries[sessionID] = &SessionCacheEntry{
		sessionID: sessionID,
		createdAt: time.Now().UTC(),
	}

	if _, err := c.Get(sessionID); err == nil {
		t.Fatal("Get() returned nil error for nil user entry")
	}

	c.mu.RLock()
	_, exists := c.Entries[sessionID]
	c.mu.RUnlock()
	if exists {
		t.Fatal("Get() did not remove nil user entry")
	}
}

func TestSessionCacheGetRemovesExpiredEntriesConcurrently(t *testing.T) {
	c := NewSessionCache()
	now := time.Now().UTC()
	sessionIDs := make([]string, 64)
	for i := range sessionIDs {
		prefix := string(rune('a' + i%26))
		suffix := string(rune('0' + i/26))
		sessionID := strings.Repeat(prefix, 32) + suffix
		sessionIDs[i] = sessionID
		c.Entries[sessionID] = &SessionCacheEntry{
			sessionID: sessionID,
			createdAt: now,
			user: &user.User{
				Claims: &user.Claims{
					ExpiresAt: now.Add(-time.Minute).Unix(),
				},
			},
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, sessionID := range sessionIDs {
				if _, err := c.Get(sessionID); err == nil {
					t.Errorf("Get(%q) returned nil error for expired entry", sessionID)
				}
			}
		}()
	}
	wg.Wait()

	c.mu.RLock()
	remainingEntries := len(c.Entries)
	c.mu.RUnlock()
	if remainingEntries != 0 {
		t.Fatalf("remaining entries = %d, want 0", remainingEntries)
	}
}

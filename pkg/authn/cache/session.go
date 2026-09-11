// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/user"
)

const defaultSessionCleanupInternal int = 60
const minSessionCleanupInternal int = 0

// SessionCacheEntry is an entry in SessionCache.
type SessionCacheEntry struct {
	sessionID string
	createdAt time.Time
	user      *user.User
}

// SessionCache contains cached tokens
type SessionCache struct {
	mu sync.RWMutex
	// The interval (in seconds) at which cache maintenance task are being triggered.
	// The default is 5 minutes (300 seconds)
	cleanupInternal int
	// The maximum number of seconds the cached entry is available to a user.
	maxEntryLifetime int64
	// If set to true, then the cache is being managed.
	managed bool
	// exit channel
	exit    chan bool
	Entries map[string]*SessionCacheEntry `json:"entries,omitempty" xml:"entries,omitempty" yaml:"entries,omitempty"`
}

// NewSessionCache returns SessionCache instance.
func NewSessionCache() *SessionCache {
	c := &SessionCache{
		cleanupInternal: defaultSessionCleanupInternal,
		Entries:         make(map[string]*SessionCacheEntry),
		exit:            make(chan bool),
	}
	return c
}

// SetCleanupInterval sets cache management interval.
func (c *SessionCache) SetCleanupInterval(i int) error {
	if i < 1 {
		return fmt.Errorf("session cache cleanup interval must be equal to or greater than %d", minSessionCleanupInternal)
	}
	c.cleanupInternal = i
	return nil

}

func manageSessionCache(c *SessionCache, exit <-chan bool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-exit:
			return
		case <-ticker.C:
			c.mu.Lock()
			for id, entry := range c.Entries {
				if entry.Valid() != nil {
					delete(c.Entries, id)
				}
			}
			c.mu.Unlock()
		}
	}
}

// Run starts management of SessionCache instance.
func (c *SessionCache) Run() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.managed {
		return
	}
	c.managed = true
	c.exit = make(chan bool)
	go manageSessionCache(c, c.exit, time.Duration(c.cleanupInternal)*time.Second)
}

// Stop stops management of SessionCache instance and releases its ticker.
func (c *SessionCache) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.managed {
		return
	}
	c.managed = false
	close(c.exit)
}

// GetCleanupInterval returns cleanup interval.
func (c *SessionCache) GetCleanupInterval() int {
	return c.cleanupInternal
}

// Add adds user to the cache.
func (c *SessionCache) Add(sessionID string, u *user.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("session cache is not available")
	}
	c.Entries[sessionID] = &SessionCacheEntry{
		sessionID: sessionID,
		createdAt: time.Now().UTC(),
		user:      u,
	}
	return nil
}

// Delete removes cached user entry.
func (c *SessionCache) Delete(sessionID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("session cache is not available")
	}
	_, exists := c.Entries[sessionID]
	if !exists {
		return errors.New("cached session id not found")
	}
	delete(c.Entries, sessionID)
	return nil
}

// Get returns cached user entry.
func (c *SessionCache) Get(sessionID string) (*user.User, error) {
	if err := parseCacheID(sessionID); err != nil {
		return nil, err
	}
	c.mu.RLock()
	entry, exists := c.Entries[sessionID]
	c.mu.RUnlock()
	if !exists {
		return nil, errors.New("cached session id not found")
	}
	if entry == nil || entry.user == nil || entry.user.Claims == nil {
		c.deleteEntry(sessionID, entry)
		return nil, fmt.Errorf("cached session id %s has nil user", sessionID)
	}
	if err := entry.Valid(); err != nil {
		c.deleteEntry(sessionID, entry)
		return nil, fmt.Errorf("cached session id error: %s", err)
	}
	return entry.user, nil
}

func (c *SessionCache) deleteEntry(sessionID string, entry *SessionCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return
	}
	if currentEntry, exists := c.Entries[sessionID]; exists && currentEntry == entry {
		delete(c.Entries, sessionID)
	}
}

// Valid checks whether SessionCacheEntry is not expired.
func (e *SessionCacheEntry) Valid() error {
	if err := e.user.Claims.Valid(); err != nil {
		return err
	}
	return nil
}

// parseCacheID checks the id associated with the cached entry for format
// requirements.
func parseCacheID(s string) error {
	if len(s) > 96 || len(s) < 32 {
		return errors.New("cached id length is outside of 32-96 character range")
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && (c != '-') {
			return errors.New("cached id contains invalid characters")
		}
	}
	return nil
}

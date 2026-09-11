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
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/user"
)

const defaultSandboxCleanupInternal int = 60
const minSandboxCleanupInternal int = 0
const defaultSandboxMaxEntryLifetime int = 300
const minSandboxMaxEntryLifetime int = 60

// SandboxCacheEntry is an entry in SandboxCache.
type SandboxCacheEntry struct {
	requestMu sync.Mutex
	sandboxID string
	createdAt time.Time
	user      *user.User
	// When set to true, the sandbox entry is no longer active.
	expired bool
}

// SandboxLease serializes checkpoint verification and redemption for one login.
// Release must be called after the request finishes. User is private to the
// lease until release; callers must not retain it or mutate it concurrently.
type SandboxLease struct {
	cache *SandboxCache
	entry *SandboxCacheEntry
	User  *user.User `json:"-" xml:"-" yaml:"-"`
}

// Acquire validates a sandbox secret and locks its authentication state.
func (c *SandboxCache) Acquire(id, secret string) (*SandboxLease, error) {
	if err := parseCacheID(id); err != nil {
		return nil, err
	}
	c.mu.RLock()
	e := c.Entries[id]
	c.mu.RUnlock()
	if e == nil {
		return nil, errors.New("cached sandbox id not found")
	}
	e.requestMu.Lock()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Entries[id] != e || e.Valid(c.maxEntryLifetime) != nil || e.user == nil || secret == "" || subtle.ConstantTimeCompare([]byte(e.user.Authenticator.TempSecret), []byte(secret)) != 1 {
		e.requestMu.Unlock()
		return nil, errors.New("invalid sandbox credential")
	}
	return &SandboxLease{cache: c, entry: e, User: e.user}, nil
}

// Release allows the next request to inspect this sandbox.
func (l *SandboxLease) Release() { l.entry.requestMu.Unlock() }

// Redeem atomically checks completion, snapshots evidence and consumes the
// sandbox. No Get/Delete sequence can issue two refresh families for this login.
func (l *SandboxLease) Redeem() (*user.User, error) {
	c, e := l.cache, l.entry
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries[e.sandboxID] != e || e.Valid(c.maxEntryLifetime) != nil || len(e.user.Checkpoints) == 0 {
		return nil, errors.New("invalid completed sandbox")
	}
	for _, checkpoint := range e.user.Checkpoints {
		if checkpoint == nil || !checkpoint.Passed {
			return nil, errors.New("incomplete authentication")
		}
	}
	proof := e.user.Clone()
	delete(c.Entries, e.sandboxID)
	return proof, nil
}

// SandboxCache contains cached tokens
type SandboxCache struct {
	mu sync.RWMutex
	// The interval (in seconds) at which cache maintenance task are being triggered.
	// The default is 5 minutes (300 seconds)
	cleanupInternal int
	// The maximum number of seconds the cached entry is available to a user.
	maxEntryLifetime int
	// If set to true, then the cache is being managed.
	managed bool
	// exit channel
	exit    chan bool
	Entries map[string]*SandboxCacheEntry `json:"entries,omitempty" xml:"entries,omitempty" yaml:"entries,omitempty"`
}

// NewSandboxCache returns SandboxCache instance.
func NewSandboxCache() *SandboxCache {
	return &SandboxCache{
		cleanupInternal:  defaultSandboxCleanupInternal,
		maxEntryLifetime: defaultSandboxMaxEntryLifetime,
		Entries:          make(map[string]*SandboxCacheEntry),
		exit:             make(chan bool),
	}
}

// SetCleanupInterval sets cache management interval.
func (c *SandboxCache) SetCleanupInterval(i int) error {
	if i < 1 {
		return fmt.Errorf("sandbox cache cleanup interval must be equal to or greater than %d", minSandboxCleanupInternal)
	}
	c.cleanupInternal = i
	return nil
}

// SetMaxEntryLifetime sets cache management max entry lifetime in seconds.
func (c *SandboxCache) SetMaxEntryLifetime(i int) error {
	if i < 60 {
		return fmt.Errorf("sandbox cache max entry lifetime must be equal to or greater than %d seconds", minSandboxMaxEntryLifetime)
	}
	c.maxEntryLifetime = i
	return nil
}

func manageSandboxCache(c *SandboxCache, exit <-chan bool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-exit:
			return
		case <-ticker.C:
			c.mu.Lock()
			for id, entry := range c.Entries {
				if entry.Valid(c.maxEntryLifetime) != nil {
					delete(c.Entries, id)
				}
			}
			c.mu.Unlock()
		}
	}
}

// Run starts management of SandboxCache instance.
func (c *SandboxCache) Run() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.managed {
		return
	}
	c.managed = true
	c.exit = make(chan bool)
	go manageSandboxCache(c, c.exit, time.Duration(c.cleanupInternal)*time.Second)
}

// Stop stops management of SandboxCache instance and releases its ticker.
func (c *SandboxCache) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.managed {
		return
	}
	c.managed = false
	close(c.exit)
}

// GetCleanupInterval returns cleanup interval.
func (c *SandboxCache) GetCleanupInterval() int {
	return c.cleanupInternal
}

// GetMaxEntryLifetime returns max entry lifetime.
func (c *SandboxCache) GetMaxEntryLifetime() int {
	return c.maxEntryLifetime
}

// Add adds user to the cache.
func (c *SandboxCache) Add(sandboxID string, u *user.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("sandbox cache is not available")
	}
	c.Entries[sandboxID] = &SandboxCacheEntry{
		sandboxID: sandboxID,
		createdAt: time.Now().UTC(),
		user:      u,
	}
	return nil
}

// Delete removes cached user entry.
func (c *SandboxCache) Delete(sandboxID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("sandbox cache is not available")
	}
	_, exists := c.Entries[sandboxID]
	if !exists {
		return errors.New("cached sandbox id not found")
	}
	delete(c.Entries, sandboxID)
	return nil
}

// Get returns cached user entry.
func (c *SandboxCache) Get(sandboxID string) (*user.User, error) {
	if err := parseCacheID(sandboxID); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, exists := c.Entries[sandboxID]; exists {
		if err := entry.Valid(c.maxEntryLifetime); err != nil {
			return nil, err
		}
		return entry.user, nil
	}
	return nil, errors.New("cached sandbox id not found")
}

// Expire expires a particular sandbox entry.
func (c *SandboxCache) Expire(sandboxID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, exists := c.Entries[sandboxID]; exists {
		entry.expired = true
	}
}

// Valid checks whether SandboxCacheEntry is non-expired.
func (e *SandboxCacheEntry) Valid(max int) error {
	if e.expired {
		return errors.New("sandbox cached entry is no longer in use")
	}
	diff := time.Now().UTC().Unix() - e.createdAt.Unix()
	if diff > int64(max) {
		return errors.New("sandbox cached entry expired")
	}
	return nil
}

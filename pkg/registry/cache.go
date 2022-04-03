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

package registry

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// The default registration cleanup interval is 5 minutes.
	defaultRegistrationCleanupInternal int = 300
	minRegistrationCleanupInternal     int = 0
	// The default lifetime of a registration lifetime is 60 minutes.
	defaultRegistrationMaxEntryLifetime int = 3600
	// The minimum lifetime of a registration lifetime is 15 minutes.
	minRegistrationMaxEntryLifetime int = 900
)

// RegistrationCacheEntry is an entry in RegistrationCache.
type RegistrationCacheEntry struct {
	registrationID string
	createdAt      time.Time
	user           map[string]string
	// When set to true, the entry is no longer active.
	expired bool
}

// RegistrationCache contains cached tokens
type RegistrationCache struct {
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
	Entries map[string]*RegistrationCacheEntry `json:"entries,omitempty" xml:"entries,omitempty" yaml:"entries,omitempty"`
}

// NewRegistrationCache returns RegistrationCache instance.
func NewRegistrationCache() *RegistrationCache {
	return &RegistrationCache{
		cleanupInternal:  defaultRegistrationCleanupInternal,
		maxEntryLifetime: defaultRegistrationMaxEntryLifetime,
		Entries:          make(map[string]*RegistrationCacheEntry),
		exit:             make(chan bool),
	}
}

// SetCleanupInterval sets cache management interval.
func (c *RegistrationCache) SetCleanupInterval(i int) error {
	if i < 1 {
		return fmt.Errorf("registration cache cleanup interval must be equal to or greater than %d", minRegistrationCleanupInternal)
	}
	c.cleanupInternal = i
	return nil
}

// SetMaxEntryLifetime sets cache management max entry lifetime in seconds.
func (c *RegistrationCache) SetMaxEntryLifetime(i int) error {
	if i < 60 {
		return fmt.Errorf("registration cache max entry lifetime must be equal to or greater than %d seconds", minRegistrationMaxEntryLifetime)
	}
	c.maxEntryLifetime = i
	return nil
}

func manageRegistrationCache(c *RegistrationCache) {
	c.managed = true
	intervals := time.NewTicker(time.Second * time.Duration(c.cleanupInternal))
	for range intervals.C {
		if c == nil {
			continue
		}
		c.mu.Lock()
		select {
		case <-c.exit:
			c.managed = false
			break
		default:
			break
		}
		if !c.managed {
			c.mu.Unlock()
			break
		}
		if c.Entries == nil {
			c.mu.Unlock()
			continue
		}
		deleteList := []string{}
		for registrationID, entry := range c.Entries {
			if err := entry.Valid(c.maxEntryLifetime); err != nil {
				deleteList = append(deleteList, registrationID)
				continue
			}
		}
		if len(deleteList) > 0 {
			for _, registrationID := range deleteList {
				delete(c.Entries, registrationID)
			}
		}
		c.mu.Unlock()
	}
	return
}

// Run starts management of RegistrationCache instance.
func (c *RegistrationCache) Run() {
	if c.managed {
		return
	}
	go manageRegistrationCache(c)
}

// Stop stops management of RegistrationCache instance.
func (c *RegistrationCache) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.managed = false
}

// GetCleanupInterval returns cleanup interval.
func (c *RegistrationCache) GetCleanupInterval() int {
	return c.cleanupInternal
}

// GetMaxEntryLifetime returns max entry lifetime.
func (c *RegistrationCache) GetMaxEntryLifetime() int {
	return c.maxEntryLifetime
}

// Add adds user to the cache.
func (c *RegistrationCache) Add(registrationID string, u map[string]string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("registration cache is not available")
	}

	for _, field := range []string{"username", "password", "email"} {
		if _, exists := u[field]; !exists {
			return fmt.Errorf("input entry has no %s field", field)
		}
	}

	for _, m := range c.Entries {
		if m.user == nil {
			continue
		}
		for _, field := range []string{"username", "email"} {
			if m.user[field] == u[field] {
				return fmt.Errorf("a record with this %s already exists", field)
			}
		}
	}

	c.Entries[registrationID] = &RegistrationCacheEntry{
		registrationID: registrationID,
		createdAt:      time.Now().UTC(),
		user:           u,
	}
	return nil
}

// Delete removes cached user entry.
func (c *RegistrationCache) Delete(registrationID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Entries == nil {
		return errors.New("registration cache is not available")
	}
	_, exists := c.Entries[registrationID]
	if !exists {
		return errors.New("cached registration id not found")
	}
	delete(c.Entries, registrationID)
	return nil
}

// Get returns cached user entry.
func (c *RegistrationCache) Get(registrationID string) (map[string]string, error) {
	if err := parseCacheID(registrationID); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, exists := c.Entries[registrationID]; exists {
		if err := entry.Valid(c.maxEntryLifetime); err != nil {
			return nil, err
		}
		return entry.user, nil
	}
	return nil, errors.New("cached registration id not found")
}

// Expire expires a particular registration entry.
func (c *RegistrationCache) Expire(registrationID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, exists := c.Entries[registrationID]; exists {
		entry.expired = true
	}
	return
}

// Valid checks whether RegistrationCacheEntry is non-expired.
func (e *RegistrationCacheEntry) Valid(max int) error {
	if e.expired {
		return errors.New("registration cached entry is no longer in use")
	}
	diff := time.Now().UTC().Unix() - e.createdAt.Unix()
	if diff > int64(max) {
		return errors.New("registration cached entry expired")
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

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
	"fmt"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// TokenCache contains cached tokens
type TokenCache struct {
	mu      sync.RWMutex
	closed  bool
	stop    chan struct{}
	done    chan struct{}
	Entries map[string]*user.User `json:"entries,omitempty" xml:"entries,omitempty" yaml:"entries,omitempty"`
}

// NewTokenCache returns TokenCache instance.
func NewTokenCache(i int) *TokenCache {
	c := &TokenCache{
		Entries: make(map[string]*user.User),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go manageTokenCache(i, c)
	return c
}

func manageTokenCache(i int, cache *TokenCache) {
	defer close(cache.done)
	if i <= 0 {
		i = 300000
	}
	ticker := time.NewTicker(time.Millisecond * time.Duration(i))
	defer ticker.Stop()
	for {
		select {
		case <-cache.stop:
			return
		case <-ticker.C:
			cache.mu.Lock()
			for k, usr := range cache.Entries {
				if err := usr.Claims.Valid(); err != nil {
					delete(cache.Entries, k)
				}
			}
			cache.mu.Unlock()
		}
	}
}

// Close clears cached credentials and waits for the maintenance worker to stop.
// A closed cache rejects Add; repeated or concurrent Close calls are safe.
func (c *TokenCache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		clear(c.Entries)
		if c.stop != nil {
			close(c.stop)
		}
	}
	done := c.done
	c.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Add adds a token and the associated claim to cache.
func (c *TokenCache) Add(usr *user.User) error {
	if usr == nil {
		return errors.ErrCacheNilUser
	}
	if usr.Token == "" {
		return errors.ErrCacheEmptyToken
	}
	if usr.Claims == nil {
		return errors.ErrCacheNilUser
	}
	if usr.Claims.ExpiresAt == 0 {
		// If not expiration time provided, then expire within 5 minutes.
		usr.Claims.ExpiresAt = time.Now().Add(5 * time.Minute).Unix()
	}
	usr.Cached = true
	cachedUsr := usr.Clone()
	cachedUsr.Cached = true

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("token cache is closed")
	}
	if c.Entries == nil {
		c.Entries = make(map[string]*user.User)
	}
	c.Entries[usr.Token] = cachedUsr

	return nil
}

// Delete removes cached token from
func (c *TokenCache) Delete(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Entries, token)
	return nil
}

// Get returns User instance if the token associated with
// the claim exists in cache. If the token is expired, it
// will be removed from the cache.
func (c *TokenCache) Get(token string) *user.User {
	c.mu.RLock()
	usr, exists := c.Entries[token]
	if !exists {
		c.mu.RUnlock()
		return nil
	}
	if usr.Claims.ExpiresAt < time.Now().Unix() {
		c.mu.RUnlock()
		c.Delete(token)
		return nil
	}
	cachedUsr := usr.Clone()
	c.mu.RUnlock()
	return cachedUsr
}

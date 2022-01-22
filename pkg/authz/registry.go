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

package authz

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"sync"
)

var (
	gatekeeperRegistry *GatekeeperRegistry
)

func init() {
	gatekeeperRegistry = &GatekeeperRegistry{
		mu:      &sync.RWMutex{},
		entries: make(map[string]*Gatekeeper),
	}
}

// GatekeeperRegistry is a registry of authorization gateways.
type GatekeeperRegistry struct {
	mu      *sync.RWMutex
	entries map[string]*Gatekeeper
}

// Lookup returns Gatekeeper entry from the GatekeeperRegistry.
func (r *GatekeeperRegistry) Lookup(s string) (*Gatekeeper, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, exists := r.entries[s]; exists {
		return p, nil
	}
	return nil, errors.ErrGatekeeperRegistryEntryNotFound.WithArgs(s)
}

// Register registers Gatekeeper with the GatekeeperRegistry.
func (r *GatekeeperRegistry) Register(s string, p *Gatekeeper) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[s]; exists {
		return errors.ErrGatekeeperRegistryEntryExists.WithArgs(s)
	}
	r.entries[s] = p
	return nil
}

// Unregister unregisters Gatekeeper from the GatekeeperRegistry.
func (r *GatekeeperRegistry) Unregister(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[s]; !exists {
		return
	}
	delete(r.entries, s)
}

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

package authn

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"sync"
)

var (
	portalRegistry *PortalRegistry
)

func init() {
	portalRegistry = &PortalRegistry{
		mu:      &sync.RWMutex{},
		entries: make(map[string]*Portal),
	}
}

// PortalRegistry is a registry of authentication portals.
type PortalRegistry struct {
	mu      *sync.RWMutex
	entries map[string]*Portal
}

// Lookup returns Portal entry from the PortalRegistry.
func (r *PortalRegistry) Lookup(s string) (*Portal, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, exists := r.entries[s]; exists {
		return p, nil
	}
	return nil, errors.ErrPortalRegistryEntryNotFound.WithArgs(s)
}

// Register registers Portal with the PortalRegistry.
func (r *PortalRegistry) Register(s string, p *Portal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[s]; exists {
		return errors.ErrPortalRegistryEntryExists.WithArgs(s)
	}
	r.entries[s] = p
	return nil
}

// Unregister unregisters Portal from the PortalRegistry.
func (r *PortalRegistry) Unregister(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[s]; !exists {
		return
	}
	delete(r.entries, s)
}

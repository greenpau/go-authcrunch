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
		mu:          &sync.RWMutex{},
		gatekeepers: make(map[string]*Gatekeeper),
		authorizers: make(map[string]*Authorizer),
	}
}

// GatekeeperRegistry is a registry of authorization gateways.
type GatekeeperRegistry struct {
	mu          *sync.RWMutex
	gatekeepers map[string]*Gatekeeper
	authorizers map[string]*Authorizer
}

// LookupGatekeeper returns Gatekeeper entry from the GatekeeperRegistry.
func (r *GatekeeperRegistry) LookupGatekeeper(s string) (*Gatekeeper, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, exists := r.gatekeepers[s]; exists {
		return p, nil
	}
	return nil, errors.ErrGatekeeperRegistryEntryNotFound.WithArgs(s)
}

// RegisterGatekeeper registers Gatekeeper with the GatekeeperRegistry.
func (r *GatekeeperRegistry) RegisterGatekeeper(s string, p *Gatekeeper) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	existingGatekeeper, exists := r.gatekeepers[s]
	if !exists {
		r.gatekeepers[s] = p
		return nil
	}
	if existingGatekeeper.id == p.id {
		return errors.ErrGatekeeperRegistryEntryExists.WithArgs(s)
	}
	r.gatekeepers[s] = p

	for _, a := range r.authorizers {
		if a.gatekeeperID != existingGatekeeper.id {
			continue
		}
		a.gatekeeperID = p.id
		a.gatekeeper = p
	}
	return nil
}

// UnregisterGatekeeper unregisters Gatekeeper from the GatekeeperRegistry.
func (r *GatekeeperRegistry) UnregisterGatekeeper(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.gatekeepers[s]; !exists {
		return
	}
	delete(r.gatekeepers, s)
}

// RegisterAuthorizer registers Authorizer with the GatekeeperRegistry.
func (r *GatekeeperRegistry) RegisterAuthorizer(a *Authorizer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	gatekeeper, exists := r.gatekeepers[a.GatekeeperName]
	if !exists {
		return errors.ErrGatekeeperRegistryEntryExists.WithArgs(a.GatekeeperName)
	}
	a.gatekeeperID = gatekeeper.id
	r.authorizers[a.id] = a
	return nil
}

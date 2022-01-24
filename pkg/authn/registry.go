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
		mu:             &sync.RWMutex{},
		portals:        make(map[string]*Portal),
		authenticators: make(map[string]*Authenticator),
	}
}

// PortalRegistry is a registry of authentication portals.
type PortalRegistry struct {
	mu             *sync.RWMutex
	portals        map[string]*Portal
	authenticators map[string]*Authenticator
}

// LookupPortal returns Portal entry from the PortalRegistry.
func (r *PortalRegistry) LookupPortal(s string) (*Portal, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, exists := r.portals[s]; exists {
		return p, nil
	}
	return nil, errors.ErrPortalRegistryEntryNotFound.WithArgs(s)
}

// RegisterPortal registers Portal with the PortalRegistry.
func (r *PortalRegistry) RegisterPortal(s string, p *Portal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existingPortal, exists := r.portals[s]
	if !exists {
		r.portals[s] = p
		return nil
	}
	if existingPortal.id == p.id {
		return errors.ErrPortalRegistryEntryExists.WithArgs(s)
	}
	r.portals[s] = p

	for _, a := range r.authenticators {
		if a.portalID != existingPortal.id {
			continue
		}
		a.portalID = p.id
		a.portal = p
	}

	return nil
}

// UnregisterPortal unregisters Portal from the PortalRegistry.
func (r *PortalRegistry) UnregisterPortal(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.portals[s]; !exists {
		return
	}
	delete(r.portals, s)
}

// RegisterAuthenticator registers Authenticator with the PortalRegistry.
func (r *PortalRegistry) RegisterAuthenticator(a *Authenticator) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	portal, exists := r.portals[a.PortalName]
	if !exists {
		return errors.ErrPortalRegistryEntryExists.WithArgs(a.PortalName)
	}
	a.portalID = portal.id
	r.authenticators[a.id] = a
	return nil
}

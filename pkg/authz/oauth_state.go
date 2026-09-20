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

package authz

import (
	"errors"
	"fmt"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type oauthSessionState struct {
	Hash    [32]byte
	Origin  string
	User    []byte
	Expires time.Time
}

// ConfigurePersistentState restores completed OAuth sessions before this
// gatekeeper is published. Binding must cover the current policy and provider
// trust configuration. Pending exchanges remain single-process and short-lived.
// The caller owns store and closes it only after all consumers are drained.
func (g *Gatekeeper) ConfigurePersistentState(store *state.Store, binding string) error {
	if store == nil {
		return fmt.Errorf("state store is nil")
	}
	if g.oauth == nil {
		return nil
	}
	o := g.oauth
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state != nil || len(o.sessions) != 0 || len(o.logins) != 0 || o.closed {
		return fmt.Errorf("OAuth persistence must be configured before use")
	}
	record, err := store.OpenRecord("oauth-sessions/"+g.config.Name, binding)
	if err != nil {
		return err
	}
	var entries []oauthSessionState
	if _, err = record.Decode(&entries); err != nil {
		return err
	}
	if len(entries) > o.config.MaxSessions {
		return fmt.Errorf("OAuth persisted capacity exceeded")
	}
	sessions := make(map[[32]byte]oauthSession, len(entries))
	for _, entry := range entries {
		if !time.Now().Before(entry.Expires) {
			continue
		}
		u, err := user.UnmarshalSession(entry.User)
		if err != nil {
			return err
		}
		if u.Claims.Subject == "" || entry.Origin == "" {
			return fmt.Errorf("invalid OAuth session state")
		}
		if _, exists := sessions[entry.Hash]; exists {
			return fmt.Errorf("duplicate OAuth session state")
		}
		sessions[entry.Hash] = oauthSession{origin: entry.Origin, user: u, expires: entry.Expires}
	}
	o.sessions = sessions
	o.state, o.stateStore = record, store
	return nil
}

// Caller holds mu through mutation and durable commit, before publishing a
// cookie or successful revocation. A failed commit disables further decisions.
func (o *oauthAuthorization) persistSessions() error {
	if o.state == nil {
		return nil
	}
	entries := make([]oauthSessionState, 0, len(o.sessions))
	for hash, s := range o.sessions {
		if !time.Now().Before(s.expires) {
			continue
		}
		data, err := s.user.MarshalSession()
		if err != nil {
			o.closed = true
			return err
		}
		entries = append(entries, oauthSessionState{Hash: hash, Origin: s.origin, User: data, Expires: s.expires})
	}
	prepared, err := o.state.PrepareEncode(entries)
	if err != nil {
		if !errors.Is(err, state.ErrCapacity) {
			o.closed = true
		}
		return err
	}
	if err := o.state.Save(prepared); err != nil {
		o.closed = true
		return err
	}
	return nil
}

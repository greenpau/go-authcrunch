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

package authn

import (
	"fmt"
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/state"
)

// ConfigurePersistentState restores completed sessions before publication.
// The binding must cover the complete normalized configuration and upstream
// trust settings. The caller owns store; requests must drain before it closes.
// Pending authentication, MFA challenges and upstream exchanges are not restored.
func (p *Portal) ConfigurePersistentState(store *state.Store, binding string) error {
	if store == nil || p.state != nil || p.closed.Load() {
		return fmt.Errorf("portal persistence must be configured before use")
	}
	record, err := store.OpenRecord("portal-sessions/"+p.config.Name, binding)
	if err != nil {
		return err
	}
	if err = p.sessions.ConfigurePersistentState(record); err != nil {
		return err
	}
	if p.refreshStore != nil {
		record, err = store.OpenRecord("portal-refresh/"+p.config.Name, binding)
		if err != nil {
			return err
		}
		if err = p.refreshStore.ConfigurePersistentState(record); err != nil {
			return err
		}
	}
	if provider, ok := p.oidc.(interface{ ConfigurePersistentState(*state.Record) error }); ok {
		record, err = store.OpenRecord("oidc/"+p.config.Name, binding)
		if err != nil {
			return err
		}
		if err = provider.ConfigurePersistentState(record); err != nil {
			return err
		}
	}
	p.state = store
	return nil
}

func (p *Portal) persistentStateErr() error {
	if p.state == nil {
		return nil
	}
	if err := p.state.Err(); err != nil {
		return err
	}
	return p.sessions.Err()
}

// Composite login prepares several kinds of credentials before the final HTTP
// write. Suppress all of them when any later durable commit fails. Portal routes
// do not stream authentication responses; assets still pass through normally.
type persistentResponseWriter struct {
	http.ResponseWriter
	health              func() error
	wroteHeader, failed bool
}

func (w *persistentResponseWriter) unavailable() bool {
	if w.failed {
		return true
	}
	if w.health() == nil {
		return false
	}
	w.failed = true
	if !w.wroteHeader {
		clear(w.Header())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.ResponseWriter.Write([]byte("Service Unavailable\n"))
	}
	return true
}

func (w *persistentResponseWriter) WriteHeader(status int) {
	if w.wroteHeader || w.unavailable() {
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *persistentResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.unavailable() {
		return len(body), nil
	}
	return w.ResponseWriter.Write(body)
}

func (w *persistentResponseWriter) finish() {
	if !w.wroteHeader {
		w.unavailable()
	}
}

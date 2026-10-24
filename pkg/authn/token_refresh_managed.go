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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

const (
	managedRefreshPending uint32 = iota + 1
	managedRefreshReady
	managedRefreshFailed
)

// Serialize only private state-record initialization. Record's individual
// methods are locked, but Load-then-Save is not an atomic initialization. This
// protects independent standalone portals sharing one exclusively held store;
// backend activation never runs under this process-wide initialization mutex.
var managedRefreshStateMu sync.Mutex

func (p *Portal) managedRefreshUnavailable() bool {
	status := p.refreshState.Load()
	return status == managedRefreshPending || status == managedRefreshFailed
}

// A stable namespace identifies this exclusive root state, independent of its
// policy. The generation record is bound to the caller's durable changing whole
// configuration epoch. A reusable deterministic digest cannot observe an omitted
// portal/store transition and is not an adequate caller binding.
func managedRefreshGeneration(store *state.Store, binding string) (tokenrefresh.Generation, error) {
	managedRefreshStateMu.Lock()
	defer managedRefreshStateMu.Unlock()
	if store == nil || binding == "" {
		return tokenrefresh.Generation{}, fmt.Errorf("managed refresh requires persistent configuration epoch")
	}
	namespace, err := store.OpenRecord("managed-refresh/namespace", "authcrunch-managed-refresh-namespace")
	if err != nil {
		return tokenrefresh.Generation{}, err
	}
	ns, err := managedRefreshStateIdentity(namespace)
	if err != nil {
		return tokenrefresh.Generation{}, err
	}
	generation, err := store.OpenRecord("managed-refresh/generation", binding)
	if err != nil {
		return tokenrefresh.Generation{}, err
	}
	id, err := managedRefreshStateIdentity(generation)
	if err != nil {
		return tokenrefresh.Generation{}, err
	}
	return tokenrefresh.Generation{Namespace: ns, ID: id}, nil
}

func managedRefreshStateIdentity(record *state.Record) (string, error) {
	value, err := record.Load()
	if err != nil {
		return "", err
	}
	if len(value) == 0 {
		value = make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			return "", err
		}
		if err := record.Save(value); err != nil {
			return "", err
		}
	}
	if len(value) != 32 {
		return "", fmt.Errorf("invalid managed refresh state identity")
	}
	return hex.EncodeToString(value), nil
}

func (p *Portal) rejectManagedRefresh(w http.ResponseWriter, rr *requests.Request) error {
	clear(w.Header())
	rr.Response.Authenticated = false
	rr.Response.Code = http.StatusServiceUnavailable
	p.disableClientCache(w)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	return nil
}

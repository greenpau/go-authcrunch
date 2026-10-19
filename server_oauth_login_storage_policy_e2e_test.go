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

package authcrunch_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
)

type policyLoginStore struct {
	oauth.LoginStore
	creates, completes atomic.Int32
}

func (s *policyLoginStore) Create(ctx context.Context, namespace string, tx oauth.LoginTransaction) error {
	s.creates.Add(1)
	return s.LoginStore.Create(ctx, namespace, tx)
}
func (s *policyLoginStore) Complete(ctx context.Context, namespace, state, claim string) error {
	s.completes.Add(1)
	return s.LoginStore.Complete(ctx, namespace, state, claim)
}

func TestE2EServerDirectOAuthInjectedLoginStore(t *testing.T) {
	store := &policyLoginStore{LoginStore: oauth.NewMemoryLoginStore()}
	f := newDirectOAuthFixtureWithOptions(t, nil, func(c *authcrunch.Config) {
		c.IdentityProviders[0].Params["login_store"] = &oauth.LoginStoreConfig{Name: "shared", Namespace: "policy-test"}
	}, authcrunch.ServerOptions{OAuthLoginStores: map[string]oauth.LoginStore{"shared": store}})
	callback := f.callback(t, f.client, f.server.URL+"/private")
	completed := f.request(t, f.client, http.MethodGet, callback, nil)
	directOAuthStatus(t, completed, http.StatusSeeOther)
	directOAuthStatus(t, f.request(t, f.client, http.MethodGet, completed.header.Get("Location"), nil), http.StatusOK)
	if store.creates.Load() != 1 || store.completes.Load() != 1 {
		t.Fatal("direct policy did not use injected transaction store")
	}
}

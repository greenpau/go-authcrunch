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

package local

import (
	"context"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// ResolveExternalAccount atomically resolves or provisions a passwordless identity.
func (b *IdentityStore) ResolveExternalAccount(ctx context.Context, account identity.ExternalAccount, create bool) (*identity.ExternalAccountIdentity, error) {
	b.authenticator.mux.Lock()
	defer b.authenticator.mux.Unlock()
	return b.authenticator.db.ResolveExternalAccount(ctx, account, create)
}

// ConnectExternalAccount binds an external login to an independently proven account.
func (b *IdentityStore) ConnectExternalAccount(ctx context.Context, account identity.ExternalAccount, source, target requests.AuthenticationEvidence) (*identity.ExternalAccountIdentity, error) {
	b.authenticator.mux.Lock()
	defer b.authenticator.mux.Unlock()
	return b.authenticator.db.ConnectExternalAccount(ctx, account, source, target)
}

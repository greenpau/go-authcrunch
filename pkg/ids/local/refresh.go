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

// WithRefreshIdentity implements the optional portal refresh capability. The
// authenticator lock also serializes database replacement during reload.
func (b *IdentityStore) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	b.authenticator.mux.Lock()
	defer b.authenticator.mux.Unlock()
	return b.authenticator.db.WithRefreshIdentity(ctx, proof, apply)
}

// RevokeUserSessions invalidates refresh sessions by immutable identity ID.
func (b *IdentityStore) RevokeUserSessions(ctx context.Context, userID string) error {
	b.authenticator.mux.Lock()
	defer b.authenticator.mux.Unlock()
	return b.authenticator.db.RevokeUserSessions(ctx, userID)
}

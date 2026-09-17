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

package oidc

import (
	"context"
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Authentication is completed, server-side login evidence, never client claims.
// Evidence.UserID is immutable within Backend and Realm. Evidence.AuthenticatedAt
// is the original authentication time. Methods and Challenges describe the actual
// completed authentication; the verifier must check current challenge requirements.
type Authentication struct {
	Realm, Backend, Username string                          `json:"-" xml:"-" yaml:"-"`
	Evidence                 requests.AuthenticationEvidence `json:"-" xml:"-" yaml:"-"`
	Methods, Challenges      []string                        `json:"-" xml:"-" yaml:"-"`
}

// Identity contains current, verified user attributes for scoped UserInfo output.
// EmailVerified must be true only when the identity backend has verified ownership.
type Identity struct {
	Profile               *identity.Profile `json:"-" xml:"-" yaml:"-"`
	Username, Name, Email string            `json:"-" xml:"-" yaml:"-"`
	EmailVerified         bool              `json:"-" xml:"-" yaml:"-"`
}

// IdentityVerifier connects a provider to an application's identity backend.
// WithIdentity must validate immutable identity, account status, credential and
// backend versions, and current authentication policy against the supplied proof.
// On success it invokes apply exactly once, synchronously, while keeping identity
// revocation serialized with the callback's credential issuance. On denial it must
// return ErrIdentityDenied without invoking apply. It must propagate apply's error.
// Complete all fallible backend work before apply; once invoked, return its result
// without further fallible work, because the callback commits provider state.
// The provider holds its state lock during this call: do not reenter the provider.
// Neither the callback nor its identity data may be retained after the call.
type IdentityVerifier interface {
	WithIdentity(context.Context, Authentication, func(Identity) error) error
}

// OpenIDProvider is the public HTTP and browser-session integration contract.
// NewProvider returns the concrete Provider implementation. Embedding applications
// own authentication and logout authorization; the provider owns protocol state.
type OpenIDProvider interface {
	http.Handler
	HandleHTTP(http.ResponseWriter, *http.Request) bool
	ValidateLoginRequest(http.ResponseWriter, *http.Request) bool
	CompleteLogin(context.Context, http.ResponseWriter, *http.Request, Authentication) error
	Logout(http.ResponseWriter, *http.Request)
	ClearSession(http.ResponseWriter, *http.Request)
	SupportsRealm(string) bool
	Discovery() map[string]any
	JWKS() map[string]any
	Close()
}

var _ OpenIDProvider = (*Provider)(nil)

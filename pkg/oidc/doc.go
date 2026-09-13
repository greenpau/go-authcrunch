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

// Package oidc implements a reusable OpenID Provider with authorization code,
// PKCE, consent, discovery, JWKS, UserInfo, and revocation endpoints.
//
// NewProvider accepts registered clients and an IdentityVerifier that validates
// trusted login evidence and serializes credential issuance with account changes.
// Applications serve the Provider as an http.Handler, authenticate users at the
// configured LoginURL, and call CompleteLogin after all required challenges pass.
// HandleHTTP supports integration with a larger router. Logout and ClearSession
// connect the application's authorized browser lifecycle to provider state.
//
// Configuration is snapshotted at construction. Provider state is bounded and
// process-local; restarting the application requires new browser authentication.
package oidc

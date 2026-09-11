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

// Package authclient authenticates clients through an AuthCrunch portal's JSON
// login endpoint. It does not require the admin API or perform database operations.
//
// NewClient and Client.Authenticate provide password, TOTP, and API key authentication.
// Applications supply any interactive input through Options.Prompt and decide
// whether to retain the returned Credentials in memory or persist them using a
// FileTokenStore. Configuration discovery, application directories, terminal
// interaction, logging, and command dispatch belong to the calling application.
//
// Credentials are opaque: this package neither validates JWT claims nor renews
// refresh tokens. Authenticate performs a fresh login and returns only credentials
// issued by that login. U2F/WebAuthn challenges are currently unsupported.
// APIKey selects a separate access-only login, without username/password or MFA
// prompts. The portal derives the identity from the key; no refresh token is issued.
package authclient

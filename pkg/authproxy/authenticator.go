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

package authproxy

import "context"

// Authenticator is an interface to an identity store.
type Authenticator interface {
	GetName() string
	BasicAuth(*Request) error
	APIKeyAuth(*Request) error
}

// ContextAuthenticator optionally propagates the protected HTTP request deadline.
// Legacy authenticators retain the original interface and their own timeout.
type ContextAuthenticator interface {
	Authenticator
	BasicAuthContext(context.Context, *Request) error
	APIKeyAuthContext(context.Context, *Request) error
}

// FreshAuthenticator opts out of credential result caching. Implementations
// return a stable value for their lifetime; runtime reconfiguration is not safe.
type FreshAuthenticator interface {
	Authenticator
	RequireFreshAuthentication() bool
}

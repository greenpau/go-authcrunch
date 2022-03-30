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

package idp

import (
	"fmt"
)

// IdentityProviderType identifies identity provider type.
type IdentityProviderType int

const (
	// UNKNOWN identifies unknown identity provider type.
	UNKNOWN IdentityProviderType = iota
	// OAUTH identifies OAuth-based identity provider.
	OAUTH
	// SAML identifies SAML-based identity provider.
	SAML
)

// String returns the description for IdentityProviderType enum.
func (m IdentityProviderType) String() string {
	switch m {
	case UNKNOWN:
		return "UNKNOWN"
	case OAUTH:
		return "OAUTH"
	case SAML:
		return "SAML"
	}
	return fmt.Sprintf("IdentityProviderType(%d)", int(m))
}

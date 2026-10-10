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

package cookie

import (
	"encoding/base64"
	"net/http"
)

// SAMLSessionIDCookieNameForState names one transaction's browser proof. State
// must be the canonical 256-bit RelayState emitted by the SAML provider.
func (f *Factory) SAMLSessionIDCookieNameForState(state string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != state {
		return ""
	}
	return f.SAMLSessionIDCookieName + "_" + state
}

// GetSAMLSessionIDCookieForState issues proof without replacing another login's
// cookie. Its lifetime and attributes match the provider's transaction.
func (f *Factory) GetSAMLSessionIDCookieForState(value, state string) string {
	name := f.SAMLSessionIDCookieNameForState(state)
	if name == "" {
		return ""
	}
	return (&http.Cookie{Name: name, Value: value, Path: "/", MaxAge: 300, Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode}).String()
}

// GetDeleteSAMLSessionIDCookieForState consumes only the completed login's proof.
func (f *Factory) GetDeleteSAMLSessionIDCookieForState(state string) string {
	issued := f.GetSAMLSessionIDCookieForState("delete", state)
	if issued == "" {
		return ""
	}
	return deletionCookie(issued)
}

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

package cookie

import (
	"net/http"
	"strings"
	"time"
)

// deletionCookie expires an issued cookie without changing its scope or security
// attributes. Max-Age takes precedence over Expires, so both must expire it.
func deletionCookie(raw string) string {
	c, err := http.ParseSetCookie(raw)
	if err != nil {
		return ""
	}
	c.Value = "delete"
	c.MaxAge = -1
	c.Expires = time.Unix(0, 0).UTC()
	return c.String()
}

// GetDeleteAccessTokenCookie expires the access cookie for the selected host.
func (f *Factory) GetDeleteAccessTokenCookie(h string) string {
	return deletionCookie(f.GetAccessTokenCookie(h, "delete"))
}

// GetDeleteSessionIDCookie expires the session cookie for the selected host.
func (f *Factory) GetDeleteSessionIDCookie(h string) string {
	return deletionCookie(f.GetSessionIDCookie(h, "delete"))
}

// GetDeleteSAMLSessionIDCookie expires the host-only SAML browser binding.
func (f *Factory) GetDeleteSAMLSessionIDCookie() string {
	return deletionCookie(f.GetSAMLSessionIDCookie("delete"))
}

// GetDeleteIdentityTokenCookie expires the provider-owned identity cookie name
// at the same whoami path used by GetIdentityTokenCookie.
func (f *Factory) GetDeleteIdentityTokenCookie(name, basePath string) string {
	return deletionCookie(f.GetIdentityTokenCookie(basePath, name, "delete"))
}

// GetDeleteRefreshTokenCookie expires the legacy refresh cookie. An empty result
// means no compatible legacy scope exists: __Host- cookies cannot have the
// legacy api/refresh_token path. Callers must omit empty headers and separately
// expire the active refresh cookie at its configured mount.
func (f *Factory) GetDeleteRefreshTokenCookie(basePath string) string {
	if strings.HasPrefix(strings.ToLower(f.RefreshTokenCookieName), "__host-") {
		return ""
	}
	raw := f.GetRefreshTokenCookie(basePath, "delete")
	// Active refresh cookies always require Secure, even when ordinary portal
	// cookies use insecure mode. Preserve the existing legacy prefix cleanup.
	if strings.HasPrefix(strings.ToLower(f.RefreshTokenCookieName), "__secure-") && f.config.Insecure {
		raw += " Secure; HttpOnly;"
	}
	return deletionCookie(raw)
}

// GetDeleteSandboxIDCookie expires the sandbox cookie at the portal path.
func (f *Factory) GetDeleteSandboxIDCookie(basePath string) string {
	return deletionCookie(f.GetSandboxIDCookie(basePath, "delete"))
}

// GetDeleteRefererCookie expires the referer cookie at the portal path.
func (f *Factory) GetDeleteRefererCookie(basePath string) string {
	return deletionCookie(f.GetRefererCookie(basePath, "delete"))
}

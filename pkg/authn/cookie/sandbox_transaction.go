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

import "net/http"

// SandboxIDCookieNameForSession returns the independent browser proof name for
// a generated sandbox ID. Malformed IDs return an empty name. IDs select state;
// only the independently generated cookie value proves possession.
func (f *Factory) SandboxIDCookieNameForSession(id string) string {
	if len(id) < 36 || len(id) >= 48 {
		return ""
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return ""
		}
	}
	return f.SandboxIDCookieName + "_" + id
}

// GetSandboxIDCookieForSession issues a host-only proof at the portal mount.
// Its five-minute lifetime is independent of the ordinary session lifetime.
// HttpOnly and SameSite=Lax apply even when legacy insecure mode is enabled.
func (f *Factory) GetSandboxIDCookieForSession(basePath, value, id string) string {
	name := f.SandboxIDCookieNameForSession(id)
	if name == "" {
		return ""
	}
	return (&http.Cookie{Name: name, Value: value, Path: portalCookiePath(basePath),
		MaxAge: 300, Secure: !f.config.Insecure, HttpOnly: true, SameSite: http.SameSiteLaxMode}).String()
}

// GetDeleteSandboxIDCookieForSession expires only the selected sandbox proof.
func (f *Factory) GetDeleteSandboxIDCookieForSession(basePath, id string) string {
	issued := f.GetSandboxIDCookieForSession(basePath, "delete", id)
	if issued == "" {
		return ""
	}
	return deletionCookie(issued)
}

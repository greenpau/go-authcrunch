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

// GetCrossDeviceSessionIDCookie binds the approving browser to a pending login.
// Security and the five-minute lifetime are independent of ordinary cookies.
func (f *Factory) GetCrossDeviceSessionIDCookie(basePath, value string) string {
	return (&http.Cookie{Name: f.CrossDeviceSessionIDCookieName, Value: value,
		Path: portalCookiePath(basePath), MaxAge: 300, Secure: true,
		HttpOnly: true, SameSite: http.SameSiteNoneMode}).String()
}

// GetDeleteCrossDeviceSessionIDCookie expires the matching browser binding.
func (f *Factory) GetDeleteCrossDeviceSessionIDCookie(basePath string) string {
	return deletionCookie(f.GetCrossDeviceSessionIDCookie(basePath, "delete"))
}

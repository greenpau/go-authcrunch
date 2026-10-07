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
	"fmt"
	"net/http"
	"strings"
)

// ValidateProviderLoginCookieName validates independently owned protocol state
// against portal credential names. Protocol cookies are always Secure, regardless
// of the common cookie configuration. Empty declares a cookieless protocol.
func (f *Factory) ValidateProviderLoginCookieName(name, path string) error {
	if name == "" {
		return nil
	}
	if len(name) > 128 || (&http.Cookie{Name: name}).Valid() != nil {
		return fmt.Errorf("invalid provider login cookie name")
	}
	if err := ValidatePrefix(name, "", path, true); err != nil {
		return err
	}
	for _, reserved := range f.cookieNames() {
		if strings.EqualFold(name, reserved) {
			return fmt.Errorf("provider login cookie conflicts with portal cookie")
		}
	}
	return nil
}

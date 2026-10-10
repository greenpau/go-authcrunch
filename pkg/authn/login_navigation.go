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

package authn

import (
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
)

// bindLoginNavigation supplies validated navigation independently of the theme's
// age. Templates keep their existing data keys, while the renderer also carries
// an explicit empty choice so another tab's cookie cannot take over later.
func (p *Portal) bindLoginNavigation(args *ui.Args, r *http.Request, destination string) {
	nav := &ui.LoginNavigation{ReturnURL: destination, PagePath: r.URL.Path, Fresh: r.URL.Query().Get("fresh") == "1"}
	if authenticators, ok := p.loginOptions["authenticators"].([]map[string]string); ok {
		for _, authenticator := range authenticators {
			if authenticator["login_return_url_enabled"] == "yes" {
				nav.ProviderPaths = append(nav.ProviderPaths, authenticator["endpoint"])
			}
		}
	}
	args.LoginNavigation = nav
}

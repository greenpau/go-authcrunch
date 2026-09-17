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

package authn

import (
	"context"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

// Use the existing portal factory so the OIDC alias honors metadata, branding,
// filesystem template overrides and the same-origin custom stylesheet.
func (p *Portal) renderOIDCPage(_ context.Context, page oidc.Page) ([]byte, error) {
	args := p.ui.GetArgs()
	args.BaseURL(page.BasePath)
	args.PageTitle = page.Title
	args.Data["oidc"] = page
	body, err := p.ui.Render("oidc", args)
	if err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

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
	"fmt"
	"sort"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Factory holds configuration and associated finctions
// for the cookies issued by authn.Authenticator.
type Factory struct {
	config                  *Config
	domains                 []string
	CookieNamePrefix        string `json:"cookie_name_prefix,omitempty" xml:"cookie_name_prefix,omitempty" yaml:"cookie_name_prefix,omitempty"`
	RefererCookieName       string `json:"referer_cookie_name,omitempty" xml:"referer_cookie_name,omitempty" yaml:"referer_cookie_name,omitempty"`
	SessionIDCookieName     string `json:"session_id_cookie_name,omitempty" xml:"session_id_cookie_name,omitempty" yaml:"session_id_cookie_name,omitempty"`
	SandboxIDCookieName     string `json:"sandbox_id_cookie_name,omitempty" xml:"sandbox_id_cookie_name,omitempty" yaml:"sandbox_id_cookie_name,omitempty"`
	IdentityTokenCookieName string `json:"identity_token_cookie_name,omitempty" xml:"identity_token_cookie_name,omitempty" yaml:"identity_token_cookie_name,omitempty"`
	AccessTokenCookieName   string `json:"access_token_cookie_name,omitempty" xml:"access_token_cookie_name,omitempty" yaml:"access_token_cookie_name,omitempty"`
	RefreshTokenCookieName  string `json:"refresh_token_cookie_name,omitempty" xml:"refresh_token_cookie_name,omitempty" yaml:"refresh_token_cookie_name,omitempty"`
}

// NewFactory returns an instance of cookie factory.
func NewFactory(c *Config) (*Factory, error) {
	f := &Factory{}
	if c == nil {
		f.config = NewConfig()
	} else {
		f.config = c
	}
	if f.config.Domains != nil {
		domains := []string{}
		domainList := []*DomainConfig{}
		for _, v := range f.config.Domains {
			domainList = append(domainList, v)
		}
		sort.SliceStable(domainList, func(i, j int) bool {
			return domainList[i].Seq < domainList[j].Seq
		})
		for _, v := range domainList {
			domains = append(domains, v.Domain)
		}
		f.domains = domains
	}

	f.config.ApplyDefaults()

	f.CookieNamePrefix = f.config.CookieNamePrefix
	f.RefererCookieName = f.config.RefererCookieName
	f.SessionIDCookieName = f.config.SessionIDCookieName
	f.SandboxIDCookieName = f.config.SandboxIDCookieName
	f.IdentityTokenCookieName = f.config.IdentityTokenCookieName
	f.AccessTokenCookieName = f.config.AccessTokenCookieName
	f.RefreshTokenCookieName = f.config.RefreshTokenCookieName

	switch strings.ToLower(f.config.SameSite) {
	case "":
	case "lax", "strict", "none":
		caser := cases.Title(language.English)
		f.config.SameSite = caser.String(f.config.SameSite)
	default:
		return nil, fmt.Errorf("the SameSite cookie attribute %q is invalid", f.config.SameSite)
	}

	hasOverlaps, duplicate := f.HasCookieNameOverlaps()
	if hasOverlaps {
		return nil, fmt.Errorf("found duplicate cookie names: %v", duplicate)
	}

	return f, nil
}

// HasCookieNameOverlaps checks if any cookie names are identical.
func (f *Factory) HasCookieNameOverlaps() (bool, string) {
	checkMap := map[string]string{
		"RefererCookieName":       f.RefererCookieName,
		"SessionIDCookieName":     f.SessionIDCookieName,
		"SandboxIDCookieName":     f.SandboxIDCookieName,
		"IdentityTokenCookieName": f.IdentityTokenCookieName,
		"AccessTokenCookieName":   f.AccessTokenCookieName,
		"RefreshTokenCookieName":  f.RefreshTokenCookieName,
	}

	// seen stores: [cookie_value] -> field_name
	seen := make(map[string]string)

	for fieldName, cookieValue := range checkMap {
		if cookieValue == "" {
			continue
		}

		if existingField, exists := seen[cookieValue]; exists {
			// Found a mismatch/duplicate!
			return true, fmt.Sprintf(
				"duplicate cookie name %q found in both %q and %q",
				cookieValue,
				existingField,
				fieldName,
			)
		}
		seen[cookieValue] = fieldName
	}

	return false, ""
}

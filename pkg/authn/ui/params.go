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

package ui

// Parameters represent a common set of configuration settings
// for HTML UI.
type Parameters struct {
	Theme                   string            `json:"theme,omitempty" xml:"theme,omitempty" yaml:"theme,omitempty"`
	Templates               map[string]string `json:"templates,omitempty" xml:"templates,omitempty" yaml:"templates,omitempty"`
	AllowRoleSelection      bool              `json:"allow_role_selection,omitempty" xml:"allow_role_selection,omitempty" yaml:"allow_role_selection,omitempty"`
	Title                   string            `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	LogoURL                 string            `json:"logo_url,omitempty" xml:"logo_url,omitempty" yaml:"logo_url,omitempty"`
	LogoDescription         string            `json:"logo_description,omitempty" xml:"logo_description,omitempty" yaml:"logo_description,omitempty"`
	PrivateLinks            []Link            `json:"private_links,omitempty" xml:"private_links,omitempty" yaml:"private_links,omitempty"`
	AutoRedirectURL         string            `json:"auto_redirect_url,omitempty" xml:"auto_redirect_url,omitempty" yaml:"auto_redirect_url,omitempty"`
	Realms                  []UserRealm       `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
	PasswordRecoveryEnabled bool              `json:"password_recovery_enabled,omitempty" xml:"password_recovery_enabled,omitempty" yaml:"password_recovery_enabled,omitempty"`
	CustomCSSPath           string            `json:"custom_css_path,omitempty" xml:"custom_css_path,omitempty" yaml:"custom_css_path,omitempty"`
	CustomJsPath            string            `json:"custom_js_path,omitempty" xml:"custom_js_path,omitempty" yaml:"custom_js_path,omitempty"`
	Language                string            `json:"language,omitempty" xml:"language,omitempty" yaml:"language,omitempty"`
}

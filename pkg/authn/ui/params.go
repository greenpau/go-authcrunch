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

import (
	"fmt"
)

// NavigationItem represents side navigation menu item.
type NavigationItem struct {
	Name     string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Path     string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Active   bool   `json:"active,omitempty" xml:"active,omitempty" yaml:"active,omitempty"`
	IconName string `json:"icon_name,omitempty" xml:"icon_name,omitempty" yaml:"icon_name,omitempty"`
}

// Parameters represent a common set of configuration settings
// for HTML UI.
type Parameters struct {
	Theme                   string            `json:"theme,omitempty" xml:"theme,omitempty" yaml:"theme,omitempty"`
	Templates               map[string]string `json:"templates,omitempty" xml:"templates,omitempty" yaml:"templates,omitempty"`
	AllowRoleSelection      bool              `json:"allow_role_selection,omitempty" xml:"allow_role_selection,omitempty" yaml:"allow_role_selection,omitempty"`
	Title                   string            `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	LogoURL                 string            `json:"logo_url,omitempty" xml:"logo_url,omitempty" yaml:"logo_url,omitempty"`
	LogoDescription         string            `json:"logo_description,omitempty" xml:"logo_description,omitempty" yaml:"logo_description,omitempty"`
	MetaTitle               string            `json:"meta_title,omitempty" xml:"meta_title,omitempty" yaml:"meta_title,omitempty"`
	MetaDescription         string            `json:"meta_description,omitempty" xml:"meta_description,omitempty" yaml:"meta_description,omitempty"`
	MetaAuthor              string            `json:"meta_author,omitempty" xml:"meta_author,omitempty" yaml:"meta_author,omitempty"`
	PrivateLinks            []Link            `json:"private_links,omitempty" xml:"private_links,omitempty" yaml:"private_links,omitempty"`
	AutoRedirectURL         string            `json:"auto_redirect_url,omitempty" xml:"auto_redirect_url,omitempty" yaml:"auto_redirect_url,omitempty"`
	Realms                  []UserRealm       `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
	PasswordRecoveryEnabled bool              `json:"password_recovery_enabled,omitempty" xml:"password_recovery_enabled,omitempty" yaml:"password_recovery_enabled,omitempty"`
	CustomCSSPath           string            `json:"custom_css_path,omitempty" xml:"custom_css_path,omitempty" yaml:"custom_css_path,omitempty"`
	CustomJsPath            string            `json:"custom_js_path,omitempty" xml:"custom_js_path,omitempty" yaml:"custom_js_path,omitempty"`
	CustomHTMLHeaderPath    string            `json:"custom_html_header_path,omitempty" xml:"custom_html_header_path,omitempty" yaml:"custom_html_header_path,omitempty"`
	StaticAssets            []StaticAsset     `json:"static_assets,omitempty" xml:"static_assets,omitempty" yaml:"static_assets,omitempty"`
	Language                string            `json:"language,omitempty" xml:"language,omitempty" yaml:"language,omitempty"`
	DisabledPages           map[string]bool   `json:"disabled_pages,omitempty" xml:"disabled_pages,omitempty" yaml:"disabled_pages,omitempty"`
}

// DisablePage disables a specific page.
func (p *Parameters) DisablePage(args []string) error {
	pages := map[string]bool{
		"settings": true,
	}

	if len(args) < 2 {
		return fmt.Errorf("invalid syntax: too few arguments")
	}

	if _, exists := pages[args[0]]; !exists {
		return fmt.Errorf("invalid syntax: %s is not supported", args[0])
	}

	if p.DisabledPages == nil {
		p.DisabledPages = make(map[string]bool)
	}

	for _, arg := range args[1:] {
		p.DisabledPages[args[0]+"/"+arg] = true
	}

	return nil
}

// IsDisabledPage checks whether a specific page is disabled.
func (p *Parameters) IsDisabledPage(s string) bool {
	if p.DisabledPages == nil {
		return false
	}
	if _, exists := p.DisabledPages[s]; !exists {
		return false
	}
	return true
}

// GetNavigationItems return items for nav menu.
func (p *Parameters) GetNavigationItems(s string) []*NavigationItem {
	var navItems []*NavigationItem
	for _, entry := range []string{
		"settings/",
		"settings/sshkeys",
		"settings/gpgkeys",
		"settings/apikeys",
		"settings/mfa",
		"settings/password",
		"settings/connected",
	} {
		if p.IsDisabledPage(entry) {
			continue
		}
		navItem := &NavigationItem{
			Path: "/" + entry,
		}
		if s == entry {
			navItem.Active = true
		}
		switch entry {
		case "settings/":
			navItem.Name = "Profile"
			navItem.IconName = "las la-user-circle"
		case "settings/sshkeys":
			navItem.Name = "SSH Keys"
			navItem.IconName = "las la-server"
		case "settings/gpgkeys":
			navItem.Name = "GPG Keys"
			navItem.IconName = "las la-key"
		case "settings/apikeys":
			navItem.Name = "API Keys"
			navItem.IconName = "las la-stream"
		case "settings/mfa":
			navItem.Name = "MFA"
			navItem.IconName = "las la-microchip"
		case "settings/password":
			navItem.Name = "Password"
			navItem.IconName = "las la-fingerprint"
		case "settings/connected":
			navItem.Name = "Connected Accounts"
			navItem.IconName = "las la-share-alt"
		}
		navItems = append(navItems, navItem)
	}
	return navItems
}

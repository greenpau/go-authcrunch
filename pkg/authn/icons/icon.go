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

package icons

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// LoginIcon represents an icon associated with an identity store or provider.
type LoginIcon struct {
	Realm               string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Endpoint            string `json:"endpoint,omitempty" xml:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Priority            int    `json:"priority,omitempty" xml:"priority,omitempty" yaml:"priority,omitempty"`
	ClassName           string `json:"class_name,omitempty" xml:"class_name,omitempty" yaml:"class_name,omitempty"`
	Color               string `json:"color,omitempty" xml:"color,omitempty" yaml:"color,omitempty"`
	BackgroundColor     string `json:"background_color,omitempty" xml:"background_color,omitempty" yaml:"background_color,omitempty"`
	Text                string `json:"text,omitempty" xml:"text,omitempty" yaml:"text,omitempty"`
	TextColor           string `json:"text_color,omitempty" xml:"text_color,omitempty" yaml:"text_color,omitempty"`
	TextBackgroundColor string `json:"text_background_color,omitempty" xml:"text_background_color,omitempty" yaml:"text_background_color,omitempty"`

	// RegistrationEnabled controls whether visitors can registers.
	RegistrationEnabled bool `json:"registration_enabled,omitempty" xml:"registration_enabled,omitempty" yaml:"registration_enabled,omitempty"`
	// UsernameRecoveryEnabled controls whether a user could recover username by providing an email address.
	UsernameRecoveryEnabled bool `json:"username_recovery_enabled,omitempty" xml:"username_recovery_enabled,omitempty" yaml:"username_recovery_enabled,omitempty"`
	// PasswordRecoveryEnabled controls whether a user could recover password by providing an email address.
	PasswordRecoveryEnabled bool `json:"password_recovery_enabled,omitempty" xml:"password_recovery_enabled,omitempty" yaml:"password_recovery_enabled,omitempty"`
	// ContactSupportEnabled controls whether contact support link is available.
	ContactSupportEnabled bool `json:"contact_support_enabled,omitempty" xml:"contact_support_enabled,omitempty" yaml:"contact_support_enabled,omitempty"`

	// SupportLink is the link to the support portal.
	SupportLink string `json:"support_link,omitempty" xml:"support_link,omitempty" yaml:"support_link,omitempty"`
	// SupportEmail is the email address to reach support.
	SupportEmail string `json:"support_email,omitempty" xml:"support_email,omitempty" yaml:"support_email,omitempty"`
}

// NewLoginIcon returns an instance of LoginIcon.
func NewLoginIcon(s string) *LoginIcon {
	icon := &LoginIcon{}
	icon.Configure(s)
	return icon
}

// Configure sets defaults for an instance of LoginIcon.
func (icon *LoginIcon) Configure(s string) {
	if icon.ClassName == "" {
		switch s {
		case "google":
			icon.ClassName = "lab la-google la-2x"
		case "facebook":
			icon.ClassName = "lab la-facebook la-2x"
		case "linkedin":
			icon.ClassName = "lab la-linkedin la-2x"
		case "github":
			icon.ClassName = "lab la-github la-2x"
		case "gitlab":
			icon.ClassName = "lab la-gitlab la-2x"
		case "windows":
			icon.ClassName = "lab la-windows la-2x"
		case "azure":
			icon.ClassName = "lab la-windows la-2x"
		case "aws", "cognito":
			icon.ClassName = "lab la-aws la-2x"
		case "amazon":
			icon.ClassName = "lab la-amazon la-2x"
		case "ldap":
			icon.ClassName = "las la-shield-alt la-2x"
		case "local":
			icon.ClassName = "las la-key la-2x"
		default:
			icon.ClassName = "lab la-codepen la-2x"
		}
	}

	if icon.Color == "" {
		switch s {
		// case "google":
		// case "facebook":
		// case "linkedin":
		// case "gitlab":
		// case "windows":
		// case "azure":
		// case "aws", "cognito":
		// case "amazon":
		case "github":
			icon.Color = "#f6f8fa"
		case "ldap":
			icon.Color = "white"
		case "local":
			icon.Color = "white"
		default:
			icon.Color = "white"
		}
	}

	if icon.BackgroundColor == "" {
		switch s {
		case "google":
			// MaterializeCSS "red darken-1"
			icon.BackgroundColor = "#e53935"
		case "facebook":
			// MaterializeCSS "blue darken-4"
			icon.BackgroundColor = "#0d47a1"
		case "linkedin":
			// MaterializeCSS "blue darken-1"
			icon.BackgroundColor = "#1e88e5"
		case "gitlab":
			icon.BackgroundColor = "#fc6d26"
		case "github":
			icon.BackgroundColor = "#24292f"
		case "windows":
			// MaterializeCSS "orange darken-1"
			icon.BackgroundColor = "#fb8c00"
		case "azure":
			// MaterializeCSS "blue"
			icon.BackgroundColor = "#03a9f4"
		case "aws", "amazon", "cognito":
			// MaterializeCSS "blue-grey darken-2"
			icon.BackgroundColor = "#455a64"
		case "ldap":
			icon.BackgroundColor = "#324960"
		case "local":
			icon.BackgroundColor = "#324960"
		default:
			icon.BackgroundColor = "#324960"
		}
	}

	if icon.Text == "" {
		switch s {
		case "google":
			icon.Text = "Google"
		case "facebook":
			icon.Text = "Facebook"
		case "linkedin":
			icon.Text = "LinkedIn"
		case "github":
			icon.Text = "Github"
		case "windows":
			icon.Text = "Microsoft"
		case "azure":
			icon.Text = "Azure"
		case "aws", "cognito":
			icon.Text = "AWS"
		case "amazon":
			icon.Text = "Amazon"
		default:
			icon.Text = icon.Realm
		}
	}

	if icon.TextColor == "" {
		switch s {
		default:
			icon.TextColor = "#37474f"
		}
	}

	if icon.BackgroundColor == "" {
		switch s {
		case "google":
			// MaterializeCSS "red darken-1"
			icon.BackgroundColor = "#e53935"
		case "facebook":
			// MaterializeCSS "blue darken-4"
			icon.BackgroundColor = "#0d47a1"
		case "linkedin":
			// MaterializeCSS "blue darken-1"
			icon.BackgroundColor = "#1e88e5"
		case "github":
			icon.BackgroundColor = "#24292f"
		case "windows":
			// MaterializeCSS "orange darken-1"
			icon.BackgroundColor = "#fb8c00"
		case "azure":
			// MaterializeCSS "blue"
			icon.BackgroundColor = "#03a9f4"
		case "aws", "amazon", "cognito":
			// MaterializeCSS "blue-grey darken-2"
			icon.BackgroundColor = "#455a64"
		case "ldap":
			icon.BackgroundColor = "#324960"
		case "local":
			icon.BackgroundColor = "#324960"
		default:
			icon.BackgroundColor = "#324960"
		}
	}

	return
}

// SetRealm sets the realm associated with the icon.
func (icon *LoginIcon) SetRealm(s string) {
	icon.Realm = s
	if icon.Text == "" {
		icon.Text = strings.ToUpper(s)
	}
}

// SetEndpoint sets the endpoint associated with the icon.
func (icon *LoginIcon) SetEndpoint(s string) {
	icon.Endpoint = s
}

// GetConfig returns icon configuration.
func (icon *LoginIcon) GetConfig() map[string]string {
	cfg := make(map[string]string)
	var entries map[string]interface{}
	j, _ := json.Marshal(icon)
	json.Unmarshal(j, &entries)
	for k, v := range entries {
		switch {
		case k == "priority":
		case strings.HasSuffix(k, "_enabled"):
			if v.(bool) {
				cfg[k] = "yes"
			} else {
				cfg[k] = "no"
			}
		default:
			cfg[k] = v.(string)
		}
	}
	return cfg
}

// Parse parses input and outputs login icon config.
func Parse(args []string) (map[string]interface{}, error) {
	section := "icon"
	cfg := make(map[string]interface{})
	icon := &LoginIcon{}
	if len(args) < 1 {
		return nil, fmt.Errorf("too few arguments")
	}

	var cursor, sectionCursor int
	for {
		if cursor >= len(args) {
			break
		}
		switch {
		case args[cursor] == "priority":
			section = "priority"
			sectionCursor = 0
		case args[cursor] == "text":
			section = "text"
			sectionCursor = 0
		case sectionCursor == 0 && section == "priority":
			i, err := strconv.Atoi(args[cursor])
			if err != nil {
				return nil, err
			}
			icon.Priority = i
		case sectionCursor == 0 && section == "icon":
			icon.Text = args[0]
			sectionCursor++
		case sectionCursor == 1 && section == "icon":
			icon.ClassName = args[cursor]
			sectionCursor++
		case sectionCursor == 2 && section == "icon":
			icon.Color = args[cursor]
			sectionCursor++
		case sectionCursor == 3 && section == "icon":
			icon.BackgroundColor = args[cursor]
			sectionCursor++
		case sectionCursor == 0 && section == "text":
			icon.TextColor = args[cursor]
			sectionCursor++
		case sectionCursor == 1 && section == "text":
			icon.TextBackgroundColor = args[cursor]
			sectionCursor++
		}
		cursor++
	}

	j, _ := json.Marshal(icon)
	json.Unmarshal(j, &cfg)
	return cfg, nil
}

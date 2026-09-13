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

package parser

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
)

type directiveField struct {
	text     *string
	list     *[]string
	integer  *int
	state    *bool
	inverted bool
}

func newOAuthFields(c *oauth.Config) map[string]*directiveField {
	return map[string]*directiveField{
		"realm":                      {text: &c.Realm},
		"driver":                     {text: &c.Driver},
		"domain_name":                {text: &c.DomainName},
		"client_id":                  {text: &c.ClientID},
		"client_secret":              {text: &c.ClientSecret},
		"server_id":                  {text: &c.ServerID},
		"tenant_id":                  {text: &c.TenantID},
		"user_pool_id":               {text: &c.UserPoolID},
		"region":                     {text: &c.Region},
		"issuer":                     {text: &c.Issuer},
		"access_token_audience":      {text: &c.AccessTokenAudience},
		"base_auth_url":              {text: &c.BaseAuthURL},
		"metadata_url":               {text: &c.MetadataURL},
		"authorization_url":          {text: &c.AuthorizationURL},
		"token_url":                  {text: &c.TokenURL},
		"logout_url":                 {text: &c.LogoutURL},
		"identity_token_cookie_name": {text: &c.IdentityTokenCookieName},
		"identity_token_field_name":  {text: &c.IdentityTokenFieldName},
		"user_info_roles_field_name": {text: &c.UserInfoRolesFieldName},
		"scopes":                     {list: &c.Scopes},
		"required_token_fields":      {list: &c.RequiredTokenFields},
		"response_type":              {list: &c.ResponseType},
		"user_group_filters":         {list: &c.UserGroupFilters},
		"user_org_filters":           {list: &c.UserOrgFilters},
		"user_info_fields":           {list: &c.UserInfoFields},
		"delay_start":                {integer: &c.DelayStart},
		"retry_attempts":             {integer: &c.RetryAttempts},
		"retry_interval":             {integer: &c.RetryInterval},
		"metadata discovery":         {state: &c.MetadataDiscoveryDisabled, inverted: true},
		"key verification":           {state: &c.KeyVerificationDisabled, inverted: true},
		"pass grant type":            {state: &c.PassGrantTypeDisabled, inverted: true},
		"response type parameter":    {state: &c.ResponseTypeDisabled, inverted: true},
		"scope":                      {state: &c.ScopeDisabled, inverted: true},
		"nonce":                      {state: &c.NonceDisabled, inverted: true},
		"pkce":                       {state: &c.PKCEDisabled, inverted: true},
		"accept header":              {state: &c.AcceptHeaderEnabled},
		"js callback":                {state: &c.JsCallbackEnabled},
		"logout":                     {state: &c.LogoutEnabled},
		"identity token cookie":      {state: &c.IdentityTokenCookieEnabled},
		"email claim check":          {state: &c.EmailClaimCheckDisabled, inverted: true},
		"tls verification":           {state: &c.TLSInsecureSkipVerify, inverted: true},
	}
}

func newLoginIconFields(icon *icons.LoginIcon) map[string]*directiveField {
	return map[string]*directiveField{
		"class_name":            {text: &icon.ClassName},
		"color":                 {text: &icon.Color},
		"background_color":      {text: &icon.BackgroundColor},
		"text":                  {text: &icon.Text},
		"text_color":            {text: &icon.TextColor},
		"text_background_color": {text: &icon.TextBackgroundColor},
		"priority":              {integer: &icon.Priority},
	}
}

// Match the longest exact keyword prefix. Joining decoded tokens would wrongly
// accept grouped/partially quoted keyword spellings and lose argument boundaries.
func matchField(args []string, fields map[string]*directiveField) (string, *directiveField, []string) {
	var key string
	var field *directiveField
	var consumed int
	for name, candidate := range fields {
		words := strings.Split(strings.ReplaceAll(name, "_", " "), " ")
		if len(args) >= len(words) && len(words) > consumed && slices.Equal(args[:len(words)], words) {
			key, field, consumed = name, candidate, len(words)
		}
		// Existing scalar/list spellings remain valid. Switches use separate
		// keyword states, rather than serialized *_disabled/ *_enabled fields.
		if candidate.state == nil && len(args) > 0 && consumed < 1 && args[0] == name {
			key, field, consumed = name, candidate, 1
		}
	}
	return key, field, args[consumed:]
}

func applyField(key string, field *directiveField, values []string, seen map[string]bool, line int) error {
	if len(values) == 0 || (field.list == nil && len(values) != 1) {
		return fmt.Errorf("invalid OAuth %s argument count at line %d", key, line)
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("empty OAuth %s value at line %d", key, line)
		}
	}
	if seen[key] {
		return fmt.Errorf("duplicate OAuth %s directive at line %d", key, line)
	}
	seen[key] = true
	switch {
	case field.text != nil:
		*field.text = values[0]
	case field.list != nil:
		*field.list = slices.Clone(values)
	case field.integer != nil:
		value, err := strconv.Atoi(values[0])
		if err != nil {
			return fmt.Errorf("invalid OAuth %s integer at line %d", key, line)
		}
		*field.integer = value
	case field.state != nil:
		if values[0] != "enabled" && values[0] != "disabled" {
			return fmt.Errorf("OAuth %s requires enabled or disabled at line %d", key, line)
		}
		*field.state = (values[0] == "enabled") != field.inverted
	}
	return nil
}

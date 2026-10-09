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

package registry

import (
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/translate"
)

// LocalizedUI optionally supplies localized registration presentation. Registry
// implementations without this capability retain their supplied titles/hints.
// The language comes from the portal UI; validation policies remain unchanged.
type LocalizedUI interface {
	GetTitleForLanguage(translate.LangID) string
	GetUsernamePolicySummaryForLanguage(translate.LangID) string
	GetPasswordPolicySummaryForLanguage(translate.LangID) string
}

// GetTitleForLanguage localizes the default title while preserving custom titles.
func (p *LocalUserRegistryProvider) GetTitleForLanguage(lang translate.LangID) string {
	if p.Title != "Sign Up" {
		return p.Title
	}
	return translate.Translate("sign_up", translate.NormalizeLanguage(string(lang)), nil)
}

// GetUsernamePolicySummaryForLanguage describes the configured username policy.
func (p *LocalUserRegistryProvider) GetUsernamePolicySummaryForLanguage(lang translate.LangID) string {
	lang = translate.NormalizeLanguage(string(lang))
	if lang == translate.English {
		return p.GetUsernamePolicySummary()
	}
	policy := p.db.Policy.User
	parts := []string{translate.Translate("username_length_hint", lang, map[string]any{"Min": policy.MinLength, "Max": policy.MaxLength})}
	if !policy.AllowUppercase {
		parts = append(parts, translate.Translate("username_lowercase_hint", lang, nil))
	}
	if !policy.AllowNonAlphaNumeric {
		parts = append(parts, translate.Translate("username_alphanumeric_hint", lang, nil))
	}
	return strings.Join(parts, " ")
}

// GetPasswordPolicySummaryForLanguage describes the configured password policy.
func (p *LocalUserRegistryProvider) GetPasswordPolicySummaryForLanguage(lang translate.LangID) string {
	lang = translate.NormalizeLanguage(string(lang))
	if lang == translate.English {
		return p.GetPasswordPolicySummary()
	}
	policy := p.db.Policy.Password
	parts := []string{translate.Translate("password_length_hint", lang, map[string]any{"Min": policy.MinLength, "Max": policy.MaxLength})}
	for _, rule := range []struct {
		required bool
		id       string
	}{
		{policy.RequireUppercase, "password_uppercase_hint"},
		{policy.RequireLowercase, "password_lowercase_hint"},
		{policy.RequireNumber, "password_number_hint"},
		{policy.RequireNonAlphaNumeric, "password_special_hint"},
	} {
		if rule.required {
			parts = append(parts, translate.Translate(rule.id, lang, nil))
		}
	}
	return strings.Join(parts, " ")
}

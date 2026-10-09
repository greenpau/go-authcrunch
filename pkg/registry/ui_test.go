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
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/translate"
)

func TestLocalizedRegistrationUI(t *testing.T) {
	db, err := identity.NewDatabase(filepath.Join(t.TempDir(), "registration.json"))
	if err != nil {
		t.Fatal(err)
	}
	p := &LocalUserRegistryProvider{Title: "Sign Up", db: db}
	var localized LocalizedUI = p
	if localized.GetTitleForLanguage(translate.French) != "S’inscrire" {
		t.Fatal("default title was not localized")
	}
	if p.GetUsernamePolicySummaryForLanguage(translate.Unknown) != p.GetUsernamePolicySummary() || p.GetPasswordPolicySummaryForLanguage("unsupported") != p.GetPasswordPolicySummary() {
		t.Fatal("default/fallback policy hints changed")
	}
	db.Policy.User.MinLength = 8
	db.Policy.User.MaxLength = 32
	db.Policy.User.AllowUppercase = false
	db.Policy.User.AllowNonAlphaNumeric = false
	if got := p.GetUsernamePolicySummaryForLanguage(translate.French); got != "Longueur du nom d’utilisateur : 8 à 32 caractères. Utilisez des lettres minuscules. Utilisez uniquement des lettres et des chiffres." {
		t.Fatalf("username policy: %q", got)
	}
	db.Policy.User.AllowUppercase = true
	db.Policy.User.AllowNonAlphaNumeric = true
	if got := p.GetUsernamePolicySummaryForLanguage(translate.French); strings.Contains(got, "Utilisez") {
		t.Fatal("disabled username restrictions still advertised")
	}
	for _, required := range []bool{false, true} {
		db.Policy.Password.MinLength = 12
		db.Policy.Password.MaxLength = 50
		db.Policy.Password.RequireUppercase = required
		db.Policy.Password.RequireLowercase = required
		db.Policy.Password.RequireNumber = required
		db.Policy.Password.RequireNonAlphaNumeric = required
		got := p.GetPasswordPolicySummaryForLanguage(translate.French)
		if !strings.Contains(got, "12 à 50") {
			t.Fatal("password bounds missing")
		}
		for _, word := range []string{"majuscules", "minuscules", "chiffres", "spéciaux"} {
			if strings.Contains(got, word) != required {
				t.Errorf("incorrect password rule %s", word)
			}
		}
	}
	for _, lang := range []translate.LangID{translate.German, translate.French, translate.Japanese, translate.Chinese, translate.Hebrew, translate.Arabic, translate.Russian} {
		if strings.Contains(p.GetUsernamePolicySummaryForLanguage(lang), "<no value>") || strings.Contains(p.GetPasswordPolicySummaryForLanguage(lang), "<no value>") {
			t.Fatalf("unresolved bounds in %s", lang)
		}
	}
	p.Title = "Example Company"
	if p.GetTitleForLanguage(translate.Arabic) != p.Title {
		t.Fatal("custom title was translated")
	}
}

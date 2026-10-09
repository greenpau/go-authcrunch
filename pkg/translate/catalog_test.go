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

package translate

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
)

func TestCatalogCompleteness(t *testing.T) {
	raw, err := staticFiles.ReadFile("data/messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog []MessageData
	if err := json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	placeholders := regexp.MustCompile(`{{\s*\.([a-zA-Z_]+)\s*}}`)
	for _, m := range catalog {
		if seen[m.ID] {
			t.Errorf("duplicate ID %s", m.ID)
		}
		seen[m.ID] = true
		for form, values := range map[string]map[string]string{"zero": m.Zero, "one": m.One, "other": m.Other} {
			if len(values) == 0 {
				continue
			}
			want := placeholders.FindAllString(values["en"], -1)
			slices.Sort(want)
			for _, lang := range []LangID{English, German, French, Japanese, Chinese, Hebrew, Arabic, Russian} {
				text := values[string(lang)]
				if strings.TrimSpace(text) == "" {
					t.Errorf("%s/%s missing %s", m.ID, form, lang)
				}
				got := placeholders.FindAllString(text, -1)
				slices.Sort(got)
				if !slices.Equal(got, want) {
					t.Errorf("%s/%s/%s changes placeholders", m.ID, form, lang)
				}
				if strings.Contains(text, "<") || strings.Contains(text, ">") {
					t.Errorf("%s contains markup; catalog messages must be plain text", m.ID)
				}
				if strings.ContainsFunc(text, func(r rune) bool {
					return lang == Arabic && unicode.Is(unicode.Hebrew, r) || lang == Hebrew && unicode.Is(unicode.Arabic, r)
				}) {
					t.Errorf("%s/%s/%s mixes Arabic and Hebrew scripts", m.ID, form, lang)
				}
				data := map[string]any{"Min": 3, "Max": 20, "Value": 30, "minutes": 5, "admin_emails": "support@example.test", "external_url": "https://example.test", "external_url_count": 2}
				if len(m.One) > 0 {
					data["Count"] = 2
					if form == "one" {
						data["Count"] = 1
					}
				}
				result := Translate(m.ID, lang, data)
				if result == m.ID || strings.Contains(result, "<no value>") {
					t.Errorf("%s/%s did not resolve", m.ID, lang)
				}
			}
		}
	}
}

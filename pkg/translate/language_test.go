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
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestValidateLangID(t *testing.T) {
	testcases := []struct {
		name      string
		langID    LangID
		shouldErr bool
		err       error
	}{
		{
			name:   "test valid English lang id",
			langID: English,
		},
		{
			name:   "test valid German lang id",
			langID: German,
		},
		{
			name:   "test valid French lang id",
			langID: French,
		},
		{
			name:   "test valid Japanese lang id",
			langID: Japanese,
		},
		{
			name:   "test valid Chinese lang id",
			langID: Chinese,
		},
		{
			name:   "test valid Hebrew lang id",
			langID: Hebrew,
		},
		{
			name:   "test valid Arabic lang id",
			langID: Arabic,
		},
		{
			name:   "test valid Russian lang id",
			langID: Russian,
		},
		{
			name:      "test unknown lang id",
			langID:    Unknown,
			shouldErr: true,
			err:       fmt.Errorf("the %q value is not set", "lang_id"),
		},
		{
			name:      "test unsupported lang id",
			langID:    LangID("es"),
			shouldErr: true,
			err:       fmt.Errorf("the %q value is unsupported", "lang_id"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLangID(tc.langID)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Fatalf("unexpected error: %v, want: %v", err, tc.err)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}
		})
	}
}

func TestGetLanguageName(t *testing.T) {
	testcases := []struct {
		name     string
		langID   LangID
		expected string
	}{
		{
			name:     "test English name",
			langID:   English,
			expected: "English",
		},
		{
			name:     "test German name",
			langID:   German,
			expected: "German",
		},
		{
			name:     "test French name",
			langID:   French,
			expected: "French",
		},
		{
			name:     "test Japanese name",
			langID:   Japanese,
			expected: "Japanese",
		},
		{
			name:     "test Chinese name",
			langID:   Chinese,
			expected: "Chinese",
		},
		{
			name:     "test Hebrew name",
			langID:   Hebrew,
			expected: "Hebrew",
		},
		{
			name:     "test Arabic name",
			langID:   Arabic,
			expected: "Arabic",
		},
		{
			name:     "test Russian name",
			langID:   Russian,
			expected: "Russian",
		},
		{
			name:     "test unknown name",
			langID:   Unknown,
			expected: "Unknown",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			output := GetLanguageName(tc.langID)
			if diff := cmp.Diff(output, tc.expected); diff != "" {
				t.Fatalf("unexpected result (-got +want):\n%s", diff)
			}
		})
	}
}

func TestIsSupportedLanguage(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "lowercase code", input: "en", expected: true},
		{name: "uppercase code", input: "JA", expected: true},
		{name: "full name lowercase", input: "german", expected: true},
		{name: "full name mixed case", input: "Chinese", expected: true},
		{name: "with whitespace", input: "  ru  ", expected: true},
		{name: "unsupported code", input: "es", expected: false},
		{name: "empty string", input: "", expected: false},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			output := IsSupportedLanguage(tc.input)
			if output != tc.expected {
				t.Fatalf("expected %v for %q, got %v", tc.expected, tc.input, output)
			}
		})
	}
}

func TestGetLanguageCode(t *testing.T) {
	testcases := []struct {
		name     string
		langID   LangID
		expected string
	}{
		{name: "English code", langID: English, expected: "en"},
		{name: "Arabic code", langID: Arabic, expected: "ar"},
		{name: "Chinese code", langID: Chinese, expected: "zh"},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			output := GetLanguageCode(tc.langID)
			if output != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, output)
			}
		})
	}
}

func TestNormalizeLanguage(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected LangID
	}{
		{name: "normalize code en", input: "en", expected: English},
		{name: "normalize code EN", input: "EN", expected: English},
		{name: "normalize name English", input: "English", expected: English},
		{name: "normalize name russian", input: "russian", expected: Russian},
		{name: "normalize name Hebrew with space", input: "  Hebrew  ", expected: Hebrew},
		{name: "fallback for unsupported", input: "spanish", expected: English},
		{name: "fallback for empty", input: "", expected: English},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			output := NormalizeLanguage(tc.input)
			if output != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, output)
			}
		})
	}
}

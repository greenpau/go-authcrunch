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
	"strings"
)

// LangID stores ISO 639-1 language code.
type LangID string

// Supported language identifiers.
const (
	// Unknown represents an unset or invalid language.
	Unknown LangID = ""
	// English represents the English language (en).
	English LangID = "en"
	// German represents the German language (de).
	German LangID = "de"
	// French represents the French language (fr).
	French LangID = "fr"
	// Japanese represents the Japanese language (ja).
	Japanese LangID = "ja"
	// Chinese represents the Chinese language (zh).
	Chinese LangID = "zh"
	// Hebrew represents the Hebrew language (he).
	Hebrew LangID = "he"
	// Arabic represents the Arabic language (ar).
	Arabic LangID = "ar"
	// Russian represents the Russian language (ru).
	Russian LangID = "ru"
)

// languageMap provides a lookup for ISO codes and full names.
var languageMap = map[string]LangID{
	"en":       English,
	"english":  English,
	"de":       German,
	"german":   German,
	"fr":       French,
	"french":   French,
	"ja":       Japanese,
	"japanese": Japanese,
	"zh":       Chinese,
	"chinese":  Chinese,
	"he":       Hebrew,
	"hebrew":   Hebrew,
	"ar":       Arabic,
	"arabic":   Arabic,
	"ru":       Russian,
	"russian":  Russian,
}

// ValidateLangID checks if the provided LangID is supported.
func ValidateLangID(langID LangID) error {
	switch langID {
	case English, German, French, Japanese, Chinese, Hebrew, Arabic, Russian:
		return nil
	case Unknown:
		return fmt.Errorf("the %q value is not set", "lang_id")
	default:
		return fmt.Errorf("the %q value is unsupported", "lang_id")
	}
}

// GetLanguageName returns the string representation of the LangID.
func GetLanguageName(langID LangID) string {
	switch langID {
	case English:
		return "English"
	case German:
		return "German"
	case French:
		return "French"
	case Japanese:
		return "Japanese"
	case Chinese:
		return "Chinese"
	case Hebrew:
		return "Hebrew"
	case Arabic:
		return "Arabic"
	case Russian:
		return "Russian"
	default:
		return "Unknown"
	}
}

// IsSupportedLanguage returns true if the provided string (ISO code or Name) is supported.
func IsSupportedLanguage(lang string) bool {
	l := strings.ToLower(strings.TrimSpace(lang))
	_, exists := languageMap[l]
	return exists
}

// GetLanguageCode returns the short ISO 639-1 code (e.g., "en", "ja") as a string.
func GetLanguageCode(langID LangID) string {
	return string(langID)
}

// NormalizeLanguage converts an ISO code or full name string to a valid LangID type.
// It defaults to English if the input is unrecognized.
func NormalizeLanguage(lang string) LangID {
	l := strings.ToLower(strings.TrimSpace(lang))
	if id, exists := languageMap[l]; exists {
		return id
	}
	return English
}

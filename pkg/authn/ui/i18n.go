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

package ui

import (
	"encoding/json"

	"github.com/greenpau/go-authcrunch/pkg/translate"
)

// LanguageCode returns the normalized portal language, defaulting to English.
func (args *Args) LanguageCode() string {
	return string(translate.NormalizeLanguage(string(args.Language)))
}

// Direction returns the reading direction for the configured portal language.
func (args *Args) Direction() string {
	switch translate.LangID(args.LanguageCode()) {
	case translate.Arabic, translate.Hebrew:
		return "rtl"
	default:
		return "ltr"
	}
}

// Translate returns plain text for a catalog message. An optional value supplies
// the message's Value placeholder; HTML templates retain contextual escaping.
func (args *Args) Translate(id string, value ...any) string {
	var data map[string]any
	if len(value) > 0 {
		data = map[string]any{"Value": value[0]}
	}
	return translate.Translate(id, translate.LangID(args.LanguageCode()), data)
}

// Messages encodes selected messages for an HTML data attribute consumed by an
// external script. The return value is plain text, never trusted HTML or JS.
func (args *Args) Messages(ids ...string) string {
	messages := make(map[string]string, len(ids))
	for _, id := range ids {
		messages[id] = args.Translate(id)
	}
	data, _ := json.Marshal(messages) // A map of strings is always encodable.
	return string(data)
}

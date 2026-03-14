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
	"embed"
	"encoding/json"
	"fmt"
	"log"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed data
var staticFiles embed.FS

var bundle *i18n.Bundle
var localizers map[string]*i18n.Localizer

// MessageData supports the pluralization fields (one/other) and descriptions.
type MessageData struct {
	ID          string            `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Description string            `json:"description,omitempty" xml:"description,omitempty" yaml:"description,omitempty"`
	Zero        map[string]string `json:"zero,omitempty" xml:"zero,omitempty" yaml:"zero,omitempty"`
	One         map[string]string `json:"one,omitempty" xml:"one,omitempty" yaml:"one,omitempty"`
	Other       map[string]string `json:"other,omitempty" xml:"other,omitempty" yaml:"other,omitempty"`
}

func init() {
	bundle = i18n.NewBundle(language.English)

	messagesFilePath := "data/messages.json"
	data, err := staticFiles.ReadFile(messagesFilePath)
	if err != nil {
		log.Fatalf("failed to read %s: %v", messagesFilePath, err)
	}

	var rawMessages []MessageData
	if err := json.Unmarshal(data, &rawMessages); err != nil {
		log.Fatalf("failed to unmarshal %s: %v", messagesFilePath, err)
	}

	localizers = make(map[string]*i18n.Localizer)
	langMap := make(map[string][]*i18n.Message)

	// Transform the custom JSON structure into a format i18n understands
	for _, m := range rawMessages {
		codes := make(map[string]bool)
		for c := range m.Other {
			codes[c] = true
		}
		for c := range m.One {
			codes[c] = true
		}

		for langCode := range codes {
			langMap[langCode] = append(langMap[langCode], &i18n.Message{
				ID:          m.ID,
				Description: m.Description,
				One:         m.One[langCode],
				Zero:        m.Zero[langCode],
				Other:       m.Other[langCode],
				Many:        m.Other[langCode],
				Two:         m.Other[langCode],
				Few:         m.Other[langCode],
			})
		}
	}

	for langCode, messages := range langMap {
		tag, err := language.Parse(langCode)
		if err != nil {
			log.Printf("skipping invalid language code '%s': %v", langCode, err)
			continue
		}
		bundle.MustAddMessages(tag, messages...)
		localizers[langCode] = i18n.NewLocalizer(bundle, langCode)
	}
}

// Translate retrieves a localized string. Pass "Count" in the data map for pluralization.
func Translate(id string, langID LangID, data map[string]interface{}) string {
	code := string(langID)
	localizer, ok := localizers[code]
	if !ok {
		return id
	}

	config := i18n.LocalizeConfig{
		MessageID:    id,
		TemplateData: data,
		DefaultMessage: &i18n.Message{
			ID:    id,
			One:   id,
			Other: id,
			Many:  id,
			Few:   id,
			Zero:  id,
		},
	}

	if data != nil {
		if count, ok := data["Count"].(int); ok {
			config.PluralCount = count
			if count == 0 {
				config.MessageID = id + ".zero"
				config.DefaultMessage = &i18n.Message{
					ID:    id + ".zero",
					One:   id + ".zero",
					Other: id + ".zero",
					Many:  id + ".zero",
					Few:   id + ".zero",
					Zero:  id + ".zero",
				}
			}
		}
	}

	translation, err := localizer.Localize(&config)
	if err != nil {
		fmt.Printf("ERROR: translation: %s: %v\n", id, err)
		return id
	}
	return translation
}

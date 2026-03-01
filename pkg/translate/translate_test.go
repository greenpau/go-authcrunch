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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestTranslate(t *testing.T) {
	testcases := []struct {
		name     string
		id       string
		langID   LangID
		data     map[string]interface{}
		expected string
	}{
		{
			name:     "test simple translation in English",
			id:       "thank_you",
			langID:   English,
			expected: "Thank you!",
		},
		{
			name:     "test simple translation in German",
			id:       "thank_you",
			langID:   German,
			expected: "Vielen Dank!",
		},
		{
			name:     "test simple translation in Chinese",
			id:       "thank_you",
			langID:   Chinese,
			expected: "谢谢！",
		},
		{
			name:     "test simple translation in Hebrew",
			id:       "thank_you",
			langID:   Hebrew,
			expected: "תודה רבה!",
		},
		{
			name:     "test simple translation in Arabic",
			id:       "thank_you",
			langID:   Arabic,
			expected: "شكراً لك!",
		},
		{
			name:     "test simple translation in Russian",
			id:       "thank_you",
			langID:   Russian,
			expected: "Спасибо!",
		},
		{
			name:     "test translation with variables in English",
			id:       "confirmation_email_arrival",
			langID:   English,
			data:     map[string]interface{}{"minutes": 15},
			expected: "You should receive your confirmation email within the next 15 minutes.",
		},
		{
			name:     "test translation with variables in Russian",
			id:       "confirmation_email_arrival",
			langID:   Russian,
			data:     map[string]interface{}{"minutes": 10},
			expected: "Вы должны получить подтверждение по электронной почте в течение следующих 10 минут.",
		},
		{
			name:   "test pluralization for one in Arabic",
			id:     "found_external_urls",
			langID: Arabic,
			data: map[string]interface{}{
				"Count":        1,
				"external_url": "https://example.com",
			},
			expected: "تم العثور على رابط خارجي واحد: https://example.com",
		},
		{
			name:   "test pluralization for many in Hebrew",
			id:     "found_external_urls",
			langID: Hebrew,
			data: map[string]interface{}{
				"Count":              3,
				"external_url_count": 3,
			},
			expected: "נמצאו 3 כתובות חיצוניות.",
		},
		{
			name:   "test pluralization for many in Chinese",
			id:     "found_external_urls",
			langID: Chinese,
			data: map[string]interface{}{
				"Count":              2,
				"external_url_count": 2,
			},
			expected: "找到 2 个外部链接。",
		},
		{
			name:     "test fallback to ID when language is unsupported",
			id:       "sign_out",
			langID:   LangID("es"),
			expected: "sign_out",
		},
		{
			name:     "test fallback to ID when message ID is missing",
			id:       "non_existent_key",
			langID:   English,
			expected: "non_existent_key",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			output := Translate(tc.id, tc.langID, tc.data)
			if diff := cmp.Diff(output, tc.expected); diff != "" {
				t.Fatalf("unexpected result (-got +want):\n%s", diff)
			}
		})
	}
}

func TestMessageIDsForDuplicates(t *testing.T) {
	data, err := staticFiles.ReadFile("data/messages.json")
	if err != nil {
		t.Fatalf("failed to read data/messages.json from embed: %v", err)
	}

	type messageEntry struct {
		ID string `json:"id"`
	}

	var messages []messageEntry
	if err := json.Unmarshal(data, &messages); err != nil {
		t.Fatalf("failed to unmarshal data/messages.json: %v", err)
	}

	seen := make(map[string]int)
	for i, msg := range messages {
		if msg.ID == "" {
			t.Errorf("entry at index %d has an empty ID", i)
			continue
		}

		if count, exists := seen[msg.ID]; exists {
			t.Errorf("duplicate message ID found: %q (appears at index %d and %d)", msg.ID, count, i)
		}
		seen[msg.ID] = i
	}
}

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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFormatTimestamp(t *testing.T) {
	// A fixed timestamp for predictable testing: Friday, Oct 3, 2025 at 02:26 UTC
	const ts = "2025-10-03T02:26:00Z"

	testcases := []struct {
		name     string
		fieldID  string
		langID   LangID
		expected string
	}{
		{
			name:     "test English timestamp formatting",
			fieldID:  "thank_you",
			langID:   English,
			expected: "Thank you!: Friday, October 3, 2025 02:26",
		},
		{
			name:     "test German timestamp formatting",
			fieldID:  "thank_you",
			langID:   German,
			expected: "Vielen Dank!: Freitag, 3. Oktober 2025 02:26",
		},
		{
			name:     "test French timestamp formatting",
			fieldID:  "thank_you",
			langID:   French,
			expected: "Merci !: vendredi 3 octobre 2025 02:26",
		},
		{
			name:     "test Japanese timestamp formatting",
			fieldID:  "thank_you",
			langID:   Japanese,
			expected: "ありがとうございます！: 2025年10月3日(金) 02:26",
		},
		{
			name:     "test Chinese timestamp formatting",
			fieldID:  "thank_you",
			langID:   Chinese,
			expected: "谢谢！: 2025年10月3日 星期五 02:26",
		},
		{
			name:     "test Russian timestamp formatting",
			fieldID:  "thank_you",
			langID:   Russian,
			expected: "Спасибо!: пятница, 3 октября 2025 г., 02:26",
		},
		{
			name:     "test Hebrew timestamp formatting",
			fieldID:  "thank_you",
			langID:   Hebrew,
			expected: "תודה רבה!: יום שישי, 3/10/2025 02:26",
		},
		{
			name:     "test Arabic timestamp formatting",
			fieldID:  "thank_you",
			langID:   Arabic,
			expected: "شكراً لك!: الجمعة، 3 أكتوبر 2025 02:26",
		},
		{
			name:     "test invalid timestamp fallback",
			fieldID:  "label",
			langID:   English,
			expected: "label: invalid-time",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			inputTs := ts
			if tc.name == "test invalid timestamp fallback" {
				inputTs = "invalid-time"
			}

			output := FormatTimestamp(tc.fieldID, inputTs, tc.langID)
			if diff := cmp.Diff(output, tc.expected); diff != "" {
				t.Fatalf("unexpected result (-got +want):\n%s", diff)
			}
		})
	}
}

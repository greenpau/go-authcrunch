// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package icons

import (
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	// "github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestParse(t *testing.T) {
	testcases := []struct {
		name      string
		input     []string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:  "text only",
			input: []string{"Okta"},
			want: map[string]interface{}{
				"text": "Okta",
			},
		},
		{
			name:  "text with priority",
			input: []string{"Okta", "priority", "100"},
			want: map[string]interface{}{
				"text":     "Okta",
				"priority": float64(100),
			},
		},

		{
			name:  "text with priority and icon class name",
			input: []string{"Okta", "lab la-gitlab la-2x", "priority", "100"},
			want: map[string]interface{}{
				"text":       "Okta",
				"priority":   float64(100),
				"class_name": "lab la-gitlab la-2x",
			},
		},
		{
			name:  "text with priority and icon class name, color",
			input: []string{"Okta", "lab la-gitlab la-2x", "green", "priority", "100"},
			want: map[string]interface{}{
				"text":       "Okta",
				"priority":   float64(100),
				"class_name": "lab la-gitlab la-2x",
				"color":      "green",
			},
		},
		{
			name:  "text with priority and icon class name, color, background color",
			input: []string{"Okta", "lab la-gitlab la-2x", "green", "brown", "priority", "100"},
			want: map[string]interface{}{
				"text":             "Okta",
				"priority":         float64(100),
				"class_name":       "lab la-gitlab la-2x",
				"color":            "green",
				"background_color": "brown",
			},
		},
		{
			name:  "text with priority, icon class name/color/background color, text color",
			input: []string{"Okta", "lab la-gitlab la-2x", "green", "brown", "priority", "100", "text", "white", "blue"},
			want: map[string]interface{}{
				"text":                  "Okta",
				"priority":              float64(100),
				"class_name":            "lab la-gitlab la-2x",
				"color":                 "green",
				"background_color":      "brown",
				"text_color":            "white",
				"text_background_color": "blue",
			},
		},
		/*
			{
				name: "test invalid config",
				shouldErr: true,
				err:       fmt.Errorf("TBD"),
			},
		*/
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%v", tc.input))

			got, err := Parse(tc.input)
			if tests.EvalErrWithLog(t, err, "Parse", tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "Icon", tc.want, got, msgs)
		})
	}
}

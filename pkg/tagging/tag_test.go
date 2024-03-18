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

package tagging

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestExtractTags(t *testing.T) {

	testcases := []struct {
		name      string
		input     string
		want      []*Tag
		shouldErr bool
		err       error
		disabled  bool
	}{
		{
			name:     "test extract tags with one tag",
			disabled: false,
			input: `{
				"tags": [
					{
						"key": "foo",
						"value": "bar"
					}
				]
			}`,
			want: []*Tag{
				{
					Key:   "foo",
					Value: "bar",
				},
			},
		},
		{
			name:     "test extract tags with multiple tags",
			disabled: false,
			input: `{
				"tags": [
					{
						"key": "foo",
						"value": "bar"
					},
					{
						"key": "bar",
						"value": "baz"
					}
				]
			}`,
			want: []*Tag{
				{
					Key:   "foo",
					Value: "bar",
				},
				{
					Key:   "bar",
					Value: "baz",
				},
			},
		},
		{
			name:     "test extract tags without any tags",
			disabled: false,
			input: `{
				"tags": [
				]
			}`,
			want: []*Tag{},
		},
		{
			name:     "test map without tags field",
			disabled: false,
			input:    `{}`,
			want:     []*Tag{},
		},
		{
			name:     "test tag without key field",
			disabled: false,
			input: `{
				"tags": [
					{
						"foo": "foo",
						"value": "bar"
					}
				]
			}`,
			shouldErr: true,
			err:       fmt.Errorf("malformed extracted tags: %s", "tag has no key"),
		},
		{
			name:     "test tag without value field",
			disabled: false,
			input: `{
				"tags": [
					{
						"key": "foo",
						"foo": "bar"
					}
				]
			}`,
			shouldErr: true,
			err:       fmt.Errorf("malformed extracted tags: %s", "tag has no value"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%v", tc.input))
			input, err := tests.UnpackDict(tc.input)
			if err != nil {
				t.Fatalf("prereq failed: %v", err)
			}
			got, err := ExtractTags(input)
			if tests.EvalErrWithLog(t, err, "ExtractTags", tc.shouldErr, tc.err, msgs) {
				return
			}
			tests.EvalObjectsWithLog(t, "ExtractTags", tc.want, got, msgs)
		})
	}
}

func TestExtractLabels(t *testing.T) {

	testcases := []struct {
		name      string
		input     string
		want      []string
		shouldErr bool
		err       error
		disabled  bool
	}{
		{
			name:     "test extract labels with one label",
			disabled: false,
			input: `{
				"labels": ["foo"]
			}`,
			want: []string{"foo"},
		},
		{
			name:     "test extract labels with multiple labels",
			disabled: false,
			input: `{
				"labels": ["foo", "bar"]
			}`,
			want: []string{"foo", "bar"},
		},
		{
			name:     "test extract labels without any labels",
			disabled: false,
			input: `{
				"labels": []
			}`,
			want: []string{},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("input:\n%v", tc.input))
			input, err := tests.UnpackDict(tc.input)
			if err != nil {
				t.Fatalf("prereq failed: %v", err)
			}
			got, err := ExtractLabels(input)
			if tests.EvalErrWithLog(t, err, "ExtractLabels", tc.shouldErr, tc.err, msgs) {
				return
			}
			tests.EvalObjectsWithLog(t, "ExtractLabels", tc.want, got, msgs)
		})
	}
}

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

package credentials

import (
	// "fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"

	"testing"
)

func TestValidateConfig(t *testing.T) {
	testcases := []struct {
		name      string
		entry     []string
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid generic credential",
			entry: []string{
				"name default",
				"username foo",
				"password bar",
			},
			want: `{
			  "generic": [
			    {
			      "name": "default",
				  "password": "bar",
				  "username": "foo"
		        }
			  ],
			  "raw_credential_configs": [
			    [
			      "name default", 
				  "username foo",
				  "password bar"
				]
			  ]
            }`,
		},
		{
			name: "test generic credential without name",
			entry: []string{
				"username foo",
				"password bar",
			},
			shouldErr: true,
			err:       errors.ErrCredKeyValueEmpty.WithArgs("name"),
		},
		{
			name: "test generic credential without username",
			entry: []string{
				"name default",
			},
			shouldErr: true,
			err:       errors.ErrCredKeyValueEmpty.WithArgs("username"),
		},
		{
			name: "test generic credential without password",
			entry: []string{
				"name default",
				"username foo",
			},
			shouldErr: true,
			err:       errors.ErrCredKeyValueEmpty.WithArgs("password"),
		},
		{
			name: "test mock credential",
			entry: []string{
				"name foo",
				"kind mock",
			},
			shouldErr: true,
			err:       errors.ErrCredUnsupportedKind.WithArgs("mock"),
		},
		{
			name:      "test not credentials",
			entry:     []string{},
			shouldErr: true,
			err:       errors.ErrCredConfigEmpty,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}

			if len(tc.entry) > 0 {
				cfg.Add(tc.entry)
			}
			err := cfg.Validate()
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
			got := tests.Unpack(t, cfg)
			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Add() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindCredential(t *testing.T) {
	testcases := []struct {
		name           string
		instructions   [][]string
		credentialName string
		want           bool
	}{
		{
			name: "find existing credential",
			instructions: [][]string{
				{
					"name foo",
					"username foo",
					"password bar",
				},
			},
			credentialName: "foo",
			want:           true,
		},
		{
			name: "find non-existing credential",
			instructions: [][]string{
				{
					"name foo",
					"username foo",
					"password bar",
				},
			},
			credentialName: "bar",
			want:           false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			for _, instruction := range tc.instructions {
				cfg.Add(instruction)
			}
			err := cfg.Validate()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.want, cfg.FindCredential(tc.credentialName)); diff != "" {
				t.Errorf("FindCredential mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractGeneric(t *testing.T) {
	testcases := []struct {
		name           string
		instructions   [][]string
		credentialName string
		want           map[string]any
	}{
		{
			name: "extract existing credential",
			instructions: [][]string{
				{
					"name foo",
					"username foo",
					"password bar",
				},
			},
			credentialName: "foo",
			want: map[string]any{
				"credential": &GenericCredential{
					Name:     "foo",
					Username: "foo",
					Password: "bar"},
			},
		},
		{
			name: "extract non-existing credential",
			instructions: [][]string{
				{
					"name foo",
					"username foo",
					"password bar",
				},
			},
			credentialName: "bar",
			want:           map[string]any{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			for _, instruction := range tc.instructions {
				cfg.Add(instruction)
			}
			err := cfg.Validate()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := make(map[string]any)
			cred := cfg.ExtractGeneric(tc.credentialName)
			if cred != nil {
				got["credential"] = cred
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ExtractGeneric mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

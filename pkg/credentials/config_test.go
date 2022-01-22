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
	// "github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

func TestParseCaddyfileCredentials(t *testing.T) {
	testcases := []struct {
		name      string
		entry     Credential
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid smtp credentials",
			entry: &SMTP{
				Name:     "smtp.contoso.com",
				Address:  "smtp.contoso.com:993",
				Protocol: "smtp",
				Username: "foo",
				Password: "bar",
			},
			want: `{
              "email": [
			    {
			      "address":  "smtp.contoso.com:993",
                  "name":     "smtp.contoso.com",
			      "username": "foo",
			      "password": "bar",
			      "protocol": "smtp"
			    }
			  ]
			}`,
		},
		{
			name: "test valid generic credentials",
			entry: &Generic{
				Name:     "default",
				Username: "foo",
				Password: "bar",
			},
			want: `{
              "generic": [
                {
                  "name":     "default",
                  "username": "foo",
                  "password": "bar"
                }
              ]
            }`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			err := cfg.Add(tc.entry)
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

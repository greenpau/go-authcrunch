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

package registry

import (
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"

	"testing"
)

func TestNewProvider(t *testing.T) {
	testcases := []struct {
		name      string
		entry     []string
		want      map[string]any
		shouldErr bool
		err       error
	}{
		{
			name: "test valid local user registry provider config",
			entry: []string{
				"name localdbRegistry",
				"kind local",
				"dropbox assets/config/registrations_local.json",
				cfgutil.EncodeArgs([]string{"title", "User Registration"}),
				"code NY2020",
				"require accept terms",
				"require domain mx",
				"email provider localhost-smtp-server",
				"admin email admin@localhost",
				"identity store localdb",
				"allow domain outlook.com",
			},
			want: map[string]any{
				"kind":                 "local",
				"admin_emails":         []string{"admin@localhost"},
				"code":                 "NY2020",
				"domain_restrictions":  []string{"allow domain outlook.com"},
				"dropbox":              "assets/config/registrations_local.json",
				"email_provider_name":  "localhost-smtp-server",
				"identity_store_name":  "localdb",
				"name":                 "localdbRegistry",
				"require_accept_terms": true,
				"require_domain_mx":    true,
				"title":                "User Registration",
			},
		},
		{
			name: "test malformed local user registry provider config",
			entry: []string{
				"kind local",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("name"),
		},
		{
			name: "bad user registry provider instruction encoding",
			entry: []string{
				"",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionThrown.WithArgs("EOF", ""),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewProvider(tc.entry)
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

			got := provider.AsMap()

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("NewProvider() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

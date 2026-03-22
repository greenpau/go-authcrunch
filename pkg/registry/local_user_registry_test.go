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
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"

	"testing"
)

func TestNewLocalUserRegistryProvider(t *testing.T) {
	testcases := []struct {
		name      string
		entry     []string
		want      map[string]any
		shouldErr bool
		err       error
	}{
		{
			name: "test valid user registry provider config",
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
				"identity store localdb local",
				"link terms http://google.com/terms",
				"link privacy http://google.com/privacy",
				"allow domain outlook.com",
			},
			want: map[string]any{
				"kind":                  "local",
				"admin_emails":          []string{"admin@localhost"},
				"code":                  "NY2020",
				"domain_restrictions":   []string{"allow domain outlook.com"},
				"dropbox":               "assets/config/registrations_local.json",
				"email_provider_name":   "localhost-smtp-server",
				"identity_store_name":   "localdb",
				"realm_name":            "local",
				"name":                  "localdbRegistry",
				"require_accept_terms":  true,
				"require_domain_mx":     true,
				"title":                 "User Registration",
				"privacy_policy_link":   "http://google.com/privacy",
				"terms_conditions_link": "http://google.com/terms",
			},
		},
		{
			name: "test malformed user registry config",
			entry: []string{
				"kind local",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("name"),
		},
		{
			name: "test malformed name instruction",
			entry: []string{
				"name foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("name foo bar"),
		},
		{
			name: "test malformed title instruction",
			entry: []string{
				"title foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("title foo bar"),
		},
		{
			name: "test malformed code instruction",
			entry: []string{
				"code foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("code foo bar"),
		},
		{
			name: "test malformed dropbox instruction",
			entry: []string{
				"dropbox foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("dropbox foo bar"),
		},
		{
			name: "test malformed require instruction",
			entry: []string{
				"require foo bar baz",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("require foo bar baz"),
		},
		{
			name: "test malformed require instruction",
			entry: []string{
				"require foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("require foo bar"),
		},
		{
			name: "test malformed link instruction",
			entry: []string{
				"link foo bar baz",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("link foo bar baz"),
		},
		{
			name: "test malformed email provider name instruction",
			entry: []string{
				"email foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("email foo bar"),
		},
		{
			name: "test malformed email provider name instruction",
			entry: []string{
				"email",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("email"),
		},
		{
			name: "test malformed email provider name instruction",
			entry: []string{
				"email foo bar baz",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("email foo bar baz"),
		},

		{
			name: "test malformed identity store name instruction",
			entry: []string{
				"identity foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("identity foo bar"),
		},
		{
			name: "test malformed identity store name instruction",
			entry: []string{
				"identity foo bar baz foo",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("identity foo bar baz foo"),
		},
		{
			name: "test malformed admin emails instruction",
			entry: []string{
				"admin",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("admin"),
		},
		{
			name: "test malformed admin emails instruction",
			entry: []string{
				"admin foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("admin foo bar"),
		},
		{
			name: "test malformed link instruction",
			entry: []string{
				"link foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("link foo bar"),
		},
		{
			name: "test malformed kind instruction",
			entry: []string{
				"kind file bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionBadSyntax.WithArgs("kind file bar"),
		},
		{
			name: "test unsupported instruction",
			entry: []string{
				"foo bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionUnsupportedKey.WithArgs("foo bar"),
		},
		{
			name: "test unsupported provider kind",
			entry: []string{
				"kind foo",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionKindMismatch.WithArgs(LocalUserRegistryProviderKindLabel, "foo"),
		},
		{
			name: "bad provider instruction encoding",
			entry: []string{
				"",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigMalformedInstructionThrown.WithArgs("EOF", ""),
		},
		{
			name: "test missing dropbox field value",
			entry: []string{
				"name localdbRegistry",
				"kind local",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("dropbox"),
		},
		{
			name: "test missing email provider field value",
			entry: []string{
				"name localdbRegistry",
				"kind local",
				"dropbox assets/config/registrations_local.json",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("email provider"),
		},
		{
			name: "test missing admin email address field value",
			entry: []string{
				"name localdbRegistry",
				"kind local",
				"dropbox assets/config/registrations_local.json",
				"email provider localhost-smtp-server",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("admin email address"),
		},
		{
			name: "test missing identity store name field value",
			entry: []string{
				"name localdbRegistry",
				"kind local",
				"dropbox assets/config/registrations_local.json",
				"email provider localhost-smtp-server",
				"admin email admin@localhost",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigKeyValueEmpty.WithArgs("identity store name"),
		},

		{
			name: "test malformed dropbox field value",
			entry: []string{
				"name localdbRegistry",
				"kind local",
				"dropbox assets/config/registrations_local.json",
				"email provider localhost-smtp-server",
				"admin email admin@localhost",
				"identity store localdb",
				"allow foo bar",
			},
			shouldErr: true,
			err: errors.ErrUserRegistryConfigMalformedInstructionThrown.WithArgs(
				[]string{"allow foo bar"},
				errors.ErrUserRegistryConfigMalformedDomainRestrictionRule.WithArgs("allow foo bar"),
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewLocalUserRegistryProvider(tc.entry)
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

			tests.EvalObjects(t, "NewLocalUserRegistryProvider", tc.want, got)
		})
	}
}

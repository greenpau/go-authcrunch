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
	"testing"
)

func TestValidateUserRegistryConfig(t *testing.T) {
	testcases := []struct {
		name      string
		config    *UserRegistryConfig
		shouldErr bool
		err       error
	}{
		{
			name:      "test user registration config without name",
			config:    &UserRegistryConfig{},
			shouldErr: true,
			err:       errors.ErrUserRegistrationConfig.WithArgs("", "name is not set"),
		},
		{
			name: "test user registration config without dropbox",
			config: &UserRegistryConfig{
				Name: "default",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistrationConfig.WithArgs("default", "dropbox is not set"),
		},
		{
			name: "test user registration config without email provider",
			config: &UserRegistryConfig{
				Name:    "default",
				Dropbox: "foo",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistrationConfig.WithArgs("default", "email provider is not set"),
		},
		{
			name: "test user registration config without admin email address",
			config: &UserRegistryConfig{
				Name:          "default",
				Dropbox:       "foo",
				EmailProvider: "bar",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistrationConfig.WithArgs("default", "admin email address is not set"),
		},
		{
			name: "test valid user registration config without identity store",
			config: &UserRegistryConfig{
				Name:                "default",
				Dropbox:             "foo",
				EmailProvider:       "bar",
				AdminEmails:         []string{"root@localhost"},
				RequireAcceptTerms:  true,
				TermsConditionsLink: "/terms.html",
				PrivacyPolicyLink:   "/privacy.html",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistrationConfig.WithArgs("default", "identity store name is not set"),
		},
		{
			name: "test valid user registration config",
			config: &UserRegistryConfig{
				Name:                "default",
				Dropbox:             "foo",
				EmailProvider:       "bar",
				AdminEmails:         []string{"root@localhost"},
				RequireAcceptTerms:  true,
				TermsConditionsLink: "/terms.html",
				PrivacyPolicyLink:   "/privacy.html",
				IdentityStore:       "foo",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
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
		})
	}
}

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
	// "fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"

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
			name: "test valid local provider config",
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
			want: `{
				"local_providers": [
					{
                        "admin_emails":         ["admin@localhost"],
                        "code":                 "NY2020",
                        "domain_restrictions":  ["allow domain outlook.com"],
                        "dropbox":              "assets/config/registrations_local.json",
                        "email_provider_name":  "localhost-smtp-server",
                        "identity_store_name":  "localdb",
                        "name":                 "localdbRegistry",
						"require_accept_terms": true,
						"require_domain_mx": true,
						"title": "User Registration"
					}
				],
				"raw_configs": [
					[
						"name localdbRegistry",
						"kind local",
						"dropbox assets/config/registrations_local.json",
						"title \"User Registration\"",
						"code NY2020",
						"require accept terms",
						"require domain mx",
						"email provider localhost-smtp-server",
						"admin email admin@localhost",
						"identity store localdb",
						"allow domain outlook.com"
					]
				]
            }`,
		},
		{
			name: "test valid local provider config",
			entry: []string{
				"name localdbRegistry",
			},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigUnsupportedKind.WithArgs(UnknownUserRegistryProviderKindLabel),
		},
		{
			name:      "test provider config without configuration statements",
			entry:     []string{},
			shouldErr: true,
			err:       errors.ErrUserRegistryConfigEmpty.WithArgs(),
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

// func TestFindProvider(t *testing.T) {
// 	testcases := []struct {
// 		name         string
// 		instructions [][]string
// 		providerName string
// 		shouldFind   bool
// 	}{
// 		{
// 			name: "find existing email provider",
// 			instructions: [][]string{
// 				{
// 					"name default",
// 					"kind email",
// 					"address localhost",
// 					"credentials default_email_creds",
// 					"protocol smtp",
// 					cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
// 				},
// 			},
// 			providerName: "default",
// 			shouldFind:   true,
// 		},
// 		{
// 			name: "find non-existing email provider",
// 			instructions: [][]string{
// 				{
// 					"name default",
// 					"kind email",
// 					"address localhost",
// 					"credentials default_email_creds",
// 					"protocol smtp",
// 					cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
// 				},
// 			},
// 			providerName: "foo",
// 			shouldFind:   false,
// 		},
// 		{
// 			name: "find existing file provider",
// 			instructions: [][]string{
// 				{
// 					"name default",
// 					"kind file",
// 					"root_dir /var/spool/auth-messaging/",
// 					cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
// 				},
// 			},
// 			providerName: "default",
// 			shouldFind:   true,
// 		},
// 		{
// 			name: "find non-existing file provider",
// 			instructions: [][]string{
// 				{
// 					"name default",
// 					"kind file",
// 					"root_dir /var/spool/auth-messaging/",
// 					cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
// 				},
// 			},
// 			providerName: "foo",
// 			shouldFind:   false,
// 		},
// 	}

// 	for _, tc := range testcases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			cfg := &Config{}
// 			for _, instruction := range tc.instructions {
// 				cfg.Add(instruction)
// 			}
// 			err := cfg.Validate()
// 			if err != nil {
// 				t.Fatalf("unexpected error: %v", err)
// 			}
// 			if diff := cmp.Diff(tc.shouldFind, cfg.FindProvider(tc.providerName)); diff != "" {
// 				t.Errorf("FindProvider mismatch (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }

// func TestExtractProvider(t *testing.T) {
// 	instructions := [][]string{
// 		{
// 			"name default-email",
// 			"kind email",
// 			"address localhost",
// 			"credentials default_email_creds",
// 			"protocol smtp",
// 			cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
// 		},
// 		{
// 			"name passwordless-email",
// 			"kind email",
// 			"address localhost",
// 			"protocol smtps",
// 			"passwordless",
// 			cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
// 		},
// 		{
// 			"name default-file",
// 			"kind file",
// 			"root_dir /var/spool/auth-messaging/",
// 			cfgutil.EncodeArgs([]string{"sender", "root@localhost", "My Auth Portal"}),
// 		},
// 	}

// 	testcases := []struct {
// 		name         string
// 		providerName string
// 		providerKind string
// 		want         map[string]any
// 	}{
// 		{
// 			name:         "extract existing email provider",
// 			providerName: "default-email",
// 			providerKind: EmailMessagingProviderKindLabel,
// 			want: map[string]any{
// 				"default-email": &EmailProvider{
// 					Name:        "default-email",
// 					Address:     "localhost",
// 					Protocol:    "smtp",
// 					Credentials: "default_email_creds",
// 					SenderEmail: "root@localhost",
// 					SenderName:  "My Auth Portal",
// 				},
// 				"kind":        EmailMessagingProviderKindLabel,
// 				"credentials": "default_email_creds",
// 			},
// 		},
// 		{
// 			name:         "extract existing passwordless email provider",
// 			providerName: "passwordless-email",
// 			providerKind: EmailMessagingProviderKindLabel,
// 			want: map[string]any{
// 				"passwordless-email": &EmailProvider{
// 					Name:         "passwordless-email",
// 					Address:      "localhost",
// 					Protocol:     "smtps",
// 					Passwordless: true,
// 					SenderEmail:  "root@localhost",
// 					SenderName:   "My Auth Portal",
// 				},
// 				"kind":        EmailMessagingProviderKindLabel,
// 				"credentials": "passwordless",
// 			},
// 		},
// 		{
// 			name:         "extract existing file provider",
// 			providerName: "default-file",
// 			providerKind: FileMessagingProviderKindLabel,
// 			want: map[string]any{
// 				"default-file": &FileProvider{
// 					Name:        "default-file",
// 					RootDir:     "/var/spool/auth-messaging/",
// 					SenderEmail: "root@localhost",
// 					SenderName:  "My Auth Portal",
// 				},
// 				"kind":        FileMessagingProviderKindLabel,
// 				"credentials": "",
// 			},
// 		},
// 		{
// 			name:         "extract non existing email provider",
// 			providerName: "foo",
// 			providerKind: EmailMessagingProviderKindLabel,
// 			want: map[string]any{
// 				"kind":        UnknownMessagingProviderKindLabel,
// 				"credentials": "",
// 			},
// 		},
// 		{
// 			name:         "extract non existing email provider",
// 			providerName: "foo",
// 			providerKind: FileMessagingProviderKindLabel,
// 			want: map[string]any{
// 				"kind":        UnknownMessagingProviderKindLabel,
// 				"credentials": "",
// 			},
// 		},
// 	}

// 	for _, tc := range testcases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			cfg := &Config{}
// 			for _, instruction := range instructions {
// 				cfg.Add(instruction)
// 			}
// 			err := cfg.Validate()
// 			if err != nil {
// 				t.Fatalf("unexpected error: %v", err)
// 			}

// 			got := make(map[string]any)

// 			switch tc.providerKind {
// 			case EmailMessagingProviderKindLabel:
// 				if cfg.ExtractEmailProvider(tc.providerName) != nil {
// 					got[tc.providerName] = cfg.ExtractEmailProvider(tc.providerName)
// 				}
// 			case FileMessagingProviderKindLabel:
// 				if cfg.ExtractFileProvider(tc.providerName) != nil {
// 					got[tc.providerName] = cfg.ExtractFileProvider(tc.providerName)
// 				}
// 			}
// 			got["kind"] = cfg.GetProviderType(tc.providerName)
// 			got["credentials"] = cfg.FindProviderCredentials(tc.providerName)

// 			if diff := cmp.Diff(tc.want, got); diff != "" {
// 				t.Errorf("ExtractGeneric mismatch (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }

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

package messaging

import (
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"testing"
)

type dummyProvider struct {
}

func (p *dummyProvider) Validate() error {
	return nil
}

func TestAddProviders(t *testing.T) {
	tmpDir, err := tests.TempDir("TestAddMessagingProviders")
	if err != nil {
		t.Fatal(err)
	}

	testcases := []struct {
		name         string
		providerName string
		entry        Provider
		want         string
		shouldErr    bool
		err          error
	}{
		{
			name:         "test valid email provider config",
			providerName: "default",
			entry: &EmailProvider{
				Name:        "default",
				Address:     "localhost",
				Protocol:    "smtp",
				Credentials: "default_email_creds",
				SenderEmail: "root@localhost",
			},
			want: `{
              "email_providers": [
                {
                  "address": "localhost",
                  "credentials": "default_email_creds",
                  "name": "default",
                  "protocol": "smtp",
				  "sender_email": "root@localhost"
                }
              ]
            }`,
		},
		{
			name:         "test valid email provider passwordless config",
			providerName: "default",
			entry: &EmailProvider{
				Name:         "default",
				Address:      "localhost",
				Protocol:     "smtp",
				Passwordless: true,
				SenderEmail:  "root@localhost",
			},
			want: `{
              "email_providers": [
                {
                  "address": "localhost",
                  "name": "default",
                  "protocol": "smtp",
				  "passwordless": true,
                  "sender_email": "root@localhost"
                }
              ]
            }`,
		},
		{
			name:         "test valid file provider config",
			providerName: "default",
			entry: &FileProvider{
				Name:    "default",
				RootDir: tmpDir,
			},
			want: `{
              "file_providers": [
                {
                  "name": "default",
				  "root_dir": "` + tmpDir + `"
                }
              ]
            }`,
		},
		{
			name:      "test invalid messaging provider config",
			entry:     &dummyProvider{},
			shouldErr: true,
			err:       errors.ErrMessagingAddProviderConfigType.WithArgs(&dummyProvider{}),
		},
		{
			name: "test file provider config without root directory",
			entry: &FileProvider{
				Name: "default",
			},
			shouldErr: true,
			err:       errors.ErrMessagingProviderKeyValueEmpty.WithArgs("root_dir"),
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

			if !cfg.FindProvider(tc.providerName) {
				t.Fatalf("failed FindProvider with %q", tc.providerName)
			}

			switch tc.entry.(type) {
			case *EmailProvider:
				p := cfg.ExtractEmailProvider(tc.providerName)
				if p == nil {
					t.Fatalf("failed to extract %q file provider", tc.providerName)
				}
				providerCreds := cfg.FindProviderCredentials(tc.providerName)
				switch providerCreds {
				case "passwordless":
					if !p.Passwordless {
						t.Fatalf("provider credentials mismatch: %v, %v", providerCreds, p.Credentials)
					}
				case p.Credentials:
				default:
					t.Fatalf("provider credentials mismatch: %v, %v", providerCreds, p.Credentials)
				}
			case *FileProvider:
				p := cfg.ExtractFileProvider(tc.providerName)
				if p == nil {
					t.Fatalf("failed to extract %q file provider", tc.providerName)
				}
			}

			if tc.name == "test valid email provider config" {
				if cfg.FindProvider("foobar") {
					t.Fatal("unexpected success with FindProvider")
				}

				if cfg.ExtractEmailProvider("foo") != nil {
					t.Fatal("unexpected success with ExtractEmailProvider")
				}

				if cfg.ExtractFileProvider("foo") != nil {
					t.Fatal("unexpected success with ExtractEmailProvider")
				}
				if cfg.FindProviderCredentials("foo") != "" {
					t.Fatal("unexpected success with FindProviderCredentials")
				}
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %s", tests.UnpackJSON(t, got))
				t.Errorf("Add() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

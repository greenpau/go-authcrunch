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

package sso

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func TestNewSingleSignOnProviderRejectsMalformedKeyMaterial(t *testing.T) {
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	validCert := "../../testdata/sso/authp_saml.crt"
	validKey := "../../testdata/sso/authp_saml.key"
	for _, tc := range []struct {
		name, cert, key, want string
	}{
		{"nil config", "", "", "configuration is nil"},
		{"certificate without PEM", write("cert.pem", []byte("not pem")), validKey, "certificate PEM block not found"},
		{"malformed certificate DER", write("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")})), validKey, "certificate parse error"},
		{"private key without PEM", validCert, write("key.pem", []byte("not pem")), "private key PEM block not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *SingleSignOnProviderConfig
			if tc.name != "nil config" {
				cfg = &SingleSignOnProviderConfig{Name: "aws", Driver: "aws", EntityID: "urn:authcrunch:test", Locations: []string{"https://example.test/sso"}, CertPath: tc.cert, PrivateKeyPath: tc.key}
			}
			provider, err := NewSingleSignOnProvider(cfg, zap.NewNop())
			if provider != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("provider = %T, error = %v, want error containing %q", provider, err, tc.want)
			}
		})
	}
}

func TestNewSingleSignOnProvider(t *testing.T) {
	testcases := []struct {
		name          string
		config        *SingleSignOnProviderConfig
		disableLogger bool
		want          string
		shouldErr     bool
		err           error
	}{
		{
			name: "test valid sso provider",
			config: &SingleSignOnProviderConfig{
				Name:           "aws",
				Driver:         "aws",
				EntityID:       "caddy-authp-idp",
				PrivateKeyPath: "../../testdata/sso/authp_saml.key",
				CertPath:       "../../testdata/sso/authp_saml.crt",
				Locations: []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			want: `{
				"name": "aws",
				"driver": "aws",
			    "config": {
	                "name":             "aws",
		            "driver":           "aws",
			        "entity_id":        "caddy-authp-idp",
				    "private_key_path": "../../testdata/sso/authp_saml.key",
					"cert_path": "../../testdata/sso/authp_saml.crt",
					"locations": [
						"https://localhost/sso/aws",
	                    "https://127.0.0.1/sso/aws"
		            ]
				}
            }`,
		},
		/*
					{
						name: "test saml identity provider",
						config: &SingleSignOnProviderConfig{
							Name: "jumpcloud",
							Kind: "saml",
							Params: map[string]interface{}{
								"realm":                  "jumpcloud",
								"driver":                 "generic",
								"idp_metadata_location":  "JumpCloud-saml2-metadata.xml",
								"idp_sign_cert_location": "certificate.pem",
								"idp_login_url":          "https://sso.jumpcloud.com/saml2/authp",
								"application_name":       "Auth Portal",
								"entity_id":              "urn:authp",
								"acs_urls": []string{
									"https://localhost/saml/jumpcloud",
								},
							},
						},
						want: `{
						  "name": "jumpcloud",
			              "kind": "saml",
			              "realm": "jumpcloud"
						}`,
					},
		*/
		{
			name: "test logger nil error",
			config: &SingleSignOnProviderConfig{
				Name:           "aws",
				Driver:         "aws",
				EntityID:       "caddy-authp-idp",
				PrivateKeyPath: "/tmp/ssoprivatekey.pem",
				Locations: []string{
					"https://localhost/sso/aws",
					"https://127.0.0.1/sso/aws",
				},
			},
			disableLogger: true,
			shouldErr:     true,
			err:           errors.ErrSingleSignOnProviderConfigureLoggerNotFound,
		},

		/*
			{
				name: "test config validation error",
				config: &SingleSignOnProviderConfig{
					Kind: "local",
					Params: map[string]interface{}{
						"path":  "foo",
						"realm": "local",
					},
				},
				shouldErr: true,
				err: errors.ErrSingleSignOnProviderConfigInvalid.WithArgs(
					"empty identity provider name",
				),
			},
		*/
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var logger *zap.Logger
			if !tc.disableLogger {
				logger = logutil.NewLogger()
			}

			provider, err := NewSingleSignOnProvider(tc.config, logger)
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
			got := map[string]interface{}{
				"name":   provider.GetName(),
				"driver": provider.GetDriver(),
				"config": provider.GetConfig(),
			}

			want := tests.Unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %v", tests.UnpackJSON(t, got))
				t.Errorf("NewSingleSignOnProvider() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

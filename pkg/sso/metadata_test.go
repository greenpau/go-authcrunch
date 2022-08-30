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
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	fileutil "github.com/greenpau/go-authcrunch/pkg/util/file"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func TestGetMetadata(t *testing.T) {
	testcases := []struct {
		name             string
		config           *SingleSignOnProviderConfig
		metadataFilePath string
		disableLogger    bool
		want             string
		shouldErr        bool
		err              error
	}{
		{
			name:             "test valid sso provider metadata",
			metadataFilePath: "../../testdata/sso/authp_saml_metadata.xml",
			config: &SingleSignOnProviderConfig{
				Name:           "aws",
				Driver:         "aws",
				EntityID:       "caddy-authp-idp",
				PrivateKeyPath: "../../testdata/sso/authp_saml.key",
				CertPath:       "../../testdata/sso/authp_saml.crt",
				Locations: []string{
					"https://localhost/apps/sso/aws",
					"https://127.0.0.1/apps/sso/aws",
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
						"https://localhost/apps/sso/aws",
	                    "https://127.0.0.1/apps/sso/aws"
		            ]
				}
            }`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var logger *zap.Logger
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))
			logger = logutil.NewLogger()
			provider, err := NewSingleSignOnProvider(tc.config, logger)
			if err != nil {
				t.Fatalf("failed initializing sso provider: %v", err)
			}

			want, err := fileutil.ReadFileBytes(tc.metadataFilePath)
			if err != nil {
				t.Fatalf("failed reading %q file: %v", tc.metadataFilePath, err)
			}
			want = bytes.TrimSpace(want)

			got, err := provider.GetMetadata()

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

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("provider.GetMetadata() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

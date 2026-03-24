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

package authn

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func buildLogoutPortal(trustedConfigs []*redirects.RedirectURIMatchConfig) (*Portal, error) {
	f, _ := cookie.NewFactory(nil)

	cryptoKeyStoreConfig, err := kms.NewCryptoKeyStoreConfig(nil)
	if err != nil {
		return nil, err
	}
	v, err := validator.NewTokenValidator(cryptoKeyStoreConfig, logutil.NewLogger())
	if err != nil {
		return nil, err
	}

	return &Portal{
		config: &PortalConfig{
			Name:                            "testPortal",
			TrustedLogoutRedirectURIConfigs: trustedConfigs,
		},
		logger:    zap.L(),
		cookie:    f,
		validator: v,
	}, nil
}

func TestHandleHTTPLogout(t *testing.T) {
	trustedConfig, err := redirects.NewRedirectURIMatchConfig("exact", "app.example.com", "exact", "/bye")
	if err != nil {
		t.Fatalf("failed to build redirect config: %v", err)
	}
	if err := trustedConfig.Validate(); err != nil {
		t.Fatalf("failed to validate redirect config: %v", err)
	}

	var testcases = []struct {
		name           string
		redirectURI    string
		trustedConfigs []*redirects.RedirectURIMatchConfig
		parsedUser     *user.User
		wantLocation   string
	}{
		{
			name:           "redirect_uri honored when trusted",
			redirectURI:    "https://app.example.com/bye",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			parsedUser: &user.User{
				Claims: &user.Claims{
					Subject: "testuser",
					Issuer:  "https://auth.example.com",
				},
			},
			wantLocation: "https://app.example.com/bye",
		},
		{
			name:           "redirect_uri rejected when untrusted",
			redirectURI:    "https://evil.example.com/steal",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			parsedUser: &user.User{
				Claims: &user.Claims{
					Subject: "testuser",
					Issuer:  "https://auth.example.com",
				},
			},
			wantLocation: "/login",
		},
		{
			name:           "OAuth user goes to realm logout",
			redirectURI:    "https://app.example.com/bye",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			parsedUser: &user.User{
				Claims: &user.Claims{
					Subject: "testuser",
					Issuer:  "https://auth.example.com/oauth2/generic",
				},
			},
			wantLocation: "/oauth2/generic/logout",
		},
		{
			name:           "redirect_uri honored for unauthenticated caller",
			redirectURI:    "https://app.example.com/bye",
			trustedConfigs: []*redirects.RedirectURIMatchConfig{trustedConfig},
			parsedUser:     nil,
			wantLocation:   "https://app.example.com/bye",
		},
		{
			name:           "no trusted config falls to login",
			redirectURI:    "https://app.example.com/bye",
			trustedConfigs: nil,
			parsedUser:     nil,
			wantLocation:   "/login",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := buildLogoutPortal(tc.trustedConfigs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			rw := buildCustomResponseWriter()
			reqURL := &url.URL{
				Scheme:   "https",
				Host:     "auth.example.com",
				Path:     "/logout",
				RawQuery: "redirect_uri=" + url.QueryEscape(tc.redirectURI),
			}
			r := &http.Request{
				URL:    reqURL,
				Method: "GET",
				Host:   "auth.example.com",
			}
			rr := requests.NewRequest()

			err = p.handleHTTPLogout(context.Background(), rw, r, rr, tc.parsedUser)
			tests.EvalObjectsWithLog(t, "error", nil, err, []string{})
			tests.EvalObjectsWithLog(t, "status_code", http.StatusFound, rw.statusCode, []string{})

			location := rw.Header().Get("Location")
			tests.EvalObjectsWithLog(t, "location", true, strings.HasSuffix(location, tc.wantLocation), []string{})
		})
	}
}

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

package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewIdentityProvider(t *testing.T) {
	// Generate JWKS keys from RSA key-pairs.
	pk1, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	jpk1, err := NewJwksKeyFromRSAPrivateKey(pk1)
	if err != nil {
		t.Fatal(err)
	}

	jpk2, err := NewJwksKeyFromRSAPrivateKey(pk2)
	if err != nil {
		t.Fatal(err)
	}

	jwksKeys := []*JwksKey{jpk1, jpk2}

	// Initialize HTTP server.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := make(map[string]interface{})
		switch r.URL.Path {
		case "/oauth/.well-known/openid-configuration":
			resp["authorization_endpoint"] = "https://" + r.Host + "/oauth/authorize"
			resp["token_endpoint"] = "https://" + r.Host + "/oauth/access_token"
			resp["jwks_uri"] = "https://" + r.Host + "/oauth/jwks.json"
		case "/oauth/jwks.json":
			resp["keys"] = jwksKeys
		default:
			t.Fatalf("unsupported path: %v", r.URL.Path)
		}

		b, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("failed to marshal %T: %v", resp, err)
		}

		fmt.Fprintln(w, string(b))
	}))
	defer ts.Close()

	tsURL, _ := url.Parse(ts.URL)
	// t.Logf("Server: %s", ts.URL)

	testcases := []struct {
		name      string
		config    *Config
		logger    *zap.Logger
		want      map[string]interface{}
		shouldErr bool
		errPhase  string
		err       error
	}{
		{
			name: "generic oauth provider",
			config: &Config{
				Name:                  "contoso",
				Realm:                 "contoso",
				Driver:                "generic",
				ClientID:              "foo",
				ClientSecret:          "bar",
				BaseAuthURL:           ts.URL + "/oauth",
				MetadataURL:           ts.URL + "/oauth/.well-known/openid-configuration",
				TLSInsecureSkipVerify: true,
			},
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"kind":  "oauth",
				"name":  "contoso",
				"realm": "contoso",
				"config": map[string]interface{}{
					"base_auth_url":            ts.URL + "/oauth",
					"client_id":                "foo",
					"client_secret":            "bar",
					"driver":                   "generic",
					"identity_token_name":      "id_token",
					"metadata_url":             ts.URL + "/oauth/.well-known/openid-configuration",
					"name":                     "contoso",
					"realm":                    "contoso",
					"required_token_fields":    []interface{}{"access_token", "id_token"},
					"response_type":            []interface{}{"code"},
					"scopes":                   []interface{}{"openid", "email", "profile"},
					"server_name":              tsURL.Host,
					"tls_insecure_skip_verify": bool(true),
					"login_icon": map[string]interface{}{
						"background_color": string("#324960"),
						"class_name":       string("lab la-codepen la-2x"),
						"color":            string("white"),
						"text_color":       string("#37474f"),
					},
				},
			},
		},
		{
			name: "generic oauth provider with static jwks keys",
			config: &Config{
				Name:                "contoso",
				Realm:               "contoso",
				Driver:              "generic",
				ClientID:            "foo",
				ClientSecret:        "bar",
				BaseAuthURL:         "https://localhost/oauth",
				ResponseType:        []string{"code"},
				RequiredTokenFields: []string{"access_token"},
				AuthorizationURL:    "https://localhost/oauth/authorize",
				TokenURL:            "https://localhost/oauth/access_token",
				JwksKeys: map[string]string{
					"87329db33bf": "../../../testdata/oauth/87329db33bf_pub.pem",
				},
				KeyVerificationDisabled: true,
				TLSInsecureSkipVerify:   true,
			},
			logger: logutil.NewLogger(),
			want: map[string]interface{}{
				"kind":  "oauth",
				"name":  "contoso",
				"realm": "contoso",
				"config": map[string]interface{}{
					"base_auth_url":             "https://localhost/oauth",
					"token_url":                 "https://localhost/oauth/access_token",
					"authorization_url":         "https://localhost/oauth/authorize",
					"client_id":                 "foo",
					"client_secret":             "bar",
					"driver":                    "generic",
					"identity_token_name":       "id_token",
					"name":                      "contoso",
					"realm":                     "contoso",
					"required_token_fields":     []interface{}{"access_token"},
					"response_type":             []interface{}{"code"},
					"scopes":                    []interface{}{"openid", "email", "profile"},
					"server_name":               "localhost",
					"tls_insecure_skip_verify":  true,
					"key_verification_disabled": true,
					"jwks_keys": map[string]interface{}{
						"87329db33bf": "../../../testdata/oauth/87329db33bf_pub.pem",
					},
					"login_icon": map[string]interface{}{
						"background_color": string("#324960"),
						"class_name":       string("lab la-codepen la-2x"),
						"color":            string("white"),
						"text_color":       string("#37474f"),
					},
				},
			},
		},
		{
			name: "test nil logger",
			config: &Config{
				Realm: "azure",
			},
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityProviderConfigureLoggerNotFound,
		},
		{
			name: "test invalid config",
			config: &Config{
				Realm: "azure",
			},
			logger:    logutil.NewLogger(),
			shouldErr: true,
			errPhase:  "initialize",
			err:       errors.ErrIdentityProviderConfigureNameEmpty,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			prv, err := NewIdentityProvider(tc.config, tc.logger)
			if tc.errPhase == "initialize" {
				if tests.EvalErrWithLog(t, err, "NewIdentityProvider", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "NewIdentityProvider", false, nil, msgs) {
					return
				}
			}

			err = prv.Configure()
			if tc.errPhase == "configure" {
				if tests.EvalErrWithLog(t, err, "IdentityProvider.Configure", tc.shouldErr, tc.err, msgs) {
					return
				}
			} else {
				if tests.EvalErrWithLog(t, err, "IdentityProvider.Configure", false, nil, msgs) {
					return
				}
			}

			got["name"] = prv.GetName()
			got["realm"] = prv.GetRealm()
			got["kind"] = prv.GetKind()
			got["config"] = prv.GetConfig()

			tests.EvalObjectsWithLog(t, "IdentityProvider", tc.want, got, msgs)
		})
	}
}

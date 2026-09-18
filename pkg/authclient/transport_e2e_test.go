// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package authclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authclient/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

type nativeRecordingTransport struct {
	t     *testing.T
	next  http.RoundTripper
	count int
}

func (tr *nativeRecordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.count++
	for _, name := range []string{"Cookie", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
		if len(r.Header.Values(name)) != 0 {
			tr.t.Error("native client sent browser state")
		}
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	var request apiauth.AuthRequest
	if err := json.Unmarshal(body, &request); err != nil {
		tr.t.Error(err)
	}
	if request.RefreshTransport != authclient.RefreshTransportBody {
		tr.t.Error("checkpoint lost native transport")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	response, err := tr.next.RoundTrip(r)
	if err == nil && len(response.Cookies()) != 0 {
		tr.t.Error("native login set a browser cookie")
	}
	return response, err
}

func nativeConfig(t *testing.T, f *e2ePortal, factor bool) *authclient.Config {
	t.Helper()
	source := f.config()
	args := [][]string{{"base", "url", source.BaseURL}, {"username", source.Username}, {"realm", source.Realm}, {"password", source.Password}, {"refresh", "transport", "body"}}
	if factor {
		args = append(args, []string{"totp", "secret", e2eTOTPSecret})
	}
	var statements []string
	for _, value := range args {
		statements = append(statements, cfgutil.EncodeArgs(value))
	}
	cfg, err := parser.NewAuthenticationClientConfigFromDirectives(statements)
	if err != nil {
		t.Fatal(err)
	}
	// Persisted adapter configuration must retain the selected transport.
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var reopened authclient.Config
	if err := json.Unmarshal(data, &reopened); err != nil {
		t.Fatal(err)
	}
	return &reopened
}

func TestE2ENativeAuthenticate(t *testing.T) {
	for _, factor := range []string{"", "totp", "mfa"} {
		for _, custom := range []bool{false, true} {
			name := factor + "/default"
			tokenName := ""
			if custom {
				name = factor + "/custom"
				tokenName = "CUSTOM_ACCESS_TOKEN"
			}
			t.Run(name, func(t *testing.T) {
				f := newE2EPortal(t, e2ePortalOptions{basePath: "/auth", factor: factor, tokenName: tokenName, refresh: true})
				supplied := f.server.Client()
				supplied.Jar, _ = cookiejar.New(nil)
				u, _ := url.Parse(f.server.URL)
				supplied.Jar.SetCookies(u, []*http.Cookie{{Name: "AUTHP_SESSION_ID", Value: "unrelated-browser-session", Path: "/"}, {Name: "AUTHP_REFRESH_TOKEN", Value: "unrelated-browser-refresh", Path: "/auth/api"}})
				before := supplied.Jar.Cookies(u.ResolveReference(&url.URL{Path: "/auth/api/refresh_token"}))
				tr := &nativeRecordingTransport{t: t, next: supplied.Transport}
				injected := *supplied
				injected.Transport = tr
				options := authclient.Options{HTTPClient: &injected}
				client, err := authclient.NewClient(nativeConfig(t, f, factor != ""), options)
				if err != nil {
					t.Fatal(err)
				}
				var previous *authclient.Credentials
				var results []*authclient.Credentials
				for attempt := range 2 {
					activeClient := client
					if factor != "" && attempt == 1 {
						cfg := nativeConfig(t, f, true)
						cfg.TOTPSecret = ""
						options.Prompt = func(_ context.Context, kind authclient.PromptKind) (string, error) {
							switch kind {
							case authclient.PromptMFA:
								return "totp", nil
							case authclient.PromptTOTP:
								return e2eTOTPAt(time.Now().Add(30 * time.Second)), nil
							default:
								return "", errors.New("unexpected native login prompt")
							}
						}
						activeClient, err = authclient.NewClient(cfg, options)
						if err != nil {
							t.Fatal(err)
						}
					}
					credentials, err := activeClient.Authenticate(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if credentials.RefreshToken == "" || credentials.SessionID == "" || credentials.RefreshTokenName != "AUTHP_REFRESH_TOKEN" || credentials.AccessExpiresAt <= 0 || credentials.RefreshExpiresAt <= 0 || credentials.SessionExpiresAt <= 0 {
						t.Fatal("native login omitted credentials or lifetime metadata")
					}
					if custom && credentials.AccessTokenName != "custom_access_token" {
						t.Fatal("custom access token name lost")
					}
					if previous != nil && (previous.RefreshToken == credentials.RefreshToken || previous.SessionID == credentials.SessionID) {
						t.Fatal("fresh native login reused previous credentials")
					}
					previous = credentials
					results = append(results, credentials)
				}
				want := 4
				if factor != "" {
					want = 6
				}
				f.assertLoginRequests(t, want)
				if tr.count != want {
					t.Fatal("client issued unexpected requests")
				}
				after := supplied.Jar.Cookies(u.ResolveReference(&url.URL{Path: "/auth/api/refresh_token"}))
				if !reflect.DeepEqual(before, after) {
					t.Fatal("native authentication changed supplied browser jar")
				}
				for _, credentials := range results {
					f.assertPersistedCredentialAccess(t, credentials)
				}
			})
		}
	}
}

func TestE2ENativeTransportUnavailable(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		name := "refresh disabled"
		if refresh {
			name = "body disabled"
		}
		t.Run(name, func(t *testing.T) {
			f := newE2EPortal(t, e2ePortalOptions{basePath: "/auth", refresh: refresh, disableBody: true})
			client, err := authclient.NewClient(nativeConfig(t, f, false), authclient.Options{HTTPClient: f.server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			var status *authclient.HTTPError
			if credentials != nil || !errors.As(err, &status) || status.StatusCode != http.StatusBadRequest {
				t.Fatal("unavailable native transport did not return HTTP 400 without credentials")
			}
			f.assertLoginRequests(t, 1)
		})
	}
	t.Run("default mode requires native opt in", func(t *testing.T) {
		f := newE2EPortal(t, e2ePortalOptions{basePath: "/auth", refresh: true})
		cfg := f.config()
		client, err := authclient.NewClient(&cfg, authclient.Options{HTTPClient: f.server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		credentials, err := client.Authenticate(t.Context())
		if credentials != nil || !errors.Is(err, authclient.ErrNativeTransportRequired) {
			t.Fatal("browser metadata did not produce the intentional transport error")
		}
		f.assertLoginRequests(t, 2)
	})
}

func TestE2ENativeCredentialsRejected(t *testing.T) {
	for _, factor := range []bool{false, true} {
		name := "password"
		method := ""
		if factor {
			name = "TOTP"
			method = "totp"
		}
		t.Run(name, func(t *testing.T) {
			f := newE2EPortal(t, e2ePortalOptions{basePath: "/auth", factor: method, refresh: true})
			cfg := nativeConfig(t, f, factor)
			if factor {
				cfg.TOTPSecret = "different-fixture-secret"
				cfg.TOTPCodeLength = 4
			} else {
				cfg.Password = "wrong-fixture-password"
			}
			client, err := authclient.NewClient(cfg, authclient.Options{HTTPClient: f.server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			var status *authclient.HTTPError
			if credentials != nil || !errors.As(err, &status) || status.StatusCode != http.StatusUnauthorized {
				t.Fatal("invalid native credentials were not rejected")
			}
			want := 2
			if factor {
				want = 3
			}
			f.assertLoginRequests(t, want)
		})
	}
}

// Inspect the actual wire envelope while the real TLS portal verifies both
// factors and issues credentials. The separate strict legacy-schema unit test
// proves why this field must remain absent in cookie/default mode.
type legacyRecordingTransport struct {
	t    *testing.T
	next http.RoundTripper
}

func (tr legacyRecordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	var request map[string]json.RawMessage
	if err := json.Unmarshal(body, &request); err != nil {
		tr.t.Error(err)
	}
	if _, present := request["refresh_transport"]; present {
		tr.t.Error("default transport changed the legacy wire schema")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return tr.next.RoundTrip(r)
}

func TestE2ELegacyCookieTransport(t *testing.T) {
	f := newE2EPortal(t, e2ePortalOptions{basePath: "/auth", factor: "totp"})
	cfg := f.config()
	cfg.TOTPSecret = e2eTOTPSecret
	injected := *f.server.Client()
	injected.Transport = legacyRecordingTransport{t: t, next: injected.Transport}
	client, err := authclient.NewClient(&cfg, authclient.Options{HTTPClient: &injected})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.assertLoginRequests(t, 3)
	f.assertPersistedCredentialAccess(t, credentials)
}

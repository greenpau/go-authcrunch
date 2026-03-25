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

package validator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
)

func TestAuthorizationSources(t *testing.T) {
	var testcases = []struct {
		name                         string
		allowedCookieNames           []string
		allowedHeaderNames           []string
		allowedQueryParamNames       []string
		allowedTokenSources          []string
		enableQueryViolations        bool
		enableCookieViolations       bool
		enableHeaderViolations       bool
		enableBearerHeaderViolations bool
		enableBearerHeader           bool
		// The name of the token.
		entries   []*testutils.InjectedTestToken
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "default token sources and names with auth header claim injection",
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceHeader, `"name": "foo",`),
			},
			allowedHeaderNames: []string{testutils.TestAccessTokenHeaderName},
			want: map[string]interface{}{
				"token_name": testutils.TestAccessTokenHeaderName,
				"claim_name": "foo",
			},
		},
		{
			name: "default token sources and names with cookie claim injection",
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken(strings.ToUpper(testutils.TestAccessTokenHeaderName), tokenSourceCookie, `"name": "foo",`),
			},
			allowedCookieNames: []string{strings.ToUpper(testutils.TestAccessTokenHeaderName)},

			want: map[string]interface{}{
				"token_name": strings.ToUpper(testutils.TestAccessTokenHeaderName),
				"claim_name": "foo",
			},
			shouldErr: false,
		},
		{
			name: "default token sources and names with query parameter claim injection",
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken("", tokenSourceQuery, `"name": "foo",`),
			},
			allowedQueryParamNames: []string{testutils.TestAccessTokenHeaderName},
			want: map[string]interface{}{
				"token_name": testutils.TestAccessTokenHeaderName,
				"claim_name": "foo",
			},
		},
		{
			name: "default token source priorities, same token name, different entries injected in query parameter and auth header",
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceHeader, `"name": "foo",`),
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceQuery, `"name": "bar",`),
			},
			allowedHeaderNames:     []string{testutils.TestAccessTokenHeaderName},
			allowedQueryParamNames: []string{testutils.TestAccessTokenHeaderName},
			want: map[string]interface{}{
				"token_name": testutils.TestAccessTokenHeaderName,
				"claim_name": "foo",
			},
		},
		{
			name:                "custom token source priorities, same token name, different entries injected in query parameter and auth header",
			allowedTokenSources: []string{tokenSourceQuery, tokenSourceCookie, tokenSourceHeader},
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceHeader, `"name": "foo",`),
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceQuery, `"name": "bar",`),
			},
			allowedHeaderNames:     []string{testutils.TestAccessTokenHeaderName},
			allowedQueryParamNames: []string{testutils.TestAccessTokenHeaderName},
			want: map[string]interface{}{
				"token_name": testutils.TestAccessTokenHeaderName,
				"claim_name": "bar",
			},
		},
		{
			name:                "bearer authorization header",
			allowedTokenSources: []string{tokenSourceHeader, tokenSourceQuery, tokenSourceCookie},
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceHeader, `"name": "foo",`),
			},
			enableBearerHeader:     true,
			allowedCookieNames:     []string{strings.ToUpper(testutils.TestAccessTokenHeaderName)},
			allowedHeaderNames:     []string{testutils.TestAccessTokenHeaderName},
			allowedQueryParamNames: []string{testutils.TestAccessTokenHeaderName},
			want: map[string]interface{}{
				"token_name": "bearer",
				"claim_name": "foo",
			},
		},
		{
			name: "default token sources and names with custom token name injection",
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken("foobar", tokenSourceHeader, `"name": "foo",`),
			},
			shouldErr: true,
			err:       errors.ErrNoTokenFound,
		},
		{
			name: "custom token names with standard token name injection",
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceHeader, `"name": "foo",`),
			},
			allowedHeaderNames: []string{"foobar_token"},
			shouldErr:          true,
			err:                errors.ErrNoTokenFound,
		},
		{
			name:                "cookie token source with auth header token injection",
			allowedTokenSources: []string{tokenSourceCookie},
			entries: []*testutils.InjectedTestToken{
				testutils.NewInjectedTestToken(testutils.TestAccessTokenHeaderName, tokenSourceHeader, `"name": "foo",`),
			},
			allowedHeaderNames: []string{testutils.TestAccessTokenHeaderName},
			shouldErr:          true,
			err:                errors.ErrNoTokenFound,
		},
		{
			name:                   "query parameter token source violations",
			enableQueryViolations:  true,
			allowedCookieNames:     []string{strings.ToUpper(testutils.TestAccessTokenHeaderName)},
			allowedHeaderNames:     []string{testutils.TestAccessTokenHeaderName},
			allowedQueryParamNames: []string{testutils.TestAccessTokenHeaderName},
			shouldErr:              true,
			err:                    errors.ErrNoTokenFound,
		},
		{
			name:                   "cookie token source violations",
			enableCookieViolations: true,
			allowedCookieNames:     []string{"foobar"},
			allowedHeaderNames:     []string{testutils.TestAccessTokenHeaderName},
			allowedQueryParamNames: []string{testutils.TestAccessTokenHeaderName},
			shouldErr:              true,
			err:                    errors.ErrNoTokenFound,
		},
		{
			name:                   "header token source violations",
			enableHeaderViolations: true,
			allowedCookieNames:     []string{strings.ToUpper(testutils.TestAccessTokenHeaderName)},
			allowedHeaderNames:     []string{testutils.TestAccessTokenHeaderName},
			allowedQueryParamNames: []string{testutils.TestAccessTokenHeaderName},
			shouldErr:              true,
			err:                    errors.ErrNoTokenFound,
		},
		{
			name:                         "bearer header token source violations",
			enableBearerHeaderViolations: true,
			allowedCookieNames:           []string{strings.ToUpper(testutils.TestAccessTokenHeaderName)},
			allowedHeaderNames:           []string{testutils.TestAccessTokenHeaderName},
			allowedQueryParamNames:       []string{testutils.TestAccessTokenHeaderName},
			shouldErr:                    true,
			err:                          errors.ErrNoTokenFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Test name: %s", tc.name)
			ctx := context.Background()
			ks, err := testutils.NewTestCryptoKeyStore()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			keys := ks.GetKeys()
			signingKey := keys[0]
			opts := options.NewTokenValidatorOptions()
			if tc.enableBearerHeaderViolations || tc.enableBearerHeader {
				opts.ValidateBearerHeader = true
			}

			opts.AuthorizationCookieNames = []string{strings.ToUpper(testutils.TestAccessTokenHeaderName)}
			opts.AuthorizationHeaderNames = []string{strings.ToLower(testutils.TestAccessTokenHeaderName)}
			opts.AuthorizationQueryParamNames = []string{strings.ToLower(testutils.TestAccessTokenHeaderName)}

			if len(tc.allowedCookieNames) > 0 {
				opts.AuthorizationCookieNames = tc.allowedCookieNames
			}
			if len(tc.allowedHeaderNames) > 0 {
				opts.AuthorizationHeaderNames = tc.allowedHeaderNames
			}
			if len(tc.allowedQueryParamNames) > 0 {
				opts.AuthorizationQueryParamNames = tc.allowedQueryParamNames
			}

			validator, err := NewTokenValidator(ks.GetConfig(), logutil.NewLogger())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			accessList := testutils.NewTestGuestAccessList()

			if err := validator.Configure(ctx, accessList, opts); err != nil {
				t.Fatal(err)
			}

			if len(tc.allowedTokenSources) > 0 {
				if err := validator.SetSourcePriority(tc.allowedTokenSources); err != nil {
					t.Fatal(err)
				}
			}

			handler := func(_ http.ResponseWriter, r *http.Request) {
				ctx := context.Background()
				var msgs []string
				msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
				if len(tc.allowedCookieNames) > 0 {
					msgs = append(msgs, fmt.Sprintf("allowed cookie names: %s", tc.allowedCookieNames))
				}
				if len(tc.allowedHeaderNames) > 0 {
					msgs = append(msgs, fmt.Sprintf("allowed header names: %s", tc.allowedHeaderNames))
				}
				if len(tc.allowedQueryParamNames) > 0 {
					msgs = append(msgs, fmt.Sprintf("allowed query parameter names: %s", tc.allowedQueryParamNames))
				}

				msgs = append(msgs, fmt.Sprintf("enable bearer header: %v", tc.enableBearerHeader))

				for i, tkn := range tc.entries {
					msgs = append(msgs, fmt.Sprintf("token %d, name: %s, location: %s", i, tkn.Name, tkn.Location))
				}
				ar := requests.NewAuthorizationRequest()
				ar.ID = "TEST_REQUEST_ID"
				ar.SessionID = "TEST_SESSION_ID"
				usr, err := validator.Authorize(ctx, r, ar)
				if tests.EvalErrWithLog(t, err, tc.want, tc.shouldErr, tc.err, msgs) {
					return
				}
				got := make(map[string]interface{})
				got["token_name"] = usr.TokenName
				got["claim_name"] = usr.Claims.Name
				tests.EvalObjectsWithLog(t, "response", tc.want, got, msgs)
			}

			reqURI := "/protected/path"
			if tc.enableQueryViolations {
				reqURI += fmt.Sprintf("?%s=foobarfoo", testutils.TestAccessTokenHeaderName)
			}

			req, err := http.NewRequest("GET", reqURI, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tc.enableCookieViolations {
				req.AddCookie(&http.Cookie{
					Name:    "foobar",
					Value:   "foobar",
					Expires: time.Now().Add(time.Minute * time.Duration(30)),
				})
				req.AddCookie(&http.Cookie{
					Name:    testutils.TestAccessTokenHeaderName,
					Value:   "foobar",
					Expires: time.Now().Add(time.Minute * time.Duration(30)),
				})
			}

			if tc.enableBearerHeaderViolations {
				req.Header.Add("Authorization", "Bearer")
			}

			if tc.enableHeaderViolations {
				req.Header.Add("Authorization", testutils.TestAccessTokenHeaderName)
			}

			for _, entry := range tc.entries {
				tokenName := entry.Name
				if tokenName == "" {
					tokenName = testutils.TestAccessTokenHeaderName
				}
				if err := signingKey.SignToken("HS512", entry.User); err != nil {
					t.Fatal(err)
				}

				if tc.enableBearerHeader {
					req.Header.Add("Authorization", "Bearer "+entry.User.Token)
					break
				}

				switch entry.Location {
				case tokenSourceCookie:
					req.AddCookie(testutils.GetCookie(tokenName, entry.User.Token, 10))
				case tokenSourceHeader:
					req.Header.Set("Authorization", fmt.Sprintf("%s=%s", tokenName, entry.User.Token))
				case tokenSourceQuery:
					q := req.URL.Query()
					q.Set(tokenName, entry.User.Token)
					req.URL.RawQuery = q.Encode()
				case "":
					t.Fatal("malformed test: token injection location is empty")
				default:
					t.Fatalf("malformed test: token injection location %s is not supported", entry.Location)
				}
			}

			w := httptest.NewRecorder()
			handler(w, req)
			w.Result()
		})
	}
}

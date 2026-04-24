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
	"net/url"
	"testing"

	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"go.uber.org/zap"
)

const (
	authorizationSetupTestReqPath = "https://hostname/route"
	authorizationSetupTestState   = "state-1"
	authorizationSetupTestNonce   = "nonce-1"
	authorizationSetupTestPKCE    = "challenge-1"
	authorizationSetupTestSession = "session-1"
	authorizationSetupTestRequest = "request-1"
)

func newGoogleAuthorizationSetupTestProvider() *IdentityProvider {
	return &IdentityProvider{
		config: &Config{
			ClientID:     "foo",
			Driver:       "google",
			Scopes:       []string{"identify"},
			ResponseType: []string{"code"},
		},
		authorizationURL: "https://domain/oauth/authorize",
		logger:           zap.NewNop(),
	}
}

func mustPrepareAndFinalizeAuthorizationRedirect(t *testing.T, provider *IdentityProvider, params oauthAuthenticateRequestParams) string {
	t.Helper()

	preparedRedirect, err := provider.prepareAuthorizationRedirectURL(
		authorizationSetupTestReqPath,
		params,
		authorizationSetupTestState,
		authorizationSetupTestNonce,
		authorizationSetupTestSession,
		authorizationSetupTestRequest,
	)
	if err != nil {
		t.Fatalf("prepareAuthorizationRedirectURL() error = %v", err)
	}

	return provider.finalizeAuthorizationRedirectURL(preparedRedirect, authorizationSetupTestPKCE)
}

func mustParseRedirectQuery(t *testing.T, redirectURL string) url.Values {
	t.Helper()

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}

	return parsedURL.Query()
}

func TestEmptyQueryIsNotOAuthResponse(t *testing.T) {
	params := parseOAuthAuthenticateRequestParams(url.Values{})

	if params.isOAuthResponse() {
		t.Fatal("expected empty query to not be an OAuth response")
	}
}

func TestRequestParamExistsWithoutValue(t *testing.T) {
	values := url.Values{
		"prompt": []string{},
	}

	value, exists := getOAuthAuthenticateRequestParam(values, "prompt")

	if !exists {
		t.Fatal("expected prompt key to exist")
	}
	if value != "" {
		t.Fatalf("expected empty prompt value, got %q", value)
	}
}

func TestCodeAndStateAreParsed(t *testing.T) {
	values := url.Values{}
	values.Set("code", "code-1")
	values.Set("state", "state-1")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.codeExists || params.code != "code-1" {
		t.Fatalf("expected code %q, got %q", "code-1", params.code)
	}
	if !params.stateExists || params.state != "state-1" {
		t.Fatalf("expected state %q, got %q", "state-1", params.state)
	}
	if !params.isOAuthResponse() {
		t.Fatal("expected code and state to be an OAuth response")
	}
}

func TestAuthorizationErrorIsParsed(t *testing.T) {
	values := url.Values{}
	values.Set("error", "access_denied")
	values.Set("error_description", "denied by provider")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.errorExists || params.authError != "access_denied" {
		t.Fatalf("expected error %q, got %q", "access_denied", params.authError)
	}
	if !params.errorDescriptionExists || params.errorDescription != "denied by provider" {
		t.Fatalf("expected error_description %q, got %q", "denied by provider", params.errorDescription)
	}
}

func TestTokensAreParsed(t *testing.T) {
	values := url.Values{}
	values.Set("access_token", "access-token-1")
	values.Set("id_token", "id-token-1")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.accessTokenExists || params.accessToken != "access-token-1" {
		t.Fatalf("expected access_token %q, got %q", "access-token-1", params.accessToken)
	}
	if !params.idTokenExists || params.idToken != "id-token-1" {
		t.Fatalf("expected id_token %q, got %q", "id-token-1", params.idToken)
	}
}

func TestLoginHintAndScopesAreParsed(t *testing.T) {
	values := url.Values{}
	values.Set("login_hint", "user@example.com")
	values.Set("additional_scopes", "email profile")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.loginHintExists || params.loginHint != "user@example.com" {
		t.Fatalf("expected login_hint %q, got %q", "user@example.com", params.loginHint)
	}
	if !params.additionalScopesExists || params.additionalScopes != "email profile" {
		t.Fatalf("expected additional_scopes %q, got %q", "email profile", params.additionalScopes)
	}
}

func TestValidGooglePrompts(t *testing.T) {
	testcases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "trims prompt",
			raw:  "  consent  ",
			want: "consent",
		},
		{
			name: "allows consent and select_account",
			raw:  "consent select_account",
			want: "consent select_account",
		},
		{
			name: "preserves request order",
			raw:  "select_account consent",
			want: "select_account consent",
		},
		{
			name: "collapses whitespace",
			raw:  "consent\t select_account\n",
			want: "consent select_account",
		},
		{
			name: "allows none by itself",
			raw:  "none",
			want: "none",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prompt, ok := normalizeOAuthPromptValue(tc.raw)

			if !ok || prompt != tc.want {
				t.Fatalf("expected valid prompt %q, got %q", tc.want, prompt)
			}
		})
	}
}

func TestInvalidGooglePrompts(t *testing.T) {
	testcases := []struct {
		name string
		raw  string
	}{
		{
			name: "empty prompt",
			raw:  "",
		},
		{
			name: "unknown prompt",
			raw:  "bogus",
		},
		{
			name: "unknown prompt mixed with valid prompt",
			raw:  "consent bogus",
		},
		{
			name: "none mixed with consent",
			raw:  "none consent",
		},
		{
			name: "none mixed with select_account",
			raw:  "select_account none",
		},
		{
			name: "duplicate consent",
			raw:  "consent consent",
		},
		{
			name: "duplicate select_account",
			raw:  "select_account select_account",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prompt, ok := normalizeOAuthPromptValue(tc.raw)

			if ok {
				t.Fatalf("expected prompt %q to be invalid", tc.raw)
			}
			if prompt != "" {
				t.Fatalf("expected normalized prompt to be empty, got %q", prompt)
			}
		})
	}
}

func TestConfiguredQueryParamsArePreserved(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.authorizationURL = "https://domain/oauth/authorize?access_type=offline&prompt=none"

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("access_type") != "offline" {
		t.Fatalf("expected access_type %q, got %q", "offline", query.Get("access_type"))
	}
	if query.Get("prompt") != "none" {
		t.Fatalf("expected prompt %q, got %q", "none", query.Get("prompt"))
	}
}

func TestGooglePromptOverridesConfiguredPrompt(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.authorizationURL = "https://domain/oauth/authorize?prompt=none"
	values := url.Values{}
	values.Set("prompt", "consent")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("prompt") != "consent" {
		t.Fatalf("expected prompt %q, got %q", "consent", query.Get("prompt"))
	}
}

func TestGoogleMultiPromptOverridesConfiguredPrompt(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.authorizationURL = "https://domain/oauth/authorize?prompt=none"
	values := url.Values{}
	values.Set("prompt", "consent select_account")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("prompt") != "consent select_account" {
		t.Fatalf("expected prompt %q, got %q", "consent select_account", query.Get("prompt"))
	}
}

func TestNonGooglePromptIsIgnored(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.config.Driver = "discord"
	values := url.Values{}
	values.Set("prompt", "consent")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["prompt"]; exists {
		t.Fatalf("expected prompt to be omitted, got %q", query.Get("prompt"))
	}
}

func TestInvalidGooglePromptIsOmitted(t *testing.T) {
	values := url.Values{}
	values.Set("prompt", "bogus")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newGoogleAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["prompt"]; exists {
		t.Fatalf("expected prompt to be omitted, got %q", query.Get("prompt"))
	}
}

func TestInvalidGooglePromptKeepsConfiguredPrompt(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.authorizationURL = "https://domain/oauth/authorize?prompt=none"
	values := url.Values{}
	values.Set("prompt", "bogus")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("prompt") != "none" {
		t.Fatalf("expected configured prompt %q, got %q", "none", query.Get("prompt"))
	}
}

func TestLoginHintIsForwarded(t *testing.T) {
	values := url.Values{}
	values.Set("login_hint", "user@example.com")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newGoogleAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("login_hint") != "user@example.com" {
		t.Fatalf("expected login_hint %q, got %q", "user@example.com", query.Get("login_hint"))
	}
}

func TestAdditionalScopesAreAppended(t *testing.T) {
	values := url.Values{}
	values.Set("additional_scopes", "email profile")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newGoogleAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("scope") != "identify email profile" {
		t.Fatalf("expected scope %q, got %q", "identify email profile", query.Get("scope"))
	}
}

func TestAuthorizationCodeCallbackIsUsed(t *testing.T) {
	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newGoogleAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	expected := authorizationSetupTestReqPath + "/authorization-code-callback"
	if query.Get("redirect_uri") != expected {
		t.Fatalf("expected redirect_uri %q, got %q", expected, query.Get("redirect_uri"))
	}
}

func TestJSCallbackIsUsed(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.config.JsCallbackEnabled = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	expected := authorizationSetupTestReqPath + "/authorization-code-js-callback"
	if query.Get("redirect_uri") != expected {
		t.Fatalf("expected redirect_uri %q, got %q", expected, query.Get("redirect_uri"))
	}
}

func TestScopeCanBeDisabled(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.disableScope = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["scope"]; exists {
		t.Fatalf("expected scope to be omitted, got %q", query.Get("scope"))
	}
}

func TestResponseTypeCanBeDisabled(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.disableResponseType = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["response_type"]; exists {
		t.Fatalf("expected response_type to be omitted, got %q", query.Get("response_type"))
	}
}

func TestNonceCanBeDisabled(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.disableNonce = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["nonce"]; exists {
		t.Fatalf("expected nonce to be omitted, got %q", query.Get("nonce"))
	}
}

func TestPKCEChallengeIsAdded(t *testing.T) {
	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newGoogleAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("code_challenge") != authorizationSetupTestPKCE {
		t.Fatalf("expected code_challenge %q, got %q", authorizationSetupTestPKCE, query.Get("code_challenge"))
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("expected code_challenge_method %q, got %q", "S256", query.Get("code_challenge_method"))
	}
}

func TestPKCECanBeDisabled(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.disablePKCE = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["code_challenge"]; exists {
		t.Fatalf("expected code_challenge to be omitted, got %q", query.Get("code_challenge"))
	}
	if _, exists := query["code_challenge_method"]; exists {
		t.Fatalf("expected code_challenge_method to be omitted, got %q", query.Get("code_challenge_method"))
	}
}

func TestInvalidAuthorizationURLFailsBeforePKCE(t *testing.T) {
	provider := newGoogleAuthorizationSetupTestProvider()
	provider.authorizationURL = "https://domain/oauth/authorize?prompt=none" + string(byte(1))

	_, err := provider.prepareAuthorizationRedirectURL(
		authorizationSetupTestReqPath,
		parseOAuthAuthenticateRequestParams(url.Values{}),
		authorizationSetupTestState,
		authorizationSetupTestNonce,
		authorizationSetupTestSession,
		authorizationSetupTestRequest,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	expected := autherrors.ErrIdentityProviderConfig.WithArgs("could not parse authorization url")
	if err.Error() != expected.Error() {
		t.Fatalf("expected error %q, got %q", expected, err)
	}
}

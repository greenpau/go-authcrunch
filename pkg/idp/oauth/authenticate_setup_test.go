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

func newAuthorizationSetupTestProvider() *IdentityProvider {
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

func TestParseOAuthAuthenticateRequestParamsEmptyQueryIsNotOAuthResponse(t *testing.T) {
	params := parseOAuthAuthenticateRequestParams(url.Values{})

	if params.isOAuthResponse() {
		t.Fatal("expected empty query to not be an OAuth response")
	}
}

func TestGetOAuthAuthenticateRequestParamHandlesExistingKeyWithNoValues(t *testing.T) {
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

func TestParseOAuthAuthenticateRequestParamsParsesCodeAndState(t *testing.T) {
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

func TestParseOAuthAuthenticateRequestParamsParsesErrorDescription(t *testing.T) {
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

func TestParseOAuthAuthenticateRequestParamsParsesAccessAndIDTokens(t *testing.T) {
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

func TestParseOAuthAuthenticateRequestParamsParsesLoginHintAndAdditionalScopes(t *testing.T) {
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

func TestParseOAuthAuthenticateRequestParamsAllowsPromptNone(t *testing.T) {
	values := url.Values{}
	values.Set("prompt", "none")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.promptExists || !params.promptValid || params.prompt != "none" {
		t.Fatalf("expected valid prompt %q, got %q", "none", params.prompt)
	}
}

func TestParseOAuthAuthenticateRequestParamsAllowsPromptConsent(t *testing.T) {
	values := url.Values{}
	values.Set("prompt", "consent")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.promptExists || !params.promptValid || params.prompt != "consent" {
		t.Fatalf("expected valid prompt %q, got %q", "consent", params.prompt)
	}
}

func TestParseOAuthAuthenticateRequestParamsAllowsPromptSelectAccount(t *testing.T) {
	values := url.Values{}
	values.Set("prompt", "select_account")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.promptExists || !params.promptValid || params.prompt != "select_account" {
		t.Fatalf("expected valid prompt %q, got %q", "select_account", params.prompt)
	}
}

func TestParseOAuthAuthenticateRequestParamsTrimsPrompt(t *testing.T) {
	values := url.Values{}
	values.Set("prompt", "  consent  ")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.promptExists || !params.promptValid || params.prompt != "consent" {
		t.Fatalf("expected valid prompt %q, got %q", "consent", params.prompt)
	}
}

func TestParseOAuthAuthenticateRequestParamsRejectsInvalidPrompt(t *testing.T) {
	values := url.Values{}
	values.Set("prompt", "bogus")

	params := parseOAuthAuthenticateRequestParams(values)

	if !params.promptExists {
		t.Fatal("expected prompt to exist")
	}
	if params.promptValid {
		t.Fatal("expected prompt to be invalid")
	}
	if params.prompt != "" {
		t.Fatalf("expected normalized prompt to be empty, got %q", params.prompt)
	}
}

func TestPrepareAuthorizationRedirectURLPreservesConfiguredQueryParams(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
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

func TestPrepareAuthorizationRedirectURLRequestPromptOverridesConfiguredPrompt(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
	provider.authorizationURL = "https://domain/oauth/authorize?prompt=none"
	values := url.Values{}
	values.Set("prompt", "consent")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("prompt") != "consent" {
		t.Fatalf("expected prompt %q, got %q", "consent", query.Get("prompt"))
	}
}

func TestPrepareAuthorizationRedirectURLIgnoresRequestPromptForNonGoogleDriver(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
	provider.config.Driver = "discord"
	values := url.Values{}
	values.Set("prompt", "consent")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["prompt"]; exists {
		t.Fatalf("expected prompt to be omitted, got %q", query.Get("prompt"))
	}
}

func TestPrepareAuthorizationRedirectURLOmitsInvalidRequestPrompt(t *testing.T) {
	values := url.Values{}
	values.Set("prompt", "bogus")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["prompt"]; exists {
		t.Fatalf("expected prompt to be omitted, got %q", query.Get("prompt"))
	}
}

func TestPrepareAuthorizationRedirectURLInvalidRequestPromptDoesNotOverrideConfiguredPrompt(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
	provider.authorizationURL = "https://domain/oauth/authorize?prompt=none"
	values := url.Values{}
	values.Set("prompt", "bogus")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("prompt") != "none" {
		t.Fatalf("expected configured prompt %q, got %q", "none", query.Get("prompt"))
	}
}

func TestPrepareAuthorizationRedirectURLForwardsLoginHint(t *testing.T) {
	values := url.Values{}
	values.Set("login_hint", "user@example.com")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("login_hint") != "user@example.com" {
		t.Fatalf("expected login_hint %q, got %q", "user@example.com", query.Get("login_hint"))
	}
}

func TestPrepareAuthorizationRedirectURLAppendsAdditionalScopes(t *testing.T) {
	values := url.Values{}
	values.Set("additional_scopes", "email profile")

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(values))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("scope") != "identify email profile" {
		t.Fatalf("expected scope %q, got %q", "identify email profile", query.Get("scope"))
	}
}

func TestPrepareAuthorizationRedirectURLUsesAuthorizationCodeCallback(t *testing.T) {
	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	expected := authorizationSetupTestReqPath + "/authorization-code-callback"
	if query.Get("redirect_uri") != expected {
		t.Fatalf("expected redirect_uri %q, got %q", expected, query.Get("redirect_uri"))
	}
}

func TestPrepareAuthorizationRedirectURLUsesJSCallbackWhenEnabled(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
	provider.config.JsCallbackEnabled = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	expected := authorizationSetupTestReqPath + "/authorization-code-js-callback"
	if query.Get("redirect_uri") != expected {
		t.Fatalf("expected redirect_uri %q, got %q", expected, query.Get("redirect_uri"))
	}
}

func TestPrepareAuthorizationRedirectURLOmitsScopeWhenDisabled(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
	provider.disableScope = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["scope"]; exists {
		t.Fatalf("expected scope to be omitted, got %q", query.Get("scope"))
	}
}

func TestPrepareAuthorizationRedirectURLOmitsResponseTypeWhenDisabled(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
	provider.disableResponseType = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["response_type"]; exists {
		t.Fatalf("expected response_type to be omitted, got %q", query.Get("response_type"))
	}
}

func TestPrepareAuthorizationRedirectURLOmitsNonceWhenDisabled(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
	provider.disableNonce = true

	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, provider, parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if _, exists := query["nonce"]; exists {
		t.Fatalf("expected nonce to be omitted, got %q", query.Get("nonce"))
	}
}

func TestFinalizeAuthorizationRedirectURLAddsPKCEChallenge(t *testing.T) {
	redirect := mustPrepareAndFinalizeAuthorizationRedirect(t, newAuthorizationSetupTestProvider(), parseOAuthAuthenticateRequestParams(url.Values{}))
	query := mustParseRedirectQuery(t, redirect)

	if query.Get("code_challenge") != authorizationSetupTestPKCE {
		t.Fatalf("expected code_challenge %q, got %q", authorizationSetupTestPKCE, query.Get("code_challenge"))
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("expected code_challenge_method %q, got %q", "S256", query.Get("code_challenge_method"))
	}
}

func TestFinalizeAuthorizationRedirectURLOmitsPKCEWhenDisabled(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
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

func TestPrepareAuthorizationRedirectURLReturnsConfigErrorBeforePKCESetup(t *testing.T) {
	provider := newAuthorizationSetupTestProvider()
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

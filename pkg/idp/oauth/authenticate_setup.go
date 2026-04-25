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
	"slices"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"go.uber.org/zap"
)

type oauthAuthenticateRequestParams struct {
	values url.Values

	accessToken            string
	accessTokenExists      bool
	idToken                string
	idTokenExists          bool
	code                   string
	codeExists             bool
	state                  string
	stateExists            bool
	authError              string
	errorExists            bool
	errorDescription       string
	errorDescriptionExists bool
	loginHint              string
	loginHintExists        bool
	additionalScopes       string
	additionalScopesExists bool
	promptRaw              string
	promptExists           bool
}

type preparedAuthorizationRedirectURL struct {
	authorizationURL *url.URL
	params           url.Values
}

func parseOAuthAuthenticateRequestParams(values url.Values) oauthAuthenticateRequestParams {
	params := oauthAuthenticateRequestParams{
		values: values,
	}

	if v, exists := getOAuthAuthenticateRequestParam(values, "access_token"); exists {
		params.accessTokenExists = true
		params.accessToken = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "id_token"); exists {
		params.idTokenExists = true
		params.idToken = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "code"); exists {
		params.codeExists = true
		params.code = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "state"); exists {
		params.stateExists = true
		params.state = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "error"); exists {
		params.errorExists = true
		params.authError = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "error_description"); exists {
		params.errorDescriptionExists = true
		params.errorDescription = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "login_hint"); exists {
		params.loginHintExists = true
		params.loginHint = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "additional_scopes"); exists {
		params.additionalScopesExists = true
		params.additionalScopes = v
	}
	if v, exists := getOAuthAuthenticateRequestParam(values, "prompt"); exists {
		params.promptExists = true
		params.promptRaw = v
	}

	return params
}

func getOAuthAuthenticateRequestParam(values url.Values, key string) (string, bool) {
	entries, exists := values[key]
	if !exists {
		return "", false
	}
	if len(entries) < 1 {
		return "", true
	}
	return entries[0], true
}

func (p oauthAuthenticateRequestParams) isOAuthResponse() bool {
	return p.stateExists || p.errorExists || p.codeExists || p.accessTokenExists
}

func (b *IdentityProvider) prepareAuthorizationRedirectURL(reqPath string, reqParams oauthAuthenticateRequestParams, state, nonce, sessionID, requestID string) (*preparedAuthorizationRedirectURL, error) {
	authorizationURL, err := url.Parse(b.authorizationURL)
	if err != nil {
		return nil, errors.ErrIdentityProviderConfig.WithArgs("could not parse authorization url")
	}

	params := authorizationURL.Query()
	params.Set("state", state)
	if !b.disableNonce {
		params.Set("nonce", nonce)
	}
	if !b.disableScope {
		scopes := b.config.Scopes
		if reqParams.additionalScopesExists {
			scopes = append(scopes, strings.Split(reqParams.additionalScopes, " ")...)
		}
		params.Set("scope", strings.Join(scopes, " "))
	}

	if b.config.JsCallbackEnabled {
		params.Set("redirect_uri", reqPath+"/authorization-code-js-callback")
	} else {
		params.Set("redirect_uri", reqPath+"/authorization-code-callback")
	}

	if !b.disableResponseType {
		params.Set("response_type", strings.Join(b.config.ResponseType, " "))
	}
	if reqParams.loginHintExists {
		params.Set("login_hint", reqParams.loginHint)
	}

	if b.config.Driver == "google" && reqParams.promptExists {
		if prompt, ok := normalizeOAuthPromptValue(reqParams.promptRaw); ok {
			params.Set("prompt", prompt)
		} else {
			b.logger.Warn(
				"ignoring unsupported OAuth 2.0 prompt value",
				zap.String("session_id", sessionID),
				zap.String("request_id", requestID),
				zap.String("prompt", strings.TrimSpace(reqParams.promptRaw)),
			)
		}
	}

	params.Set("client_id", b.config.ClientID)

	return &preparedAuthorizationRedirectURL{
		authorizationURL: authorizationURL,
		params:           params,
	}, nil
}

func (b *IdentityProvider) finalizeAuthorizationRedirectURL(prepared *preparedAuthorizationRedirectURL, codeChallenge string) string {
	if !b.disablePKCE && codeChallenge != "" {
		prepared.params.Set("code_challenge", codeChallenge)
		prepared.params.Set("code_challenge_method", "S256")
	}

	prepared.authorizationURL.RawQuery = prepared.params.Encode()
	return prepared.authorizationURL.String()
}

var validOAuthPromptValues = []string{
	"none",
	"consent",
	"select_account",
	"consent select_account",
	"select_account consent",
}

// See https://developers.google.com/identity/protocols/oauth2/web-server for supported prompt values.
func normalizeOAuthPromptValue(prompt string) (string, bool) {
	prompt = strings.Join(strings.Fields(prompt), " ")
	if slices.Contains(validOAuthPromptValues, prompt) {
		return prompt, true
	}
	return "", false
}

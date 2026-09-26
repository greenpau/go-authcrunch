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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const maxOAuthResponseSize = 1 << 20

// Authenticate performs authentication. The embedding application must supply
// Upstream.SessionID from a protected, distinct per-browser cookie on both the
// initiating request and the callback; a shared correlation ID is insufficient.
func (b *IdentityProvider) Authenticate(r *requests.Request) error {
	// Delayed discovery publishes endpoints and issuer together. Do not read
	// partially configured metadata while its background initialization runs.
	if b.closed.Load() || (b.configured.Load() && !b.ready.Load()) {
		return errors.ErrIdentityProviderConfig.WithArgs("OAuth provider is not ready")
	}
	b.setupMu.RLock()
	defer b.setupMu.RUnlock()
	reqPath := r.Upstream.BaseURL + path.Join(r.Upstream.BasePath, r.Upstream.Method, r.Upstream.Realm)
	r.Response.Code = http.StatusBadRequest

	reqParams := parseOAuthAuthenticateRequestParams(r.Upstream.Request.URL.Query())

	if reqParams.isOAuthResponse() {
		if len(reqParams.values["state"]) != 1 || !b.state.beginCallback(reqParams.state, r.Upstream.SessionID, reqPath+"/authorization-code-callback") {
			return errors.ErrIdentityProviderOauthAuthorizationStateNotFound
		}
		defer b.state.del(reqParams.state)
		b.logger.Debug(
			"received OAuth 2.0 response",
			zap.String("session_id", r.Upstream.SessionID),
			zap.String("request_id", r.ID),
			zap.Any("params", reqParams.values),
		)
		if reqParams.errorExists {
			if reqParams.errorDescriptionExists {
				return errors.ErrIdentityProviderOauthAuthorizationFailedDetailed.WithArgs(reqParams.authError, reqParams.errorDescription)
			}
			return errors.ErrIdentityProviderOauthAuthorizationFailed.WithArgs(reqParams.authError)
		}
		switch {
		case reqParams.codeExists && reqParams.stateExists:
			// Received Authorization Code
			b.state.addCode(reqParams.state, reqParams.code)
			b.logger.Debug(
				"received OAuth 2.0 code and state from the authorization server",
				zap.String("session_id", r.Upstream.SessionID),
				zap.String("request_id", r.ID),
				zap.String("state", reqParams.state),
				zap.String("code", reqParams.code),
			)

			reqRedirectURI := reqPath + "/authorization-code-callback"
			var codeVerifier string
			if !b.disablePKCE {
				codeVerifier, _ = b.state.getVerifier(reqParams.state)
			}
			var accessToken map[string]interface{}
			var err error
			switch b.config.Driver {
			case "facebook":
				accessToken, err = b.fetchFacebookAccessToken(reqRedirectURI, reqParams.state, reqParams.code)
			default:
				accessToken, err = b.fetchAccessToken(reqRedirectURI, reqParams.state, reqParams.code, codeVerifier)
			}
			if err != nil {
				b.logger.Debug(
					"failed fetching OAuth 2.0 access token from the authorization server",
					zap.String("session_id", r.Upstream.SessionID),
					zap.String("request_id", r.ID),
					zap.Error(err),
				)
				return errors.ErrIdentityProviderOauthFetchAccessTokenFailed.WithArgs(err)
			}
			b.logger.Debug(
				"received OAuth 2.0 authorization server access token",
				zap.String("request_id", r.ID),
				zap.Any("token", accessToken),
			)

			var m map[string]interface{}

			switch b.config.Driver {
			case "github", "gitlab", "facebook", "discord", "linkedin":
				m, err = b.fetchClaims(accessToken)
				if err != nil {
					return errors.ErrIdentityProviderOauthFetchClaimsFailed.WithArgs(err)
				}
			default:
				m, err = b.validateAccessToken(r.Upstream.Request.Context(), reqParams.state, accessToken)
				if err != nil {
					return errors.ErrIdentityProviderOauthValidateAccessTokenFailed.WithArgs(err)
				}
			}

			// Fetch user info.
			if err := b.fetchUserInfo(accessToken, m); err != nil {
				b.logger.Debug(
					"failed fetching user info",
					zap.String("request_id", r.ID),
					zap.Error(err),
				)
			}

			// Fetch subsequent user info, e.g. user groups.
			if err := b.fetchUserGroups(accessToken, m); err != nil {
				b.logger.Debug(
					"failed fetching user groups",
					zap.String("request_id", r.ID),
					zap.Error(err),
				)
			}

			if b.config.IdentityTokenCookieEnabled {
				if v, exists := accessToken["id_token"]; exists {
					r.Response.IdentityTokenCookie.Enabled = true
					r.Response.IdentityTokenCookie.Name = b.config.IdentityTokenCookieName
					r.Response.IdentityTokenCookie.Payload = v.(string)
				}
			}

			r.Response.Payload = m
			r.Response.Code = http.StatusOK
			b.logger.Debug(
				"decoded claims from OAuth 2.0 authorization server access token",
				zap.String("request_id", r.ID),
				zap.Any("claims", m),
			)
			return nil
		case reqParams.idTokenExists && reqParams.accessTokenExists:
			accessToken := map[string]interface{}{
				"access_token": reqParams.accessToken,
				"id_token":     reqParams.idToken,
			}
			m, err := b.validateAccessToken(r.Upstream.Request.Context(), reqParams.state, accessToken)
			if err != nil {
				return errors.ErrIdentityProviderOauthValidateAccessTokenFailed.WithArgs(err)
			}

			r.Response.Payload = m
			r.Response.Code = http.StatusOK

			if b.config.IdentityTokenCookieEnabled {
				r.Response.IdentityTokenCookie.Enabled = true
				r.Response.IdentityTokenCookie.Name = b.config.IdentityTokenCookieName
				r.Response.IdentityTokenCookie.Payload = reqParams.idToken
			}

			b.logger.Debug(
				"decoded claims from OAuth 2.0 authorization server access token",
				zap.String("request_id", r.ID),
				zap.Any("claims", m),
			)
			return nil
		}
		return errors.ErrIdentityProviderOauthResponseProcessingFailed
	}
	if r.Upstream.SessionID == "" {
		return errors.ErrIdentityProviderConfig.WithArgs("OAuth browser session is missing")
	}
	state := uuid.New().String()
	nonceRequired := !b.disableNonce
	var nonce string
	if nonceRequired {
		nonce = util.GetRandomString(32)
	}
	preparedRedirect, err := b.prepareAuthorizationRedirectURL(reqPath, reqParams, state, nonce, nonceRequired, r.Upstream.SessionID, r.ID)
	if err != nil {
		return err
	}

	var codeVerifier string
	var codeChallenge string
	if !b.disablePKCE {
		verifierBytes := make([]byte, 32)
		if _, err := rand.Read(verifierBytes); err != nil {
			return errors.ErrIdentityProviderConfig.WithArgs("failed to generate PKCE verifier")
		}
		codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)
		h := sha256.Sum256([]byte(codeVerifier))
		codeChallenge = base64.RawURLEncoding.EncodeToString(h[:])
	}

	if err := b.state.addLogin(state, nonce, codeVerifier, r.Upstream.SessionID, reqPath+"/authorization-code-callback"); err != nil {
		return errors.ErrIdentityProviderOauthAuthorizationStateLimitReached
	}
	r.Response.Code = http.StatusFound
	r.Response.RedirectURL = b.finalizeAuthorizationRedirectURL(preparedRedirect, codeChallenge)
	b.logger.Debug(
		"redirecting to OAuth 2.0 endpoint",
		zap.String("request_id", r.ID),
		zap.String("redirect_url", r.Response.RedirectURL),
	)
	return nil
}

func (b *IdentityProvider) fetchAccessToken(redirectURI, state, code, codeVerifier string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("client_id", b.config.ClientID)
	params.Set("client_secret", b.config.ClientSecret)
	if !b.disablePassGrantType {
		params.Set("grant_type", "authorization_code")
	}
	params.Set("state", state)
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		params.Set("code_verifier", codeVerifier)
	}

	cli := &http.Client{
		Timeout: time.Second * 10,
	}

	cli, err := b.newBrowser()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", b.tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	// Adjust !!!
	if b.enableAcceptHeader {
		req.Header.Set("Accept", "application/json")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	respBody, err := readOAuthResponseBody(resp.Body, "token")
	if err != nil {
		return nil, err
	}

	b.logger.Debug(
		"OAuth 2.0 access token response received",
		zap.Any("body", respBody),
		zap.String("redirect_uri", redirectURI),
	)

	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}

	b.logger.Debug(
		"OAuth 2.0 access token response decoded",
		zap.Any("body", data),
	)

	if err := oauthAccessTokenResponseError(data); err != nil {
		return nil, err
	}

	for k := range b.requiredTokenFields {
		if _, exists := data[k]; !exists {
			return nil, errors.ErrIdentityProviderAuthorizationServerResponseFieldNotFound.WithArgs(k)
		}
	}
	return data, nil
}

func (b *IdentityProvider) fetchFacebookAccessToken(redirectURI, state, code string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("client_id", b.config.ClientID)
	params.Set("client_secret", b.config.ClientSecret)
	params.Set("code", code)
	params.Set("redirect_uri", redirectURI)

	cli := &http.Client{
		Timeout: time.Second * 10,
	}

	cli, err := b.newBrowser()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", b.tokenURL, nil)
	if err != nil {
		return nil, err
	}

	req.URL.RawQuery = params.Encode()

	// Adjust !!!
	if b.enableAcceptHeader {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	respBody, err := readOAuthResponseBody(resp.Body, "token")
	if err != nil {
		return nil, err
	}
	b.logger.Debug(
		"OAuth 2.0 access token response received",
		zap.Any("body", respBody),
	)

	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}
	if err := oauthAccessTokenResponseError(data); err != nil {
		return nil, err
	}

	for k := range b.requiredTokenFields {
		if _, exists := data[k]; !exists {
			return nil, errors.ErrIdentityProviderAuthorizationServerResponseFieldNotFound.WithArgs(k)
		}
	}
	return data, nil
}

func readOAuthResponseBody(body io.Reader, kind string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxOAuthResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxOAuthResponseSize {
		return nil, fmt.Errorf("OAuth %s response exceeds %d bytes", kind, maxOAuthResponseSize)
	}
	return data, nil
}

func readOAuthSuccessResponse(resp *http.Response, kind string) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("OAuth %s endpoint returned HTTP %d", kind, resp.StatusCode)
	}
	return readOAuthResponseBody(resp.Body, kind)
}

func rejectOAuthRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func oauthAccessTokenResponseError(data map[string]any) error {
	rawCode, exists := data["error"]
	if !exists {
		return nil
	}
	code, ok := rawCode.(string)
	if !ok || code == "" {
		return errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs("invalid error response")
	}
	if rawDescription, exists := data["error_description"]; exists {
		if description, ok := rawDescription.(string); ok {
			return errors.ErrIdentityProviderOauthGetAccessTokenFailedDetailed.WithArgs(code, description)
		}
	}
	return errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs(code)
}

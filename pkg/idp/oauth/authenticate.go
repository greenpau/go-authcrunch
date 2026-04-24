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
	"io/ioutil"
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

// Authenticate performs authentication.
func (b *IdentityProvider) Authenticate(r *requests.Request) error {
	reqPath := r.Upstream.BaseURL + path.Join(r.Upstream.BasePath, r.Upstream.Method, r.Upstream.Realm)
	r.Response.Code = http.StatusBadRequest

	reqParams := parseOAuthAuthenticateRequestParams(r.Upstream.Request.URL.Query())

	if reqParams.isOAuthResponse() {
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
			if b.state.exists(reqParams.state) {
				b.state.addCode(reqParams.state, reqParams.code)
			} else {
				return errors.ErrIdentityProviderOauthAuthorizationStateNotFound
			}
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
				m, err = b.validateAccessToken(reqParams.state, accessToken)
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
			b.state.del(reqParams.state)
			return nil
		case reqParams.idTokenExists && reqParams.accessTokenExists:
			accessToken := map[string]interface{}{
				"access_token": reqParams.accessToken,
				"id_token":     reqParams.idToken,
			}
			m, err := b.validateAccessToken(reqParams.state, accessToken)
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
	r.Response.Code = http.StatusFound
	state := uuid.New().String()
	nonce := util.GetRandomString(32)
	preparedRedirect, err := b.prepareAuthorizationRedirectURL(reqPath, reqParams, state, nonce, r.Upstream.SessionID, r.ID)
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

	r.Response.RedirectURL = b.finalizeAuthorizationRedirectURL(preparedRedirect, codeChallenge)

	if err := b.state.add(state, nonce); err != nil {
		return errors.ErrIdentityProviderOauthAuthorizationStateLimitReached
	}
	if codeVerifier != "" {
		b.state.addVerifier(state, codeVerifier)
	}
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

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
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

	if _, exists := data["error"]; exists {
		if v, exists := data["error_description"]; exists {
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailedDetailed.WithArgs(data["error"].(string), v.(string))
		}
		switch data["error"].(type) {
		case string:
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs(data["error"].(string))
		default:
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs(data["error"])
		}
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

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
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
	if _, exists := data["error"]; exists {
		if v, exists := data["error_description"]; exists {
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailedDetailed.WithArgs(data["error"].(string), v.(string))
		}
		switch data["error"].(type) {
		case string:
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs(data["error"].(string))
		default:
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs(data["error"])
		}
	}

	for k := range b.requiredTokenFields {
		if _, exists := data[k]; !exists {
			return nil, errors.ErrIdentityProviderAuthorizationServerResponseFieldNotFound.WithArgs(k)
		}
	}
	return data, nil
}

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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/qr"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/tagging"
	"github.com/greenpau/go-authcrunch/pkg/util"

	"regexp"

	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

var tokenSecretRegexPattern = regexp.MustCompile(`^[A-Za-z0-9]{10,200}$`)
var tokenIssuerRegexPattern = regexp.MustCompile(`^[A-Za-z0-9]{3,50}$`)
var tokenDescriptionRegexPattern = regexp.MustCompile(`[\W\s]{3,255}$`)
var tokenPasscodeRegexPattern = regexp.MustCompile(`^[0-9]{4,8}$`)

func handleAPIProfileResponse(w http.ResponseWriter, rr *requests.Request, code int, resp map[string]interface{}) error {
	resp["status"] = code
	rr.Response.Code = code
	respBytes, _ := json.Marshal(resp)
	w.WriteHeader(rr.Response.Code)
	w.Write(respBytes)
	return nil
}

func (p *Portal) handleAPIProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsedUser *user.User) error {
	entry := make(map[string]interface{})
	resp := make(map[string]interface{})
	resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)

	if parsedUser == nil {
		resp["message"] = "Profile API received nil user"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	usr, err := p.sessions.Get(parsedUser.Claims.ID)
	if err != nil {
		p.logger.Warn(
			"jti session not found",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("jti", parsedUser.Claims.ID),
			zap.Any("error", err),
			zap.String("source_address", addrutil.GetSourceAddress(r)),
		)
		resp["message"] = "Profile API failed to locate JTI session"
		return handleAPIProfileResponse(w, rr, http.StatusUnauthorized, resp)
	}

	if permitted := usr.HasRole("authp/admin", "authp/user"); !permitted {
		resp["message"] = "Profile API did not find valid role for the user"
		return handleAPIProfileResponse(w, rr, http.StatusForbidden, resp)
	}

	// Unpack the request and determine the type of the request.
	var reqKind = "unknown"

	// Read the request body
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		resp["message"] = "Profile API failed to parse request body"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}
	var bodyData map[string]interface{}
	if err := json.Unmarshal(body, &bodyData); err != nil {
		resp["message"] = "Profile API failed to parse request JSON body"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	if v, exists := bodyData["kind"]; exists {
		reqKind = v.(string)
	}

	switch reqKind {
	case "fetch_user_dashboard_data":
	case "delete_user_multi_factor_verifier":
	case "fetch_user_multi_factor_verifiers":
	case "fetch_user_app_multi_factor_verifier_code":
	case "test_user_app_multi_factor_verifier":
	case "add_user_app_multi_factor_verifier":
	default:
		resp["message"] = "Profile API recieved unsupported request type"
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	// Determine supported authentication methods.

	switch usr.Authenticator.Method {
	case "local":
	default:
		resp["message"] = fmt.Sprintf("%s is not supported with profile API", usr.Authenticator.Method)
		return handleAPIProfileResponse(w, rr, http.StatusNotImplemented, resp)
	}

	backend := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
	if backend == nil {
		p.logger.Warn(
			"backend not found",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("realm", usr.Authenticator.Realm),
			zap.String("jti", usr.Claims.ID),
			zap.String("source_address", addrutil.GetSourceAddress(r)),
		)
		resp["message"] = fmt.Sprintf("backend for %s realm not found", usr.Authenticator.Realm)
		return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
	}

	p.logger.Debug(
		"backend found for handling api request",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("realm", usr.Authenticator.Realm),
		zap.String("jti", usr.Claims.ID),
		zap.String("request_kind", reqKind),
		zap.String("source_address", addrutil.GetSourceAddress(r)),
	)

	// Populate username (sub) and email address (email)
	rr.User.Username = usr.Claims.Subject
	rr.User.Email = usr.Claims.Email

	switch reqKind {
	case "fetch_user_dashboard_data":
		assetCount := make(map[string]interface{})
		generalSettingsResp := make(map[string]interface{})
		if err := p.handleHTTPGeneralSettings(ctx, r, rr, usr, backend, generalSettingsResp); err != nil {
			resp["message"] = "failed to extract user metadata"
			p.logger.Debug(
				"failed to extract user metadata",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}
		if metadata, exists := generalSettingsResp["metadata"]; exists {
			entry["metadata"] = metadata
		} else {
			resp["message"] = "Profile API failed to extract user metadata"
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		// API Keys

		apiKeysResp := make(map[string]interface{})
		apiKeysResp["endpoint"] = "/list"
		if err := p.handleHTTPAPIKeysSettings(ctx, r, rr, usr, backend, apiKeysResp); err != nil {
			resp["message"] = "failed to extract user api keys"
			p.logger.Debug(
				"failed to extract user api keys",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if apikeys, exists := apiKeysResp["apikeys"]; exists {
			assetCount["api_key"] = len(apikeys.([]*identity.APIKey))
		} else {
			assetCount["api_key"] = 0
		}

		// SSH Keys

		sshKeysResp := make(map[string]interface{})
		sshKeysResp["endpoint"] = "/list"
		if err := p.handleHTTPSSHKeysSettings(ctx, r, rr, usr, backend, sshKeysResp); err != nil {
			resp["message"] = "failed to extract user ssh keys"
			p.logger.Debug(
				"failed to extract user ssh keys",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if sshkeys, exists := sshKeysResp["sshkeys"]; exists {
			assetCount["ssh_key"] = len(sshkeys.([]*identity.PublicKey))
		} else {
			assetCount["ssh_key"] = 0
		}

		// GPG Keys

		gpgKeysResp := make(map[string]interface{})
		gpgKeysResp["endpoint"] = "/list"
		if err := p.handleHTTPGPGKeysSettings(ctx, r, rr, usr, backend, gpgKeysResp); err != nil {
			resp["message"] = "failed to extract user gpg keys"
			p.logger.Debug(
				"failed to extract user gpg keys",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if gpgkeys, exists := gpgKeysResp["gpgkeys"]; exists {
			assetCount["gpg_key"] = len(gpgkeys.([]*identity.PublicKey))
		} else {
			assetCount["gpg_key"] = 0
		}

		// MFA/2FA

		mfa2faResp := make(map[string]interface{})
		mfa2faResp["endpoint"] = "/list"
		if err := p.handleHTTPMfaSettings(ctx, r, rr, usr, backend, mfa2faResp); err != nil {
			resp["message"] = "failed to extract user MFA/2FA"
			p.logger.Debug(
				"failed to extract user MFA/2FA",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if mfaTokens, exists := mfa2faResp["mfa_tokens"]; exists {
			assetCount["mfa_2fa"] = len(mfaTokens.([]*identity.MfaToken))
		} else {
			assetCount["mfa_2fa"] = 0
		}

		// User Roles

		entry["roles"] = parsedUser.Claims.Roles

		// Finalize

		entry["asset_count"] = assetCount
		entry["connected_accounts"] = []interface{}{}
		resp["entry"] = entry
		return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
	case "fetch_user_multi_factor_verifiers":
		fetchedData := make(map[string]interface{})
		fetchedData["endpoint"] = "/list"
		if err := p.handleHTTPMfaSettings(ctx, r, rr, usr, backend, fetchedData); err != nil {
			resp["message"] = "failed to extract user MFA/2FA"
			p.logger.Debug(
				"failed to extract user MFA/2FA",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}

		if mfaTokens, exists := fetchedData["mfa_tokens"]; exists {
			resp["entries"] = mfaTokens
		} else {
			resp["entries"] = []string{}
		}
		return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
	case "delete_user_multi_factor_verifier":
		fetchedData := make(map[string]interface{})
		var verifierID string
		if v, exists := bodyData["id"]; exists {
			verifierID = v.(string)
		} else {
			resp["message"] = "Profile API did not find id in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		fetchedData["endpoint"] = fmt.Sprintf("/delete/%s", verifierID)
		if err := p.handleHTTPMfaSettings(ctx, r, rr, usr, backend, fetchedData); err != nil {
			resp["message"] = "failed to delete user MFA/2FA"
			p.logger.Debug(
				"failed to delete user MFA/2FA",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Error(err),
			)
			return handleAPIProfileResponse(w, rr, http.StatusInternalServerError, resp)
		}
		resp["entry"] = verifierID
		return handleAPIProfileResponse(w, rr, http.StatusOK, resp)

	case "fetch_user_app_multi_factor_verifier_code":
		var tokenLifetime, tokenDigits int
		var tokenIssuer, tokenSecret string

		// Extract data.
		if v, exists := bodyData["period"]; exists {
			switch exp := v.(type) {
			case float64:
				tokenLifetime = int(exp)
			case int:
				tokenLifetime = exp
			case int64:
				tokenLifetime = int(exp)
			case json.Number:
				i, _ := exp.Int64()
				tokenLifetime = int(i)
			}
		} else {
			resp["message"] = "Profile API did not find period in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["digits"]; exists {
			switch exp := v.(type) {
			case float64:
				tokenDigits = int(exp)
			case int:
				tokenDigits = exp
			case int64:
				tokenDigits = int(exp)
			case json.Number:
				i, _ := exp.Int64()
				tokenDigits = int(i)
			}
		} else {
			resp["message"] = "Profile API did not find digits in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["issuer"]; exists {
			tokenIssuer = v.(string)
		} else {
			resp["message"] = "Profile API did not find issuer in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["secret"]; exists {
			tokenSecret = v.(string)
		} else {
			resp["message"] = "Profile API did not find secret in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}

		// Validate data.
		if !tokenIssuerRegexPattern.MatchString(tokenIssuer) {
			resp["message"] = "Profile API found non-compliant token issuer value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if !tokenSecretRegexPattern.MatchString(tokenSecret) {
			resp["message"] = "Profile API found non-compliant token secret value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if tokenLifetime != 15 && tokenLifetime != 30 && tokenLifetime != 60 && tokenLifetime != 90 {
			resp["message"] = "Profile API found non-compliant token lifetime value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if tokenDigits != 4 && tokenDigits != 6 && tokenDigits != 8 {
			resp["message"] = "Profile API found non-compliant token digits value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}

		code := qr.NewCode()
		code.Secret = tokenSecret
		code.Type = "totp"
		code.Period = tokenLifetime
		code.Issuer = fmt.Sprintf("AuthCrunch@%s", tokenIssuer)
		code.Label = fmt.Sprintf("%s:%s", code.Issuer, usr.Claims.Email)
		code.Digits = tokenDigits
		if err := code.Build(); err != nil {
			resp["message"] = "Profile API failed to build QR code"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		codeData := make(map[string]interface{})
		codeData["uri"] = code.Get()
		codeData["uri_encoded"] = code.GetEncoded()
		resp["entry"] = codeData
		return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
	case "test_user_app_multi_factor_verifier":
		var tokenLifetime, tokenDigits int
		var tokenSecret, tokenPasscode string

		// Extract data.
		if v, exists := bodyData["period"]; exists {
			switch exp := v.(type) {
			case float64:
				tokenLifetime = int(exp)
			case int:
				tokenLifetime = exp
			case int64:
				tokenLifetime = int(exp)
			case json.Number:
				i, _ := exp.Int64()
				tokenLifetime = int(i)
			}
		} else {
			resp["message"] = "Profile API did not find period in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["digits"]; exists {
			switch exp := v.(type) {
			case float64:
				tokenDigits = int(exp)
			case int:
				tokenDigits = exp
			case int64:
				tokenDigits = int(exp)
			case json.Number:
				i, _ := exp.Int64()
				tokenDigits = int(i)
			}
		} else {
			resp["message"] = "Profile API did not find digits in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["secret"]; exists {
			tokenSecret = v.(string)
		} else {
			resp["message"] = "Profile API did not find secret in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["passcode"]; exists {
			tokenPasscode = v.(string)
		} else {
			resp["message"] = "Profile API did not find passcode in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}

		// Validate data.
		if !tokenSecretRegexPattern.MatchString(tokenSecret) {
			resp["message"] = "Profile API found non-compliant token secret value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if !tokenPasscodeRegexPattern.MatchString(tokenPasscode) {
			resp["message"] = "Profile API found non-compliant token passcode value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if tokenLifetime != 15 && tokenLifetime != 30 && tokenLifetime != 60 && tokenLifetime != 90 {
			resp["message"] = "Profile API found non-compliant token lifetime value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if tokenDigits != 4 && tokenDigits != 6 && tokenDigits != 8 {
			resp["message"] = "Profile API found non-compliant token digits value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}

		respData := make(map[string]interface{})
		appToken := identity.MfaToken{
			ID:         util.GetRandomString(40),
			CreatedAt:  time.Now().UTC(),
			Parameters: make(map[string]string),
			Flags:      make(map[string]bool),
			Comment:    "TBD",
			Type:       "totp",
			Secret:     tokenSecret,
			Algorithm:  "sha1",
			Period:     tokenLifetime,
			Digits:     tokenDigits,
		}
		if err := appToken.ValidateCodeWithTime(tokenPasscode, time.Now().Add(-time.Second*time.Duration(appToken.Period)).UTC()); err != nil {
			respData["success"] = false
		} else {
			respData["success"] = true
		}
		resp["entry"] = respData
		return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
	case "add_user_app_multi_factor_verifier":
		var tokenTitle, tokenDescription, tokenSecret string
		var tokenLifetime, tokenDigits int
		var tokenLabels []string = []string{}
		var tokenTags []tagging.Tag = []tagging.Tag{}

		// Extract data.
		if v, exists := bodyData["period"]; exists {
			switch exp := v.(type) {
			case float64:
				tokenLifetime = int(exp)
			case int:
				tokenLifetime = exp
			case int64:
				tokenLifetime = int(exp)
			case json.Number:
				i, _ := exp.Int64()
				tokenLifetime = int(i)
			}
		} else {
			resp["message"] = "Profile API did not find period in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["digits"]; exists {
			switch exp := v.(type) {
			case float64:
				tokenDigits = int(exp)
			case int:
				tokenDigits = exp
			case int64:
				tokenDigits = int(exp)
			case json.Number:
				i, _ := exp.Int64()
				tokenDigits = int(i)
			}
		} else {
			resp["message"] = "Profile API did not find digits in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["title"]; exists {
			tokenTitle = v.(string)
		} else {
			resp["message"] = "Profile API did not find title in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["description"]; exists {
			tokenDescription = v.(string)
		} else {
			resp["message"] = "Profile API did not find description in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if v, exists := bodyData["secret"]; exists {
			tokenSecret = v.(string)
		} else {
			resp["message"] = "Profile API did not find secret in the request payload"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}

		// Validate data.
		if !tokenIssuerRegexPattern.MatchString(tokenTitle) {
			resp["message"] = "Profile API found non-compliant token title value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if !tokenDescriptionRegexPattern.MatchString(tokenDescription) && (tokenDescription != "") {
			resp["message"] = "Profile API found non-compliant token description value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if !tokenSecretRegexPattern.MatchString(tokenSecret) {
			resp["message"] = "Profile API found non-compliant token secret value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if tokenLifetime != 15 && tokenLifetime != 30 && tokenLifetime != 60 && tokenLifetime != 90 {
			resp["message"] = "Profile API found non-compliant token lifetime value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}
		if tokenDigits != 4 && tokenDigits != 6 && tokenDigits != 8 {
			resp["message"] = "Profile API found non-compliant token digits value"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}

		rr.MfaToken.SkipVerification = true
		rr.MfaToken.Comment = tokenTitle
		rr.MfaToken.Description = tokenDescription
		rr.MfaToken.Secret = tokenSecret
		rr.MfaToken.Type = "totp"
		rr.MfaToken.Period = tokenLifetime
		rr.MfaToken.Digits = tokenDigits
		rr.MfaToken.Labels = tokenLabels
		rr.MfaToken.Tags = tokenTags

		if err = backend.Request(operator.AddMfaToken, rr); err != nil {
			resp["message"] = "Profile API failed to add token identity store"
			return handleAPIProfileResponse(w, rr, http.StatusBadRequest, resp)
		}

		resp["entry"] = "Created"
		return handleAPIProfileResponse(w, rr, http.StatusOK, resp)
	}

	// Default response
	resp["message"] = fmt.Sprintf("unsupported %s request kind with profile API", reqKind)
	return handleAPIProfileResponse(w, rr, http.StatusNotImplemented, resp)
}

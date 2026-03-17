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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

func (p *Portal) handleIssueTokens(ctx context.Context, r *http.Request, rr *requests.Request, usr *user.User) (*apiauth.AuthResponse, error) {
	backend := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
	if backend == nil {
		return nil, fmt.Errorf("authentication realm not found")
	}

	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		return nil, fmt.Errorf("user lookup failed: %v", err)
	}

	m := make(map[string]interface{})

	m["sub"] = rr.User.Username
	m["email"] = rr.User.Email
	if rr.User.FullName != "" {
		m["name"] = rr.User.FullName
	}
	if len(rr.User.Roles) > 0 {
		m["roles"] = rr.User.Roles
	}

	m["jti"] = rr.Upstream.SessionID
	m["exp"] = time.Now().Add(time.Duration(p.keystore.GetTokenLifetime(nil, nil)) * time.Second).UTC().Unix()
	m["iat"] = time.Now().UTC().Unix()
	m["nbf"] = time.Now().Add(time.Duration(60) * time.Second * -1).UTC().Unix()
	m["realm"] = backend.GetRealm()
	m["origin"] = rr.Upstream.Realm
	m["iss"] = util.GetIssuerURL(r)
	m["addr"] = addrutil.GetSourceAddress(r)

	if err := p.transformUser(ctx, rr, m); err != nil {
		return nil, err
	}

	injectPortalRoles(m, p.config)

	usr, err := user.NewUser(m)
	if err != nil {
		return nil, err
	}

	if err := p.keystore.SignToken(nil, nil, usr); err != nil {
		return nil, err
	}

	usr.Authenticator.Name = backend.GetName()
	usr.Authenticator.Realm = backend.GetRealm()
	usr.Authenticator.Method = backend.GetKind()

	authResponse := &apiauth.AuthResponse{
		Authenticated:   true,
		AccessToken:     usr.Token,
		AccessTokenName: usr.TokenName,
	}

	return authResponse, nil
}

func (p *Portal) handleSandboxCheckpointVerification(_ context.Context, r *http.Request, rr *requests.Request, usr *user.User, authRequest *apiauth.AuthRequest) error {
	var prevCheckpointPassed bool

	backend := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
	if backend == nil {
		return fmt.Errorf("authentication realm not found")
	}

	for _, checkpoint := range usr.Checkpoints {
		if checkpoint.Passed {
			continue
		}
		if prevCheckpointPassed {
			usr.Authenticator.NextChallenge = checkpoint.Type
			return nil
		}

		if checkpoint.Type != authRequest.ChallengeKind {
			return fmt.Errorf("expected authentication checkpoint type %s, but got something else", checkpoint.Type)
		}

		if checkpoint.FailedAttempts >= 5 {
			return fmt.Errorf("user reached maximum number of allowed failed attempts for %s checkpoint type", checkpoint.Type)
		}

		challengeContainsOnlyNumbers := strings.IndexFunc(
			authRequest.ChallengeResponse, func(r rune) bool {
				return !unicode.IsDigit(r)
			}) == -1 && len(authRequest.ChallengeResponse) > 0

		switch {
		case checkpoint.Type == "password":
			rr.Flags.Enabled = true
			rr.User.Username = authRequest.Username
			rr.User.Password = authRequest.ChallengeResponse
			if err := backend.Request(operator.Authenticate, rr); err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				p.logger.Warn(
					"password authentication failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Int("checkpoint_id", checkpoint.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_name", checkpoint.Name),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("password authentication failed")
			}
			p.logger.Info(
				"user authentication checkpoint passed",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Int("checkpoint_id", checkpoint.ID),
				zap.String("checkpoint_name", checkpoint.Name),
				zap.String("checkpoint_type", checkpoint.Type),
			)
			checkpoint.Passed = true
			prevCheckpointPassed = true
		case checkpoint.Type == "totp" || (checkpoint.Type == "mfa" && challengeContainsOnlyNumbers):
			if err := backend.Request(operator.CheckMfaLockout, rr); err != nil {
				return fmt.Errorf("account temporarily locked due to too many failed MFA attempts")
			}
			rr.Flags.Enabled = true
			rr.User.Username = authRequest.Username
			rr.MfaToken.Passcode = authRequest.ChallengeResponse
			if err := backend.Request(operator.GetMfaTokens, rr); err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				p.logger.Warn(
					"failed fetching totp tokens",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Int("checkpoint_id", checkpoint.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_name", checkpoint.Name),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("failed fetching totp tokens")
			}

			var tokenValidated bool
			tokenBundle := rr.Response.Payload.(*identity.MfaTokenBundle)
			for _, token := range tokenBundle.Get() {
				if token.Type != "totp" {
					continue
				}
				if token.Disabled {
					continue
				}
				if err := token.ValidateCode(rr.MfaToken.Passcode); err != nil {
					continue
				}
				tokenValidated = true
				break
			}
			if !tokenValidated {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				backend.Request(operator.IncrementMfaFailedAttempts, rr)
				p.logger.Warn(
					"totp passcode authentication failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Int("checkpoint_id", checkpoint.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_name", checkpoint.Name),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("totp passcode authentication failed")
			}

			backend.Request(operator.ResetMfaFailedAttempts, rr)
			p.logger.Info(
				"user authentication checkpoint passed",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Int("checkpoint_id", checkpoint.ID),
				zap.String("checkpoint_name", checkpoint.Name),
				zap.String("checkpoint_type", checkpoint.Type),
			)
			checkpoint.Passed = true
			prevCheckpointPassed = true
		case (checkpoint.Type == "u2f" || checkpoint.Type == "mfa") && authRequest.ChallengeResponse == "webauthn":
			rr.Flags.Enabled = true
			rr.User.Username = authRequest.Username
			if err := backend.Request(operator.GetMfaTokens, rr); err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				p.logger.Warn(
					"failed fetching totp tokens",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Int("checkpoint_id", checkpoint.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_name", checkpoint.Name),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("failed fetching totp tokens")
			}

			creds := []map[string]string{}
			tokenBundle := rr.Response.Payload.(*identity.MfaTokenBundle)
			for _, token := range tokenBundle.Get() {
				if token.Type != "u2f" {
					continue
				}
				if token.Disabled {
					continue
				}
				cred := make(map[string]string)
				cred["id"] = token.Parameters["u2f_id"]
				cred["type"] = token.Parameters["u2f_type"]
				cred["transports"] = token.Parameters["u2f_transports"]
				creds = append(creds, cred)
			}

			if len(creds) == 0 {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				p.logger.Warn(
					"no u2f tokens found",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Int("checkpoint_id", checkpoint.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_name", checkpoint.Name),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("no u2f tokens found")
			}

			usr.Authenticator.TempChallenge = util.GetRandomString(64)
			webauthChallenge := make(map[string]any)
			webauthChallenge["challenge"] = usr.Authenticator.TempChallenge
			webauthChallenge["rp_name"] = "AUTHP"
			webauthChallenge["timeout"] = 60000
			webauthChallenge["user_verification"] = "discouraged"
			webauthChallenge["ext_uvm"] = false
			webauthChallenge["ext_loc"] = false
			webauthChallenge["tx_auth_simple"] = "Could you please verify yourself?"
			webauthChallenge["credentials"] = creds

			jsonChallenge, err := json.Marshal(webauthChallenge)
			if err != nil {
				return fmt.Errorf("failed to marshal webauth challenge to JSON: %v", err)
			}
			usr.Authenticator.NextChallenge = "mfa:u2f:" + base64.StdEncoding.EncodeToString(jsonChallenge)
		case checkpoint.Type == "u2f":
			if err := backend.Request(operator.CheckMfaLockout, rr); err != nil {
				return fmt.Errorf("account temporarily locked due to too many failed MFA attempts")
			}
			rr.Flags.Enabled = true
			rr.User.Username = authRequest.Username
			rr.WebAuthn.Challenge = usr.Authenticator.TempChallenge
			if err := backend.Request(operator.Authenticate, rr); err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				backend.Request(operator.IncrementMfaFailedAttempts, rr)
				p.logger.Warn(
					"u2f authentication failed",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.Int("checkpoint_id", checkpoint.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_name", checkpoint.Name),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("u2f authentication failed")
			}
			backend.Request(operator.ResetMfaFailedAttempts, rr)
			p.logger.Info(
				"user authentication checkpoint passed",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.Int("checkpoint_id", checkpoint.ID),
				zap.String("checkpoint_name", checkpoint.Name),
				zap.String("checkpoint_type", checkpoint.Type),
			)
			checkpoint.Passed = true
			prevCheckpointPassed = true
		default:
			return fmt.Errorf("authentication checkpoint type %s is unsupported", checkpoint.Type)
		}
	}

	if prevCheckpointPassed {
		// All checkpoints passed.
		rr.Response.Authenticated = true
		usr.Authorized = true
	}

	return nil
}

func (p *Portal) handleJSONLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	var authResp *apiauth.AuthResponse

	if r.Method != http.MethodPost {
		return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Authentication Required")
	}

	authRequest, err := apiauth.ParseAuthRequest(ctx, w, r)
	if err != nil {
		p.logger.Warn(
			"failed parsing authentication request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("authentication_flow", "api"),
			zap.Error(err),
		)
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	rr.Flags.Enabled = true
	if err := p.identifyUserRequest(rr, authRequest.AsStringMap()); err != nil {
		p.logger.Warn(
			"failed identifying user",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("authentication_flow", "api"),
			zap.Error(err),
		)
		return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
	}

	if authRequest.HasChallengeResponse() {
		usr, err := p.sandboxes.Get(authRequest.SandboxID)
		if err != nil {
			p.logger.Warn(
				"failed fetching user from sandbox",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("authentication_flow", "api"),
				zap.Error(err),
			)
			return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		}

		if usr.Authenticator.TempSecret != authRequest.SandboxSecret {
			p.logger.Warn(
				"user provided sandbox sandbox secret does not match",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("authentication_flow", "api"),
				zap.Error(err),
			)
			return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		}

		if err := p.handleSandboxCheckpointVerification(ctx, r, rr, usr, authRequest); err != nil {
			p.logger.Warn(
				"user sandbox checkpoint verification failed",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("authentication_flow", "api"),
				zap.String("username", rr.User.Username),
				zap.Error(err),
			)
			return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
		}

		if usr.Authorized {
			if rr.User.Username != usr.Claims.Subject || rr.User.Email != usr.Claims.Email {
				p.logger.Warn(
					"username or email mismatch between sandbox and claims",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("authentication_flow", "api"),
					zap.String("claims_username", rr.User.Username),
					zap.String("sandbox_username", usr.Claims.Subject),
					zap.String("claims_email", rr.User.Email),
					zap.String("sandbox_email", usr.Claims.Email),
				)
				return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			}

			authResp, err = p.handleIssueTokens(ctx, r, rr, usr)
			if err != nil {
				p.logger.Warn(
					"failed to issue tokens",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("authentication_flow", "api"),
					zap.String("username", rr.User.Username),
					zap.Error(err),
				)
				return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			}
			p.sandboxes.Delete(usr.Authenticator.TempSessionID)
			p.logger.Debug(
				"user was successfully authenticated",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("authentication_flow", "api"),
				zap.String("username", rr.User.Username),
			)
		} else {
			p.logger.Debug(
				"next user authentication checkpoint",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("authentication_flow", "api"),
				zap.String("username", rr.User.Username),
				zap.String("next_challenge", usr.Authenticator.NextChallenge),
			)
			usr.Authenticator.TempSecret = util.GetRandomStringFromRange(36, 48)
			authResp = &apiauth.AuthResponse{
				SandboxID:     usr.Authenticator.TempSessionID,
				SandboxSecret: usr.Authenticator.TempSecret,
				NextChallenge: usr.Authenticator.NextChallenge,
			}
		}
	} else {
		usr, err := p.createSandboxUser(ctx, w, r, rr)
		if err != nil {
			rr.Response.Code = http.StatusBadRequest
			return p.handleHTTPErrorWithLog(ctx, w, r, rr, http.StatusBadRequest, err.Error())
		}

		if err := p.sandboxes.Add(usr.Authenticator.TempSessionID, usr); err != nil {
			rr.Response.Code = http.StatusInternalServerError
			return p.handleHTTPErrorWithLog(ctx, w, r, rr, http.StatusInternalServerError, err.Error())
		}

		p.logger.Debug(
			"user initiated authentication flow",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("sandbox_id", usr.Authenticator.TempSessionID),
			zap.String("authentication_flow", "api"),
			zap.String("username", authRequest.Username),
			zap.Any("checkpoints", usr.Checkpoints),
			zap.Any("rr", rr.User),
		)

		authResp = &apiauth.AuthResponse{
			SandboxID:     usr.Authenticator.TempSessionID,
			SandboxSecret: usr.Authenticator.TempSecret,
			NextChallenge: usr.Authenticator.NextChallenge,
		}
	}

	rr.Response.Code = 200

	respBytes, _ := json.Marshal(authResp)
	w.WriteHeader(rr.Response.Code)
	w.Write(respBytes)
	return nil
}

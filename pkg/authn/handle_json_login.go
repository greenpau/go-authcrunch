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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

const tokenRefreshDiscardTimeout = 5 * time.Second

func (p *Portal) handleIssueTokens(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, proof *user.User) (_ *apiauth.AuthResponse, err error) {
	u, tokens, err := p.issueSandboxTokens(ctx, r, rr, proof)
	defer func() {
		if err == nil || tokens == nil {
			return
		}
		// Issuance has committed, but JSON completion has not delivered this
		// credential. Release its family even if a later step canceled the
		// request. Previously replaced families remain revoked.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tokenRefreshDiscardTimeout)
		defer cancel()
		if cleanupErr := p.refresh.Logout(cleanupCtx, tokens.RefreshToken, proof.RefreshTransport); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("discard undelivered refresh token: %w: %w", tokenrefresh.ErrUnavailable, cleanupErr))
		}
	}()
	if err != nil {
		return nil, err
	}
	browserReplacement := proof.RefreshTransport == tokenrefresh.CookieTransport && p.hasRefreshCookie(r)
	if proof.RefreshTransport == tokenrefresh.CookieTransport {
		// Retire the old identity before publishing any new browser credentials,
		// including when this realm does not issue a refresh family.
		if err := p.revokeRefreshOnLogin(ctx, w, r); err != nil {
			return nil, fmt.Errorf("%w: %w", tokenrefresh.ErrUnavailable, err)
		}
	}
	if err := p.finishOIDCLogin(ctx, w, r, proof); err != nil {
		return nil, err
	}
	if tokens == nil {
		if browserReplacement {
			u.Authorized = true
			if err := p.sessions.Add(u.Claims.ID, u); err != nil {
				return nil, err
			}
			w.Header().Add("Set-Cookie", p.cookie.GetAccessTokenCookie(addrutil.GetSourceHost(r), u.Token))
		}
		return &apiauth.AuthResponse{Authenticated: true, AccessToken: u.Token, AccessTokenName: p.config.TokenGrantorOptions.AccessTokenCookieName}, nil
	}
	if proof.RefreshTransport == tokenrefresh.CookieTransport {
		if err := p.sessions.Add(u.Claims.ID, u); err != nil {
			return nil, err
		}
		p.deliverRefreshCookies(w, r, tokens)
	}
	return p.refreshResponse(tokens, proof.RefreshTransport), nil
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
			// Keep the canonical identity established before acquiring the sandbox,
			// including when the caller supplied an email address or mixed case.
			rr.User.Username = usr.LoginUsername
			rr.User.Password = authRequest.ChallengeResponse
			if err := p.authenticatePassword(addrutil.GetSourceAddress(r), func() error {
				return backend.Request(operator.Authenticate, rr)
			}); err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				if err == errPasswordAttemptLimited {
					rr.Response.Code = http.StatusTooManyRequests
					return err
				}
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
			checkpoint.Method = "pwd"
			prevCheckpointPassed = true
		case checkpoint.Type == "totp" || (checkpoint.Type == "mfa" && challengeContainsOnlyNumbers):
			rr.Authentication = usr.LoginEvidence
			if err := backend.Request(operator.CheckMfaLockout, rr); err != nil {
				p.logger.Warn(
					"user locked out due to too many failed MFA attempts",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("account temporarily locked due to too many failed MFA attempts")
			}
			rr.Flags.Enabled = true
			rr.User.Username = usr.LoginUsername
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

			rr.Authentication = usr.LoginEvidence
			if err := backend.Request(operator.ConsumeMfaTOTP, rr); err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				rr.Authentication = usr.LoginEvidence
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

			rr.Authentication = usr.LoginEvidence
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
			checkpoint.Method = "otp"
			prevCheckpointPassed = true
		case (checkpoint.Type == "u2f" || checkpoint.Type == "mfa") && authRequest.ChallengeResponse == "webauthn":
			rr.Flags.Enabled = true
			rr.User.Username = usr.LoginUsername
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

			checkpoint.Type = "u2f"
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
			// Issuing an assertion challenge does not finish this checkpoint.
			// Wait for its signed response before visiting subsequent factors.
			return nil
		case checkpoint.Type == "u2f":
			rr.WebAuthn.Request = authRequest.ChallengeResponse
			rr.Authentication = usr.LoginEvidence
			if err := backend.Request(operator.CheckMfaLockout, rr); err != nil {
				p.logger.Warn(
					"user locked out due to too many failed MFA attempts",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("src_ip", addrutil.GetSourceAddress(r)),
					zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
					zap.String("checkpoint_type", checkpoint.Type),
				)
				return fmt.Errorf("account temporarily locked due to too many failed MFA attempts")
			}
			rr.Flags.Enabled = true
			rr.User.Username = usr.LoginUsername
			rr.WebAuthn.Challenge = usr.Authenticator.TempChallenge
			var err error
			rr.WebAuthn.ExpectedOrigin, err = getWebAuthnExpectedOrigin(r)
			if err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				return fmt.Errorf("failed to validate WebAuthn origin: %v", err)
			}
			rr.Authentication = usr.LoginEvidence
			if err := backend.Request(operator.Authenticate, rr); err != nil {
				rr.Response.Code = http.StatusUnauthorized
				checkpoint.FailedAttempts++
				rr.Authentication = usr.LoginEvidence
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
			checkpoint.Method = "hwk"
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

	if authRequest.APIKey != "" {
		return p.handleJSONAPIKeyLogin(ctx, w, r, authRequest)
	}
	if authRequest.RefreshTransport == "body" && (!p.refreshRealm(authRequest.Realm) || !p.config.RefreshTokens.BodyTransportEnabled) {
		return p.handleJSONError(ctx, w, http.StatusBadRequest, "Native refresh is unavailable")
	}
	if p.refreshRealm(authRequest.Realm) || p.hasRefreshCookie(r) {
		if err := p.validateRefreshLogin(r, authRequest.RefreshTransport); err != nil {
			return p.handleJSONError(ctx, w, http.StatusForbidden, "Invalid refresh transport")
		}
	}
	if authRequest.RefreshTransport == "body" {
		// Native clients receive credentials only in JSON, including during login.
		w.Header().Del("Set-Cookie")
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
		lease, err := p.sandboxes.Acquire(authRequest.SandboxID, authRequest.SandboxSecret)
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

		defer lease.Release()
		usr := lease.User
		if usr.Authenticator.Realm != authRequest.Realm || usr.LoginUsername != rr.User.Username || usr.RefreshTransport != authRequest.RefreshTransport {
			return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Invalid authentication context")
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

		completedBefore := passedCheckpointCount(usr)
		if err := p.handleSandboxCheckpointVerification(ctx, r, rr, usr, authRequest); err != nil {
			p.logger.Warn(
				"user sandbox checkpoint verification failed",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("authentication_flow", "api"),
				zap.String("username", rr.User.Username),
				zap.Error(err),
			)
			statusCode := http.StatusUnauthorized
			if err == errPasswordAttemptLimited {
				statusCode = http.StatusTooManyRequests
			}
			return p.handleJSONErrorWithLog(ctx, w, r, rr, statusCode, http.StatusText(statusCode))
		}

		if err := p.recordLoginEvidence(usr, rr, completedBefore); err != nil {
			p.sandboxes.Delete(authRequest.SandboxID)
			return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Reauthentication required")
		}

		if usr.Authorized {
			if rr.User.Username != usr.LoginUsername || rr.User.Email != usr.LoginEmail {
				p.logger.Warn(
					"backend identity changed during sandbox authentication",
					zap.String("session_id", rr.Upstream.SessionID),
					zap.String("request_id", rr.ID),
					zap.String("authentication_flow", "api"),
				)
				return p.handleJSONErrorWithLog(ctx, w, r, rr, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			}

			proof, redeemErr := lease.Redeem()
			if redeemErr != nil {
				return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Invalid completed authentication")
			}
			authResp, err = p.handleIssueTokens(ctx, w, r, rr, proof)
			if err != nil {
				if errors.Is(err, tokenrefresh.ErrDenied) {
					return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Reauthentication required")
				}
				if p.refreshRealm(proof.Authenticator.Realm) || errors.Is(err, tokenrefresh.ErrUnavailable) {
					return p.refreshError(ctx, w, err)
				}
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

		usr.RefreshTransport = authRequest.RefreshTransport
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

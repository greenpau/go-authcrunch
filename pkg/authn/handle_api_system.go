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

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/system"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func handleAPISystemError(_ context.Context, w http.ResponseWriter, _ *http.Request, rr *requests.Request) error {
	w.Header().Set("Content-Type", "application/json")
	resp := make(map[string]interface{})
	resp["error"] = http.StatusText(rr.Response.Code)
	resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	respBytes, _ := json.Marshal(resp)
	w.WriteHeader(rr.Response.Code)
	w.Write(respBytes)
	return nil
}

func handleAPISystemResponse(_ context.Context, w http.ResponseWriter, encryptedRespMsg []byte) error {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(200)
	w.Write(encryptedRespMsg)
	return nil
}

func (p *Portal) handleAPIExtractUserIdentity(ctx context.Context, rr *requests.Request, m map[string]any) error {
	switch rr.Upstream.Method {
	case "oauth2", "saml":
		return fmt.Errorf("upstream authentication method %q is not supported", rr.Upstream.Method)
	default:
		m["sub"] = rr.User.Username
		m["email"] = rr.User.Email
		if rr.User.FullName != "" {
			m["name"] = rr.User.FullName
		}
		if len(rr.User.Roles) > 0 {
			m["roles"] = rr.User.Roles
		}
	}

	m["origin"] = rr.Upstream.Realm
	m["realm"] = rr.Upstream.Realm

	if err := p.transformUser(ctx, rr, m); err != nil {
		return err
	}

	injectPortalRoles(m, p.config)

	delete(m, "frontend_links")

	return nil
}

func (p *Portal) handleAPISystem(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, _ *user.User) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return handleAPISystemError(ctx, w, r, rr)
	}

	defer r.Body.Close()

	footer, err := system.ParseEncryptedMessageFooter(string(body))
	if err != nil {
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "encrypted_message_footer_parsing"),
			zap.Error(err),
		)
		return handleAPISystemError(ctx, w, r, rr)
	}

	cryptoKey := p.keystore.GetSystemKeyByID(footer.KeyID)
	if cryptoKey == nil {
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "key_store_search"),
			zap.String("error", "no matching key found in crypto key store"),
		)
		return handleAPISystemError(ctx, w, r, rr)
	}

	secretKey, err := system.ParseKeyFromString(cryptoKey.Config.Secret)
	if err != nil {
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "key_secret_retrieval"),
			zap.Error(err),
		)
		return handleAPISystemError(ctx, w, r, rr)
	}

	encryptor, err := system.NewEncryptor(footer.KeyID, secretKey)
	if err != nil {
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "build_encryptor"),
			zap.Error(err),
		)
		return handleAPISystemError(ctx, w, r, rr)
	}

	imsg, err := encryptor.DecryptMessage(string(body))
	if err != nil {
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "decrypt_message"),
			zap.Error(err),
		)
		return handleAPISystemError(ctx, w, r, rr)
	}

	if err := imsg.Validate(); err != nil {
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "validate_message"),
			zap.Error(err),
		)
		return handleAPISystemError(ctx, w, r, rr)
	}

	switch msg := imsg.(type) {
	case *system.BasicAuthRequestMessage:
		if err := p.authenticateBasicAuthRequest(ctx, w, r, rr, msg.Realm, msg.Username, msg.Password); err != nil {
			p.logger.Warn(
				"malformed request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "system"),
				zap.String("phase", "authentication"),
				zap.Error(err),
			)
			return handleAPISystemError(ctx, w, r, rr)
		}

		userIdentity := make(map[string]any)
		userIdentity["addr"] = msg.Address
		if err := p.handleAPIExtractUserIdentity(ctx, rr, userIdentity); err != nil {
			p.logger.Warn(
				"malformed request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "system"),
				zap.String("phase", "authorize"),
				zap.Error(err),
			)
			return handleAPISystemError(ctx, w, r, rr)
		}

		respMsg := system.AuthResponseMessage{
			ID:            rr.ID,
			Kind:          system.AuthResponseKindKeyword,
			Authenticated: true,
			UserData:      userIdentity,
			Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		}

		encryptedRespMsg, err := encryptor.EncryptMessage(&respMsg)
		if err != nil {
			rr.Response.Code = http.StatusInternalServerError
			p.logger.Warn(
				"malformed request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "system"),
				zap.String("phase", "build_response"),
				zap.Error(err),
			)
			return handleAPISystemError(ctx, w, r, rr)
		}
		return handleAPISystemResponse(ctx, w, []byte(encryptedRespMsg))
	case *system.APIKeyAuthRequestMessage:
		if err := p.authenticateAPIKeyAuthRequest(ctx, w, r, rr, msg.Realm, msg.APIKey); err != nil {
			p.logger.Warn(
				"malformed request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "system"),
				zap.String("phase", "authentication"),
				zap.Error(err),
			)
			return handleAPISystemError(ctx, w, r, rr)
		}

		userIdentity := make(map[string]any)
		userIdentity["addr"] = msg.Address
		if err := p.handleAPIExtractUserIdentity(ctx, rr, userIdentity); err != nil {
			p.logger.Warn(
				"malformed request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "system"),
				zap.String("phase", "authorize"),
				zap.Error(err),
			)
			return handleAPISystemError(ctx, w, r, rr)
		}

		respMsg := system.AuthResponseMessage{
			ID:            rr.ID,
			Kind:          system.AuthResponseKindKeyword,
			Authenticated: true,
			UserData:      userIdentity,
			Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		}

		encryptedRespMsg, err := encryptor.EncryptMessage(&respMsg)
		if err != nil {
			rr.Response.Code = http.StatusInternalServerError
			p.logger.Warn(
				"malformed request",
				zap.String("session_id", rr.Upstream.SessionID),
				zap.String("request_id", rr.ID),
				zap.String("api_endpoint", "system"),
				zap.String("phase", "build_response"),
				zap.Error(err),
			)
			return handleAPISystemError(ctx, w, r, rr)
		}
		return handleAPISystemResponse(ctx, w, []byte(encryptedRespMsg))
	case nil:
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "validate_message"),
			zap.String("error", "message is nil"),
		)
		return handleAPISystemError(ctx, w, r, rr)
	default:
		rr.Response.Code = http.StatusBadRequest
		p.logger.Warn(
			"malformed request",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("api_endpoint", "system"),
			zap.String("phase", "validate_message"),
			zap.Error(fmt.Errorf("unsupported message type: %T", msg)),
		)
		return handleAPISystemError(ctx, w, r, rr)
	}
}

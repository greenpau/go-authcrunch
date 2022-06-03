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
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func (p *Portal) handleJSONWhoami(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	if usr == nil {
		return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Access denied")
	}

	// Check whether id_token is being requested.
	identityTokenEnabled := r.URL.Query().Get("id_token")
	if identityTokenEnabled != "true" || usr.Claims == nil {
		return p.handleJSONWhoamiPlain(ctx, w, usr)
	}

	// Locate the realm based on the issuer of the user's token.
	realm := extractRealmFromIssuer(usr.Claims.Issuer, "oauth2")
	if realm == "" {
		return p.handleJSONWhoamiPlain(ctx, w, usr)
	}

	// Locate the identity provider based on the realm.
	provider := p.getIdentityProviderByRealm(realm)
	if provider == nil {
		p.logger.Warn(
			"failed returning id_token",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "realm not found"),
		)
		return p.handleJSONWhoamiPlain(ctx, w, usr)
	}

	// Check whether the provider has identity token cookie configured.
	if provider.GetIdentityTokenCookieName() == "" {
		p.logger.Debug(
			"failed returning id_token",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "identity token cookie name is empty"),
		)
		return p.handleJSONWhoamiPlain(ctx, w, usr)
	}

	// Iterate over cookies to find the identity token cookie.
	cookie, err := r.Cookie(provider.GetIdentityTokenCookieName())
	if err != nil {
		p.logger.Debug(
			"failed returning id_token",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "identity token cookie not found"),
		)
		return p.handleJSONWhoamiPlain(ctx, w, usr)
	}

	respMap := make(map[string]interface{})
	for k, v := range usr.AsMap() {
		respMap[k] = v
	}
	respMap["id_token"] = cookie.Value
	respBytes, _ := json.Marshal(respMap)
	w.WriteHeader(200)
	w.Write(respBytes)
	return nil
}

func (p *Portal) handleJSONWhoamiPlain(ctx context.Context, w http.ResponseWriter, usr *user.User) error {
	respBytes, _ := json.Marshal(usr.AsMap())
	w.WriteHeader(200)
	w.Write(respBytes)
	return nil
}

func extractRealmFromIssuer(s, sp string) string {
	var ready bool
	for _, k := range strings.Split(s, "/") {
		if k == sp {
			ready = true
			continue
		}
		if ready {
			return k
		}
	}
	return ""
}

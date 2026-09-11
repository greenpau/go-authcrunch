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
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// API keys are independent credentials, using the same verification and signing
// as proxy API key authentication. They do not complete password/MFA checkpoints
// or establish evidence for a renewable session, even in a refresh-enabled realm.
func (p *Portal) handleJSONAPIKeyLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, request *apiauth.AuthRequest) error {
	// This exchange delivers credentials in JSON and does not establish cookies.
	w.Header().Del("Set-Cookie")
	proxyRequest := &authproxy.Request{Realm: request.Realm, Secret: request.APIKey, Address: addrutil.GetSourceAddress(r)}
	if err := p.APIKeyAuth(proxyRequest); err != nil {
		return p.handleJSONError(ctx, w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}
	response := apiauth.AuthResponse{
		Authenticated: true, AccessToken: proxyRequest.Response.Payload,
		AccessTokenName: p.config.TokenGrantorOptions.AccessTokenCookieName,
	}
	data, _ := json.Marshal(response)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return nil
}

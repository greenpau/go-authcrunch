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

package validator

import (
	"context"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

// parseCustomAuthHeader authorizes HTTP requests based on the presence and the
// content of HTTP Authorization or X-API-Key headers.
func (v *TokenValidator) parseCustomAuthHeader(ctx context.Context, r *http.Request, ar *requests.AuthorizationRequest) error {
	if v.basicAuthEnabled {
		if err := v.parseCustomBasicAuthHeader(ctx, r, ar); err != nil {
			return err
		}
	}
	if !ar.Token.Found && v.apiKeyAuthEnabled {
		return v.parseCustomAPIKeyAuthHeader(ctx, r, ar)
	}
	return nil
}

func (v *TokenValidator) parseCustomBasicAuthHeader(_ context.Context, r *http.Request, ar *requests.AuthorizationRequest) error {
	var tokenSecret, tokenRealm string
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil
	}
	entries := strings.Split(hdr, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if !strings.HasPrefix(entry, "Basic") {
			continue
		}
		entry = strings.TrimPrefix(entry, "Basic")
		entry = strings.TrimSpace(entry)

		ar.Token.Source = "basicauth"
		ar.Token.Name = "Basic"
		ar.Token.Found = true

		tokenSecret = entry
		tokenRealm = r.Header.Get(v.authRealmHeaderName)
		break
	}

	if ar.Token.Found {
		if tokenRealm != "" {
			// Check if the realm is registered.
			if _, exists := v.authProxyConfig.BasicAuth.Realms[tokenRealm]; !exists {
				return errors.ErrBasicAuthFailed
			}
		}

		apr := &authproxy.Request{
			Address: addrutil.GetSourceAddress(r),
			Realm:   tokenRealm,
			Secret:  tokenSecret,
		}

		if err := v.authProxy.BasicAuth(apr); err != nil {
			return err
		}

		ar.Token.Name = apr.Response.Name
		ar.Token.Payload = apr.Response.Payload
		ar.Token.Source = tokenSourceBasicAuth
	}

	return nil
}

func (v *TokenValidator) parseCustomAPIKeyAuthHeader(_ context.Context, r *http.Request, ar *requests.AuthorizationRequest) error {
	hdr := r.Header.Get(v.apiKeyHeaderName)
	if hdr == "" {
		return nil
	}
	tokenSecret := strings.TrimSpace(hdr)

	ar.Token.Source = "apikey"
	ar.Token.Name = v.apiKeyHeaderName
	ar.Token.Found = true

	tokenRealm := r.Header.Get(v.authRealmHeaderName)

	if tokenRealm != "" {
		// Check if the realm is registered.
		if _, exists := v.authProxyConfig.APIKeyAuth.Realms[tokenRealm]; !exists {
			return errors.ErrAPIKeyAuthFailed
		}
	}

	apr := &authproxy.Request{
		Address: addrutil.GetSourceAddress(r),
		Realm:   tokenRealm,
		Secret:  tokenSecret,
	}

	if err := v.authProxy.APIKeyAuth(apr); err != nil {
		return err
	}
	ar.Token.Name = apr.Response.Name
	ar.Token.Payload = apr.Response.Payload
	ar.Token.Source = tokenSourceAPIAuth
	return nil
}

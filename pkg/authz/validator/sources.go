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
	"fmt"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"

	"go.uber.org/zap"
)

const (
	tokenSourceBearerHeader = "bearer"
	tokenSourceHeader       = "header"
	tokenSourceCookie       = "cookie"
	tokenSourceQuery        = "query"
	tokenSourceAPIAuth      = "apiauth"
	tokenSourceBasicAuth    = "basicauth"
)

var (
	defaultTokenSourcePriority = map[string]int{
		tokenSourceCookie: 0,
		tokenSourceHeader: 1,
		tokenSourceQuery:  2,
	}
	defaultTokenSources []string
)

func init() {
	defaultTokenSources = make([]string, len(defaultTokenSourcePriority))
	for source, priority := range defaultTokenSourcePriority {
		defaultTokenSources[priority] = source
	}
}

func (v *TokenValidator) clearAuthSources() {
	v.clearAuthHeaders()
	v.clearAuthCookies()
	v.clearAuthQueryParams()
}

// clearAuthQueryParams clears source HTTP query parameters.
func (v *TokenValidator) clearAuthQueryParams() {
	v.authQueryParams = make(map[string]interface{})
}

// clearAuthHeaders clears source HTTP Authorization header.
func (v *TokenValidator) clearAuthHeaders() {
	v.authHeaders = make(map[string]interface{})
}

// clearAuthCookies clears source HTTP cookies.
func (v *TokenValidator) clearAuthCookies() {
	v.authCookies = make(map[string]interface{})
}

// parseQueryParams authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP query parameters.
func (v *TokenValidator) parseQueryParams(_ context.Context, r *http.Request, ar *requests.AuthorizationRequest) {
	values := r.URL.Query()
	if len(values) == 0 {
		return
	}
	for k := range v.authQueryParams {
		value := values.Get(k)
		if len(value) > 32 {
			ar.Token.Found = true
			ar.Token.Name = k
			ar.Token.Payload = value
			ar.Token.Source = tokenSourceQuery
			return
		}
	}
}

// AuthorizeAuthorizationHeader authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP Authorization header.
func (v *TokenValidator) parseAuthHeader(_ context.Context, r *http.Request, ar *requests.AuthorizationRequest) {
	hdrs := r.Header.Values("Authorization")
	if len(hdrs) == 0 {
		return
	}

	for _, hdr := range hdrs {
		for _, entry := range splitAuthorizationEntries(hdr) {
			entry = strings.TrimSpace(entry)
			fields := strings.Fields(entry)
			if v.opts.ValidateBearerHeader && len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
				// If JWT token as being passed as a bearer token
				// then, the token will not be a key-value pair.
				ar.Token.Found = true
				ar.Token.Name = tokenSourceBearerHeader
				ar.Token.Payload = fields[1]
				ar.Token.Source = tokenSourceBearerHeader
				return
			}
			kv := strings.SplitN(entry, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k := strings.TrimSpace(kv[0])
			if _, exists := v.authHeaders[k]; exists {
				ar.Token.Found = true
				ar.Token.Name = k
				ar.Token.Payload = strings.TrimSpace(kv[1])
				ar.Token.Source = tokenSourceHeader
				return
			}
		}
	}
}

func splitAuthorizationEntries(value string) []string {
	var entries []string
	start := 0
	quoted := false
	escaped := false
	for i := 0; i < len(value); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && value[i] == '\\':
			escaped = true
		case value[i] == '"':
			quoted = !quoted
		case value[i] == ',' && !quoted:
			entries = append(entries, value[start:i])
			start = i + 1
		}
	}
	return append(entries, value[start:])
}

// AuthorizeCookies authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP cookies.
func (v *TokenValidator) parseCookies(_ context.Context, r *http.Request, ar *requests.AuthorizationRequest) {
	for _, cookie := range r.Cookies() {
		if _, exists := v.authCookies[cookie.Name]; !exists {
			continue
		}
		if len(cookie.Value) < 32 {
			continue
		}
		parts := strings.Split(strings.TrimSpace(cookie.Value), " ")
		ar.Token.Found = true
		ar.Token.Name = cookie.Name
		ar.Token.Payload = strings.TrimSpace(parts[0])
		ar.Token.Source = tokenSourceCookie
		return
	}
}

// Authorize authorizes HTTP requests based on the presence and the content of
// the tokens in the requests.
func (v *TokenValidator) Authorize(ctx context.Context, r *http.Request, ar *requests.AuthorizationRequest) (usr *user.User, err error) {
	if v.closed.Load() {
		return nil, fmt.Errorf("token validator is closed")
	}
	for _, sourceName := range v.tokenSources {
		switch sourceName {
		case tokenSourceHeader:
			v.parseAuthHeader(ctx, r, ar)
		case tokenSourceCookie:
			v.parseCookies(ctx, r, ar)
		case tokenSourceQuery:
			v.parseQueryParams(ctx, r, ar)
		}
		if ar.Token.Found {
			break
		}
	}

	if !ar.Token.Found && v.authProxyConfig != nil {
		// Search for credentials (basic, api key, etc.) in HTTP headers.
		if err := v.parseCustomAuthHeader(ctx, r, ar); err != nil {
			return nil, err
		}
	}

	if !ar.Token.Found {
		return nil, errors.ErrNoTokenFound
	}

	if ar.Token.IsPlainPayload {
		usr = v.cache.Get(ar.Token.CacheKey)
		if usr == nil {
			v.logger.Debug("cache miss for plaintext credentials",
				zap.String("session_id", ar.SessionID),
				zap.String("request_id", ar.ID),
				zap.String("src_ip", addrutil.GetSourceAddress(r)),
				zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
				zap.String("credentials_source", ar.Token.Source),
			)
			usr, err = user.NewUser(ar.Token.Payload)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if ar.Token.Source == tokenSourceBasicAuth || ar.Token.Source == tokenSourceAPIAuth {
			usr = v.cache.Get(ar.Token.CacheKey)
		} else {
			usr = v.cache.Get(ar.Token.Payload)
		}
		if usr == nil {
			v.logger.Debug("cache miss for JWT credentials",
				zap.String("session_id", ar.SessionID),
				zap.String("request_id", ar.ID),
				zap.String("src_ip", addrutil.GetSourceAddress(r)),
				zap.String("src_conn_ip", addrutil.GetSourceConnAddress(r)),
				zap.String("credentials_source", ar.Token.Source),
			)
			usr, err = v.keystore.ParseToken(ar)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := v.authorizeRequest(ctx, r, usr); err != nil {
		ar.Response.User = make(map[string]interface{})
		if usr.Claims.ID != "" {
			ar.Response.User["jti"] = usr.Claims.ID
		}
		if usr.Claims.Subject != "" {
			ar.Response.User["sub"] = usr.Claims.Subject
		}
		if usr.Claims.Email != "" {
			ar.Response.User["email"] = usr.Claims.Email
		}
		if usr.Claims.Name != "" {
			ar.Response.User["name"] = usr.Claims.Name
		}
		return usr, err
	}

	usr.TokenSource = ar.Token.Source
	usr.TokenName = ar.Token.Name

	if ar.Token.IsPlainPayload || ar.Token.Source == tokenSourceBasicAuth || ar.Token.Source == tokenSourceAPIAuth {
		usr.Token = ar.Token.CacheKey
	} else {
		usr.Token = ar.Token.Payload
	}
	return usr, nil
}

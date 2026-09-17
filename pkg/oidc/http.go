// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const oidcDiscoveryPath = "/.well-known/openid-configuration"

// HandleHTTP serves a provider endpoint and reports whether it handled the request.
// It leaves unmatched requests untouched for the embedding HTTP router.
// The issuer pins the exact mount; suffix matches cannot select another issuer.
func (o *Provider) HandleHTTP(w http.ResponseWriter, r *http.Request) bool {
	endpoint, mounted := strings.CutPrefix(r.URL.Path, o.mount)
	if !mounted || (endpoint != oidcDiscoveryPath && !strings.HasPrefix(endpoint, "/oidc/")) {
		return false
	}
	// Release state and identity locks before writing to a potentially slow peer.
	response := &oidcHTTPResponse{header: make(http.Header)}
	defer o.sendResponse(w, r, response, endpoint == "/oidc/authorize" || endpoint == "/oidc/continue")
	w = response
	oidcHeaders(w)
	if !o.originOK(r) {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return true
	}
	o.mu.Lock()
	closed := o.closed
	o.mu.Unlock()
	if closed {
		oidcError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return true
	}
	if o.cors(w, r, endpoint) {
		return true
	}
	switch endpoint {
	case oidcDiscoveryPath:
		if !oidcMethod(w, r, "GET", "HEAD") {
			return true
		}
		oidcJSON(w, r, o.Discovery())
	case "/oidc/jwks":
		if !oidcMethod(w, r, "GET", "HEAD") {
			return true
		}
		oidcJSON(w, r, o.JWKS())
	case "/oidc/authorize":
		o.authorize(response, r)
	case "/oidc/continue":
		o.continueAuthorization(response, r)
	case "/oidc/token":
		o.token(w, r)
	case "/oidc/userinfo":
		o.userinfo(w, r)
	case "/oidc/revoke":
		o.revoke(w, r)
	default:
		oidcError(w, http.StatusNotFound, "invalid_request")
	}
	return true
}

func oidcHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}

func oidcMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	if slices.Contains(allowed, r.Method) {
		return true
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	oidcError(w, http.StatusMethodNotAllowed, "invalid_request")
	return false
}

func oidcJSON(w http.ResponseWriter, r *http.Request, data any) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(data)
	}
}

func oidcError(w http.ResponseWriter, status int, code string) {
	if response, ok := w.(*oidcHTTPResponse); ok {
		response.errorCode = code
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func oidcParameters(w http.ResponseWriter, r *http.Request, queryAllowed bool) (url.Values, error) {
	if len(r.URL.RawQuery) > oidcMaxRequestBytes || (!queryAllowed && (r.URL.RawQuery != "" || r.URL.ForceQuery)) {
		return nil, fmt.Errorf("invalid oidc query")
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	if r.Method == http.MethodPost {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" {
			return nil, fmt.Errorf("oidc requires form encoding")
		}
		r.Body = http.MaxBytesReader(w, r.Body, oidcMaxRequestBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		for name, values := range form {
			params[name] = append(params[name], values...)
		}
	}
	for _, values := range params {
		if len(values) != 1 {
			return nil, fmt.Errorf("duplicate oidc parameter")
		}
	}
	return params, nil
}

// Discovery returns a fresh copy of the provider metadata.
func (o *Provider) Discovery() map[string]any {
	issuer := o.config.Issuer
	claims := []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "acr", "at_hash"}
	for _, scope := range []string{"profile", "email", "address", "phone"} {
		claims = append(claims, oidcScopeClaims[scope]...)
	}
	metadata := map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + "/oidc/authorize",
		"token_endpoint":                                 issuer + "/oidc/token",
		"userinfo_endpoint":                              issuer + "/oidc/userinfo",
		"jwks_uri":                                       issuer + "/oidc/jwks",
		"revocation_endpoint":                            issuer + "/oidc/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query", "form_post"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":     []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                               []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		"claims_supported":                               claims,
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_parameter_supported":                     true,
		"request_parameter_supported":                    true,
		"request_object_signing_alg_values_supported":    []string{"none", "RS256"},
		"request_uri_parameter_supported":                false,
		"authorization_response_iss_parameter_supported": true,
	}
	if len(o.config.AuthenticationContexts) > 0 {
		values := make([]string, 0, len(o.config.AuthenticationContexts))
		for _, c := range o.config.AuthenticationContexts {
			values = append(values, c.Value)
		}
		metadata["acr_values_supported"] = values
	}
	return metadata
}

// Buffer bounded protocol responses so no network I/O occurs under state locks.
type oidcHTTPResponse struct {
	page             *Page
	errorCode        string
	formActionOrigin string
	header           http.Header
	status           int
	body             bytes.Buffer
}

func (w *oidcHTTPResponse) Header() http.Header { return w.header }
func (w *oidcHTTPResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *oidcHTTPResponse) Write(body []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.body.Write(body)
}
func (w *oidcHTTPResponse) send(dst http.ResponseWriter) {
	maps.Copy(dst.Header(), w.header)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	dst.WriteHeader(w.status)
	_, _ = dst.Write(w.body.Bytes())
}

// OIDC bearer endpoints never authenticate cookies. Public clients may call
// the token endpoint from their registered HTTPS origins, without credentials.
func (o *Provider) cors(w http.ResponseWriter, r *http.Request, endpoint string) bool {
	if endpoint != "/oidc/token" && endpoint != "/oidc/userinfo" && endpoint != "/oidc/jwks" && endpoint != oidcDiscoveryPath {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	allowed := endpoint != "/oidc/token"
	if !allowed {
		for _, client := range o.clients {
			if client.TokenEndpointAuthMethod != "none" {
				continue
			}
			for _, redirect := range client.RedirectURIs {
				uri, _ := url.Parse(redirect)
				if uri.Scheme+"://"+uri.Host == origin {
					allowed = true
				}
			}
		}
	}
	w.Header().Add("Vary", "Origin")
	if allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if r.Method != http.MethodOptions {
		return false
	}
	method := r.Header.Get("Access-Control-Request-Method")
	if !allowed || (method != "POST" && method != "GET") || (endpoint == "/oidc/token" && method != "POST") {
		oidcError(w, http.StatusForbidden, "invalid_request")
		return true
	}
	for header := range strings.SplitSeq(r.Header.Get("Access-Control-Request-Headers"), ",") {
		if header = strings.ToLower(strings.TrimSpace(header)); header != "" && header != "authorization" && header != "content-type" {
			oidcError(w, http.StatusForbidden, "invalid_request")
			return true
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
	w.WriteHeader(http.StatusNoContent)
	return true
}

// ServeHTTP implements http.Handler, returning 404 for requests outside provider routes.
func (o *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !o.HandleHTTP(w, r) {
		http.NotFound(w, r)
	}
}

// ValidateLoginRequest checks the browser origin before the host processes credentials.
// On rejection it writes a 403 response. It does not authenticate a user.
func (o *Provider) ValidateLoginRequest(w http.ResponseWriter, r *http.Request) bool {
	if o.sameOrigin(r) {
		return true
	}
	oidcHeaders(w)
	oidcError(w, http.StatusForbidden, "invalid_request")
	return false
}

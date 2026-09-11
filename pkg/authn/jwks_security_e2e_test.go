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

package authn_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

func TestE2EPortalJWKSHostileTokens(t *testing.T) {
	f := newJWKSE2EPortal(t, newJWKSE2EDatabase(t), "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, e2eRSAKey)
	admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
	_, discovery := f.request(t, "GET", e2eJWKSPath, "", 200)
	public := decodeE2EJWKS(t, discovery, 1)
	claims := jwtlib.MapClaims{"sub": "keyadmin", "roles": []string{"authp/admin"}, "exp": time.Now().Add(time.Hour).Unix()}
	none, err := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, claims).SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal("could not construct unsigned test token")
	}
	keyBytes, err := x509.MarshalPKIXPublicKey(e2eJWKPublicKey(t, public[0]))
	if err != nil {
		t.Fatal(err)
	}
	hmac, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString(keyBytes)
	if err != nil {
		t.Fatal("could not construct algorithm-confusion test token")
	}
	parts := strings.Split(member, ".")
	forgedClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(forgedClaims)
	for _, tc := range []struct{ name, token string }{
		{"unsigned admin", none},
		{"RSA public key as HMAC secret", hmac},
		{"member token with forged admin claims", strings.Join(parts, ".")},
		{"non-object claims", "eyJhbGciOiJSUzI1NiJ9.W10.AA"},
		{"missing algorithm", "e30.e30.AA"},
		{"malformed base64", "?.?.?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, denied := f.request(t, "GET", e2ePrivateKeysPath+"?format=jwk", tc.token, 401)
			assertE2ENoPrivateKeys(t, denied)
			_, after := f.request(t, "GET", e2eJWKSPath, tc.token, 200)
			if !bytes.Equal(discovery, after) {
				t.Fatal("invalid credentials affected public discovery")
			}
		})
	}

	// Even a signature from a trusted key cannot make malformed identity
	// metadata valid. Obtain the test signer through the authorized HTTP export.
	_, exported := f.request(t, "GET", e2ePrivateKeysPath, admin, 200)
	signer := parseE2EPrivateKey(t, decodeE2EPrivateKeys(t, exported, public)[0], "pkcs8", "pem")
	for _, field := range []string{"iss", "mail", "email", "sub", "name", "jti"} {
		t.Run("malformed signed "+field, func(t *testing.T) {
			for _, expired := range []bool{false, true} {
				for _, value := range []any{123, nil, []string{"invalid"}, map[string]any{"invalid": true}} {
					exp := time.Now().Add(time.Hour).Unix()
					if expired {
						exp = time.Now().Add(-time.Hour).Unix()
					}
					claims := jwtlib.MapClaims{"sub": "keyadmin", "roles": []string{"authp/admin"}, "exp": exp}
					claims[field] = value
					token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
					signed, err := token.SignedString(signer)
					if err != nil {
						t.Fatal("could not construct malformed signed test token")
					}
					_, denied := f.request(t, "GET", e2ePrivateKeysPath, signed, 401)
					assertE2ENoPrivateKeys(t, denied)
				}
			}
		})
	}
	// A rejected token cannot poison later authorization of the real admin.
	f.request(t, "GET", e2ePrivateKeysPath, admin, 200)
}

func TestE2EPortalJWKSAdversarialPaths(t *testing.T) {
	f := newJWKSE2EPortal(t, newJWKSE2EDatabase(t), "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true})
	admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
	trace := http.Header{"X-JWKS-Test-Trace-Path": {"true"}}
	for _, path := range []string{
		"/api/server/%70rivate_keys", "/api%2fserver/private_keys", "//api/server/private_keys",
		"/assets/../api/server/private_keys", "/favicon/api/server/private_keys", "/.well-known/jwks.json/api/server/private_keys",
		"/%2e%2e/xauth/api/server/private_keys",
	} {
		t.Run(path, func(t *testing.T) {
			// Paths with the complete suffix remain behind both authorization
			// checks, regardless of decoded slashes, dots, or special segments.
			for _, token := range []string{"", member} {
				_, denied := f.request(t, "GET", path+"?format=jwk", token, 403, trace)
				assertE2ENoPrivateKeys(t, denied)
			}
		})
	}
	for _, path := range []string{"/api//server/../server/private_keys", e2ePrivateKeysPath + "/extra", e2ePrivateKeysPath + "%252fextra", e2ePrivateKeysPath + ".json", "/api/unknown?path=" + e2ePrivateKeysPath} {
		for _, token := range []string{"", member, admin} {
			_, denied := f.request(t, "GET", path, token, 400, trace)
			assertE2ENoPrivateKeys(t, denied)
		}
	}
	_, expected := f.request(t, "GET", e2eJWKSPath, "", 200)
	for _, path := range []string{e2ePrivateKeysPath + e2eJWKSPath, "/api/../.well-known/jwks.json", "/%2ewell-known/%6awks.json"} {
		_, data := f.request(t, "GET", path+"?format=jwk&private=true&callback=exfiltrate", "", 200, trace)
		if !bytes.Equal(data, expected) {
			t.Fatal("public suffix returned a different key set")
		}
	}
}

func TestE2EPortalJWKSRawRequestTargets(t *testing.T) {
	f := newJWKSE2EPortal(t, newJWKSE2EDatabase(t), "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true})
	member := f.login(t, "keymember")
	for _, tc := range []struct {
		name, target string
		status       int
	}{
		{"absolute form", f.server.URL + f.base + e2ePrivateKeysPath, 403},
		{"untrusted absolute authority", "https://untrusted.example" + f.base + e2ePrivateKeysPath, 403},
		// This representation falls outside the embedding handler's mount.
		{"scheme relative", "/" + f.base + e2ePrivateKeysPath, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, token := range []string{"", member} {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", f.server.Listener.Addr().String(), f.client.Transport.(*http.Transport).TLSClientConfig)
				if err != nil {
					t.Fatal("could not connect to test portal")
				}
				t.Cleanup(func() { conn.Close() })
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				// Write the request target verbatim; http.Client normally rewrites
				// absolute-form requests into origin form before transmission.
				request := "GET " + tc.target + " HTTP/1.1\r\nHost: untrusted.example\r\nX-JWKS-Test-Trace-Path: true\r\nConnection: close\r\n"
				if token != "" {
					request += "Authorization: Bearer " + token + "\r\n"
				}
				if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
					t.Fatal("could not send raw test request")
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatal("could not read raw test response")
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				conn.Close()
				if err != nil || response.StatusCode != tc.status {
					t.Fatalf("raw request: HTTP %d, want %d; read error: %v", response.StatusCode, tc.status, err)
				}
				assertE2ENoPrivateKeys(t, body)
			}
		})
	}
}

func TestE2EPortalJWKSCredentialTransports(t *testing.T) {
	f := newJWKSE2EPortal(t, newJWKSE2EDatabase(t), "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true})
	admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
	name := cookie.NewConfig().AccessTokenCookieName
	for _, tc := range []struct {
		name, token string
		status      int
	}{
		{"admin", admin, 200}, {"member", member, 403}, {"invalid", strings.Repeat("x", 40), 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, transport := range []string{"cookie", "header", "query"} {
				t.Run(transport, func(t *testing.T) {
					path := e2ePrivateKeysPath + "?format=jwk"
					headers := http.Header{}
					switch transport {
					case "cookie":
						headers.Set("Cookie", name+"="+tc.token)
					case "header":
						headers.Set("Authorization", strings.ToLower(name)+"="+tc.token)
					case "query":
						path += "&" + strings.ToLower(name) + "=" + url.QueryEscape(tc.token)
					}
					_, body := f.request(t, "GET", path, "", tc.status, headers)
					if tc.status != 200 {
						assertE2ENoPrivateKeys(t, body)
					}
				})
			}
		})
	}
	// Untrusted forwarded headers do not confer an authenticated identity.
	_, denied := f.request(t, "GET", e2ePrivateKeysPath, "", 403, http.Header{
		"X-Forwarded-User": {"keyadmin"}, "X-Forwarded-Roles": {"authp/admin"},
		"X-Original-Url": {e2eJWKSPath}, "X-Rewrite-Url": {e2eJWKSPath},
	})
	assertE2ENoPrivateKeys(t, denied)
	headers, data := f.request(t, "GET", e2ePrivateKeysPath+"?callback=exfiltrate", admin, 200, http.Header{"Origin": {"https://untrusted.example"}})
	if headers.Get("Access-Control-Allow-Origin") != "" || headers.Get("Access-Control-Allow-Credentials") != "" || headers.Get("Content-Type") != "application/json" || headers.Get("X-Content-Type-Options") != "nosniff" || !json.Valid(data) {
		t.Fatal("private export enabled cross-origin response access or JSONP")
	}
}

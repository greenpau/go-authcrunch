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
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn"
)

func newJWKSE2EEd25519File(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("could not generate Ed25519 test key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal("could not encode Ed25519 test key")
	}
	path := filepath.Join(t.TempDir(), "ed25519.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return "crypto key sign-verify from file " + path
}

func TestE2EPortalEd25519ConfiguredRollover(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	current := strings.Replace(newJWKSE2EEd25519File(t), "crypto key ", "crypto key ed-current ", 1)
	next := strings.Replace(newJWKSE2EEd25519File(t), "crypto key ", "crypto key ed-next ", 1)
	api := &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
	original := newJWKSE2EPortal(t, db, "/xauth", api, current, next)
	oldToken := original.login(t, "keyadmin")
	_, discovery := original.request(t, "GET", e2eJWKSPath, "", 200)
	oldKeys := decodeE2EJWKS(t, discovery, 2)
	if verifyE2EJWKSToken(t, oldKeys, oldToken, "keyadmin").Header["kid"] != "ed-current" {
		t.Fatal("original portal selected the wrong signer")
	}
	original.close()

	rotated := newJWKSE2EPortal(t, db, "/xauth", api, next, strings.Replace(current, "sign-verify", "verify", 1))
	newToken := rotated.login(t, "keyadmin")
	_, discovery = rotated.request(t, "GET", e2eJWKSPath, "", 200)
	active := decodeE2EJWKS(t, discovery, 1)
	if verifyE2EJWKSToken(t, active, newToken, "keyadmin").Header["kid"] != "ed-next" {
		t.Fatal("configured rollover did not select the next signer")
	}
	verifyE2EJWKSToken(t, oldKeys, newToken, "keyadmin")
	// Retaining the old private PEM solely for verification accepts its
	// tokens without advertising or exporting it as an active signing key.
	_, exported := rotated.request(t, "GET", e2ePrivateKeysPath, oldToken, 200)
	decodeE2EPrivateKeys(t, exported, active)
	rotated.close()

	retired := newJWKSE2EPortal(t, db, "/xauth", api, next)
	// A fresh portal has no token-cache entry that could mask key removal.
	retired.request(t, "GET", e2ePrivateKeysPath, oldToken, 401)
	retired.request(t, "GET", e2ePrivateKeysPath, newToken, 200)
}

func (f *jwksE2EPortal) postCredentials(t *testing.T, path string, body any, status int) *apiauth.AuthResponse {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal("could not encode credential request")
	}
	r, err := http.NewRequestWithContext(t.Context(), "POST", f.server.URL+f.base+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal("credential request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("credential request HTTP %d, want %d", response.StatusCode, status)
	}
	if status != http.StatusOK {
		return nil
	}
	var credentials apiauth.AuthResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&credentials); err != nil {
		t.Fatal("invalid credential response")
	}
	if len(response.Cookies()) != 0 {
		t.Fatal("native credential transport set cookies")
	}
	return &credentials
}

func TestE2EPortalSigningAndRefreshCompatibility(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	imported := newJWKSE2EEd25519File(t)
	verifier := strings.Replace(imported, "sign-verify", "verify", 1)
	const secret = "synthetic-signing-compatibility-secret"
	for _, tc := range []struct {
		name, method string
		keys         []string
	}{
		{"default", "ES512", nil},
		{"existing HMAC", "HS512", []string{verifier, "crypto key shared sign-verify " + secret}},
		{"existing RSA", "RS512", []string{verifier, e2eRSAKey}},
		{"existing ECDSA", "ES256", []string{verifier, e2eECKey}},
		{"imported Ed25519", "EdDSA", []string{imported}},
		{"generated EdDSA", "EdDSA", []string{"crypto default autogenerate algorithm EdDSA"}},
		{"generated Ed25519", "Ed25519", []string{"crypto default autogenerate algorithm Ed25519"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWKSE2EPortalWithRefresh(t, db, "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, true, tc.keys...)
			begin := f.postCredentials(t, "/login", apiauth.AuthRequest{Username: "keyadmin", Realm: "local", RefreshTransport: "body"}, 200)
			login := f.postCredentials(t, "/login", apiauth.AuthRequest{Username: "keyadmin", Realm: "local", RefreshTransport: "body", SandboxID: begin.SandboxID, SandboxSecret: begin.SandboxSecret, ChallengeKind: "password", ChallengeResponse: tests.TestPwd1}, 200)
			if !login.Authenticated || login.AccessToken == "" || login.RefreshToken == "" {
				t.Fatal("password login did not issue access and refresh credentials")
			}
			refreshed := f.postCredentials(t, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, 200)
			if refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken || refreshed.SessionID != login.SessionID {
				t.Fatal("refresh did not rotate the credential in the same session")
			}
			var public []map[string]string
			if tc.method != "HS512" {
				_, data := f.request(t, "GET", e2eJWKSPath, "", 200)
				public = decodeE2EJWKS(t, data, 1)
				if public[0]["alg"] != tc.method {
					t.Fatal("published signing method changed")
				}
			} else {
				f.request(t, "GET", e2eJWKSPath, "", 404)
			}
			var ids []string
			for _, signed := range []string{login.AccessToken, refreshed.AccessToken} {
				var token *jwtlib.Token
				if public != nil {
					token = verifyE2EJWKSToken(t, public, signed, "keyadmin")
				} else {
					var err error
					token, err = jwtlib.Parse(signed, func(*jwtlib.Token) (any, error) { return []byte(secret), nil }, jwtlib.WithValidMethods([]string{tc.method}), jwtlib.WithExpirationRequired())
					if err != nil || !token.Valid {
						t.Fatal("existing HMAC signature changed")
					}
				}
				if token.Header["alg"] != tc.method {
					t.Fatal("login or refresh changed signing method")
				}
				jti, _ := token.Claims.(jwtlib.MapClaims)["jti"].(string)
				ids = append(ids, jti)
				f.request(t, "GET", "/whoami", signed, 200)
			}
			if ids[0] == "" || ids[0] == ids[1] {
				t.Fatal("refresh did not issue a new access token")
			}
			// A spent credential is rejected and revokes its descendant.
			f.postCredentials(t, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, 401)
			f.postCredentials(t, "/api/refresh_token", map[string]string{"refresh_token": refreshed.RefreshToken}, 401)
		})
	}
}

// The consumer signs directly with crypto/ed25519 so the two directions do not
// depend on the same JWT registration or header construction.
func signE2EEd25519(t *testing.T, private ed25519.PrivateKey, method string, claims jwtlib.MapClaims) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": method, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(input)))
}

func TestE2EPortalEd25519VerificationAndPersistence(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	f := newJWKSE2EPortal(t, db, "/tenant/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, "crypto default autogenerate algorithm Ed25519")
	admin := f.login(t, "keyadmin")
	member := f.login(t, "keymember")
	_, data := f.request(t, "GET", e2eJWKSPath, "", 200)
	public := decodeE2EJWKS(t, data, 1)
	verifyE2EJWKSToken(t, public, admin, "keyadmin")
	for _, token := range []string{"", member} {
		_, denied := f.request(t, "GET", e2ePrivateKeysPath, token, 403)
		assertE2ENoPrivateKeys(t, denied)
	}
	_, exported := f.request(t, "GET", e2ePrivateKeysPath, admin, 200)
	pair := decodeE2EPrivateKeys(t, exported, public)[0]
	private := parseE2EPrivateKey(t, pair, "pkcs8", "pem").(ed25519.PrivateKey)
	var privatePEM string
	if err := json.Unmarshal(pair.PrivateKey, &privatePEM); err != nil {
		t.Fatal("invalid private PEM export")
	}
	path := filepath.Join(t.TempDir(), "restored.pem")
	if err := os.WriteFile(path, []byte(privatePEM), 0600); err != nil {
		t.Fatal(err)
	}
	restored := newJWKSE2EPortal(t, db, "/xauth", nil, "crypto key sign-verify from file "+path)
	_, after := restored.request(t, "GET", e2eJWKSPath, "", 200)
	restoredPublic := decodeE2EJWKS(t, after, 1)
	// A PEM restores the material. Its imported signing default is EdDSA;
	// it carries no preference for the generated issuer's Ed25519 label.
	if public[0]["x"] != restoredPublic[0]["x"] || restoredPublic[0]["alg"] != "EdDSA" {
		t.Fatal("PEM import did not preserve key material and imported default")
	}
	restored.request(t, "GET", "/whoami", admin, 200)
	verifyE2EJWKSToken(t, restoredPublic, restored.login(t, "keyadmin"), "keyadmin")
	for _, method := range []string{"EdDSA", "Ed25519"} {
		t.Run(method, func(t *testing.T) {
			claims := jwtlib.MapClaims{"sub": "keyadmin", "roles": []string{"authp/admin"}, "exp": time.Now().Add(time.Hour).Unix()}
			signed := signE2EEd25519(t, private, method, claims)
			f.request(t, "GET", e2ePrivateKeysPath, signed, 200)
			restored.request(t, "GET", "/whoami", signed, 200)
			for _, field := range []string{"sub", "iss", "email"} {
				malformed := jwtlib.MapClaims{"sub": "keyadmin", "roles": []string{"authp/admin"}, "exp": time.Now().Add(time.Hour).Unix()}
				malformed[field] = 123
				_, denied := f.request(t, "GET", e2ePrivateKeysPath, signE2EEd25519(t, private, method, malformed), 401)
				assertE2ENoPrivateKeys(t, denied)
			}
			expired := jwtlib.MapClaims{"sub": "keyadmin", "roles": []string{"authp/admin"}, "exp": time.Now().Add(-time.Hour).Unix()}
			f.request(t, "GET", e2ePrivateKeysPath, signE2EEd25519(t, private, method, expired), 401)
			parts := strings.Split(signed, ".")
			other := "EdDSA"
			if method == other {
				other = "Ed25519"
			}
			header, _ := json.Marshal(map[string]string{"alg": other})
			altered := base64.RawURLEncoding.EncodeToString(header) + "." + parts[1] + "." + parts[2]
			f.request(t, "GET", e2ePrivateKeysPath, altered, 401)
			f.request(t, "GET", e2ePrivateKeysPath, parts[0]+"."+parts[1]+".AA", 401)
		})
	}
	confused, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "keyadmin", "roles": []string{"authp/admin"}}).SignedString([]byte(private.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal("could not build test token")
	}
	_, denied := f.request(t, "GET", e2ePrivateKeysPath, confused, 401)
	assertE2ENoPrivateKeys(t, denied)
}

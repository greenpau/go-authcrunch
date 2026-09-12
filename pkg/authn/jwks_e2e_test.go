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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const (
	e2eJWKSPath        = "/.well-known/jwks.json"
	e2ePrivateKeysPath = "/api/server/private_keys"
	e2eRSAKey          = "crypto key rsa-current sign-verify from file ../../testdata/rskeys/test_2_pri.pem"
	e2eNextRSAKey      = "crypto key rsa-next sign-verify from file ../../testdata/rskeys/test_1_pri.pem"
	e2eECKey           = "crypto key ec-current sign-verify from file ../../testdata/ecdsakeys/test_2_pri.pem"
)

// These tests are external consumers: all discovery, login, and export requests
// cross a real TLS listener. Only configuration and database provisioning use
// library APIs. No test injects authenticated users or accesses portal internals.
type jwksE2EPortal struct {
	server *httptest.Server
	client *http.Client
	base   string
	logs   *observer.ObservedLogs
	close  func()
}

func newJWKSE2EDatabase(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"keyadmin", "keymember"} {
		role := "authp/user"
		if username == "keyadmin" {
			role = "authp/admin"
		}
		if err := db.AddUser(&requests.Request{User: requests.User{
			Username: username, Email: username + "@example.test", Password: tests.TestPwd1, Roles: []string{role},
		}}); err != nil {
			t.Fatal("could not provision E2E identity")
		}
	}
	return path
}

func newJWKSE2ECurveFile(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal("could not generate E2E signing key")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal("could not encode E2E signing key")
	}
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return "crypto key curve-signing sign-verify from file " + path
}

func newJWKSE2EPortal(t *testing.T, dbPath, base string, api *authn.APIConfig, directives ...string) *jwksE2EPortal {
	t.Helper()
	return newJWKSE2EPortalWithRefresh(t, dbPath, base, api, false, directives...)
}

func newJWKSE2EPortalWithRefresh(t *testing.T, dbPath, base string, api *authn.APIConfig, refresh bool, directives ...string) *jwksE2EPortal {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{
		Name: "jwks-local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	// Isolate generated keys from other portal fixtures, including shuffled runs.
	keys := append([]string{"crypto default autogenerate tag " + t.Name()}, directives...)
	config := &authn.PortalConfig{Name: "jwks-e2e", IdentityStores: []string{"jwks-local"}, API: api, RawCryptoKeyStoreConfig: keys, CookieConfig: cookie.NewConfig()}
	if refresh {
		config.RefreshTokens = &authn.RefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://" + server.Listener.Addr().String(), BasePath: base, BodyTransportEnabled: true}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded authn.PortalConfig
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	portal, err := authn.NewPortal(authn.PortalParameters{Config: &decoded, Logger: logger, IdentityStores: []ids.IdentityStore{store}})
	if err != nil {
		t.Fatal("could not construct E2E portal")
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-JWKS-Test-Trace-Path") == "true" {
			// Only path tests opt in: credential-transport queries must not be logged.
			t.Logf("portal request: Path=%q RawPath=%q RequestURI=%q", r.URL.Path, r.URL.RawPath, r.RequestURI)
		}
		// The embedding HTTP server owns mount selection. Preserve the path that
		// the portal receives, just as a mounted production handler does.
		if base != "" && !strings.HasPrefix(r.URL.Path, base+"/") {
			http.NotFound(w, r)
			return
		}
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("E2E portal handler failed")
		}
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	f := &jwksE2EPortal{server: server, client: client, base: base, logs: logs}
	f.close = func() { server.Close(); portal.Close() }
	t.Cleanup(f.close)
	return f
}

func (f *jwksE2EPortal) login(t *testing.T, username string) string {
	t.Helper()
	client, err := authclient.NewClient(&authclient.Config{
		BaseURL: f.server.URL + f.base, Realm: "local", Username: username, Password: tests.TestPwd1,
	}, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err != nil || credentials == nil || credentials.AccessToken == "" {
		t.Fatal("real password login did not issue credentials")
	}
	return credentials.AccessToken
}

func (f *jwksE2EPortal) request(t *testing.T, method, path, token string, status int, headers ...http.Header) (http.Header, []byte) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+f.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Accept", "application/json")
	for _, extra := range headers {
		for name, values := range extra {
			for _, value := range values {
				r.Header.Add(name, value)
			}
		}
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal("E2E HTTP request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal("could not read E2E response")
	}
	if resp.StatusCode != status {
		// Query parameters may contain credentials in transport tests.
		t.Fatalf("%s %s: HTTP %d, want %d", method, r.URL.EscapedPath(), resp.StatusCode, status)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Location") != "" {
		t.Fatal("endpoint allowed caching or redirected")
	}
	return resp.Header, body
}

func decodeE2EJWKS(t *testing.T, data []byte, count int) []map[string]string {
	t.Helper()
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != count {
		t.Fatal("JWKS did not contain the expected keys array")
	}
	for _, key := range set.Keys {
		for field := range key {
			switch field {
			case "kty", "kid", "alg", "use", "n", "e", "crv", "x", "y":
			default:
				t.Fatal("public JWKS contains an unexpected field")
			}
		}
		if key["use"] != "sig" || key["alg"] == "" {
			t.Fatal("JWKS lacks signing metadata")
		}
	}
	return set.Keys
}

func e2eJWKInteger(t *testing.T, value string) *big.Int {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(b) == 0 {
		t.Fatal("invalid JWK integer")
	}
	return new(big.Int).SetBytes(b)
}

func e2eJWKPublicKey(t *testing.T, key map[string]string) crypto.PublicKey {
	t.Helper()
	switch key["kty"] {
	case "RSA":
		return &rsa.PublicKey{N: e2eJWKInteger(t, key["n"]), E: int(e2eJWKInteger(t, key["e"]).Int64())}
	case "EC":
		curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
		curve := curves[key["crv"]]
		x, y := e2eJWKInteger(t, key["x"]), e2eJWKInteger(t, key["y"])
		if curve == nil || !curve.IsOnCurve(x, y) {
			t.Fatal("invalid JWK public point")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	case "OKP":
		public, err := base64.RawURLEncoding.DecodeString(key["x"])
		if err != nil || key["crv"] != "Ed25519" || len(public) != ed25519.PublicKeySize || key["y"] != "" {
			t.Fatal("invalid Ed25519 public JWK")
		}
		return ed25519.PublicKey(public)
	default:
		t.Fatal("unsupported public JWK")
		return nil
	}
}

func verifyE2EJWKSToken(t *testing.T, keys []map[string]string, signed, subject string) *jwtlib.Token {
	t.Helper()
	methods := make([]string, 0, len(keys))
	for _, key := range keys {
		methods = append(methods, key["alg"])
	}
	token, err := jwtlib.Parse(signed, func(token *jwtlib.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		for _, key := range keys {
			if kid == key["kid"] && token.Method.Alg() == key["alg"] {
				return e2eJWKPublicKey(t, key), nil
			}
		}
		return nil, fmt.Errorf("no matching published signing key")
	}, jwtlib.WithValidMethods(methods), jwtlib.WithExpirationRequired())
	if err != nil || token == nil || !token.Valid {
		t.Fatal("independent JWKS verification failed")
	}
	if token.Method.Alg() == "EdDSA" || token.Method.Alg() == "Ed25519" {
		parts := strings.Split(signed, ".")
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		valid := false
		for _, key := range keys {
			if key["kty"] == "OKP" {
				valid = valid || ed25519.Verify(e2eJWKPublicKey(t, key).(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), signature)
			}
		}
		if err != nil || len(signature) != ed25519.SignatureSize || !valid {
			t.Fatal("standard-library Ed25519 verification failed")
		}
	}
	if sub, err := token.Claims.GetSubject(); err != nil || sub != subject {
		t.Fatal("verified token has the wrong subject")
	}
	return token
}

type e2ePrivateKeyPair struct {
	PublicKey  map[string]string `json:"public_key"`
	PrivateKey json.RawMessage   `json:"private_key"`
}

func decodeE2EPrivateKeys(t *testing.T, data []byte, public []map[string]string) []e2ePrivateKeyPair {
	t.Helper()
	var set struct {
		Keys []e2ePrivateKeyPair `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != len(public) {
		t.Fatal("private export did not contain the expected keys array")
	}
	for i, pair := range set.Keys {
		if !reflect.DeepEqual(pair.PublicKey, public[i]) {
			t.Fatal("exported private key is paired with the wrong public JWK")
		}
	}
	return set.Keys
}

func parseE2EPrivateKey(t *testing.T, pair e2ePrivateKeyPair, format, encoding string) crypto.Signer {
	t.Helper()
	var secret any
	var err error
	if format == "jwk" {
		var key map[string]string
		if err := json.Unmarshal(pair.PrivateKey, &key); err != nil {
			t.Fatal("private JWK is not an object")
		}
		for field, value := range pair.PublicKey {
			if key[field] != value {
				t.Fatal("private JWK public parameters differ from discovery")
			}
		}
		switch public := e2eJWKPublicKey(t, key).(type) {
		case *rsa.PublicKey:
			private := &rsa.PrivateKey{PublicKey: *public, D: e2eJWKInteger(t, key["d"]), Primes: []*big.Int{e2eJWKInteger(t, key["p"]), e2eJWKInteger(t, key["q"])}}
			if err := private.Validate(); err != nil {
				t.Fatal("invalid RSA private JWK")
			}
			private.Precompute()
			if private.Precomputed.Dp.Cmp(e2eJWKInteger(t, key["dp"])) != 0 || private.Precomputed.Dq.Cmp(e2eJWKInteger(t, key["dq"])) != 0 || private.Precomputed.Qinv.Cmp(e2eJWKInteger(t, key["qi"])) != 0 {
				t.Fatal("invalid RSA private JWK CRT parameters")
			}
			secret = private
		case *ecdsa.PublicKey:
			d, err := base64.RawURLEncoding.DecodeString(key["d"])
			if err != nil || len(d) != (public.Curve.Params().N.BitLen()+7)/8 {
				t.Fatal("private EC scalar has incorrect padding")
			}
			secret = &ecdsa.PrivateKey{PublicKey: *public, D: new(big.Int).SetBytes(d)}
		case ed25519.PublicKey:
			seed, err := base64.RawURLEncoding.DecodeString(key["d"])
			if err != nil || len(seed) != ed25519.SeedSize {
				t.Fatal("private Ed25519 JWK must encode a 32-byte seed")
			}
			secret = ed25519.NewKeyFromSeed(seed)
		}
	} else {
		var value string
		if err := json.Unmarshal(pair.PrivateKey, &value); err != nil {
			t.Fatal("PEM/DER private key is not a JSON string")
		}
		var der []byte
		if encoding == "der" {
			der, err = base64.StdEncoding.DecodeString(value)
			if err != nil {
				t.Fatal("DER key is not standard base64")
			}
		} else {
			block, rest := pem.Decode([]byte(value))
			labels := map[string]string{"pkcs8": "PRIVATE KEY", "pkcs1": "RSA PRIVATE KEY", "sec1": "EC PRIVATE KEY"}
			if block == nil || len(rest) != 0 || block.Type != labels[format] {
				t.Fatal("wrong private PEM format")
			}
			der = block.Bytes
		}
		switch format {
		case "pkcs8":
			secret, err = x509.ParsePKCS8PrivateKey(der)
		case "pkcs1":
			secret, err = x509.ParsePKCS1PrivateKey(der)
		case "sec1":
			secret, err = x509.ParseECPrivateKey(der)
		}
		if err != nil {
			t.Fatal("exported private key cannot be parsed")
		}
	}
	signer, ok := secret.(crypto.Signer)
	if !ok {
		t.Fatal("exported key is not a signer")
	}
	want, err := x509.MarshalPKIXPublicKey(e2eJWKPublicKey(t, pair.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	got, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(want, got) {
		t.Fatal("private key does not match its public JWK")
	}
	return signer
}

func TestE2EPortalJWKSFormats(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, tc := range []struct {
		name, base  string
		keys        []string
		count       int
		kind, curve string
	}{
		{"autogenerated at root", "", nil, 1, "EC", "P-521"},
		{"RSA at custom mount", "/xauth", []string{e2eRSAKey}, 1, "RSA", ""},
		{"EC at nested mount", "/tenant/xauth", []string{e2eECKey}, 1, "EC", ""},
		{"EdDSA", "/xauth", []string{"crypto default autogenerate algorithm EdDSA"}, 1, "OKP", "Ed25519"},
		{"Ed25519", "/tenant/xauth", []string{"crypto default autogenerate algorithm Ed25519"}, 1, "OKP", "Ed25519"},
		{"Ed25519 PEM", "/xauth", []string{newJWKSE2EEd25519File(t)}, 1, "OKP", "Ed25519"},
		{"mixed RSA EC Ed25519", "/xauth", []string{e2eRSAKey, e2eECKey, newJWKSE2EEd25519File(t)}, 3, "RSA", ""},
		{"P256", "/xauth", []string{newJWKSE2ECurveFile(t, elliptic.P256())}, 1, "EC", "P-256"},
		{"P384", "/xauth", []string{newJWKSE2ECurveFile(t, elliptic.P384())}, 1, "EC", "P-384"},
		{"multiple RSA", "/xauth", []string{e2eRSAKey, e2eNextRSAKey}, 2, "RSA", ""},
		{"mixed RSA and EC", "/tenant/xauth", []string{e2eRSAKey, e2eECKey}, 2, "RSA", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWKSE2EPortal(t, db, tc.base, &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, tc.keys...)
			headers, body := f.request(t, "GET", e2eJWKSPath, "", 200)
			if headers.Get("Content-Type") != "application/jwk-set+json" || len(headers.Values("Set-Cookie")) != 0 || headers.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("public discovery changed sessions or response headers")
			}
			public := decodeE2EJWKS(t, body, tc.count)
			if public[0]["kty"] != tc.kind {
				t.Fatal("portal did not use its configured signing key type")
			}
			if tc.curve != "" && public[0]["crv"] != tc.curve {
				t.Fatal("portal did not publish the expected EC curve")
			}
			admin := f.login(t, "keyadmin")
			verifyE2EJWKSToken(t, public, admin, "keyadmin")
			head, headBody := f.request(t, "HEAD", e2eJWKSPath, "invalid", 200)
			if len(headBody) != 0 || head.Get("Content-Length") != headers.Get("Content-Length") || len(head.Values("Set-Cookie")) != 0 {
				t.Fatal("HEAD does not describe public GET")
			}
			formats := []string{"pkcs8", "jwk"}
			mixed := false
			for _, key := range public {
				mixed = mixed || key["kty"] != tc.kind
			}
			if !mixed {
				if public[0]["kty"] == "RSA" {
					formats = append(formats, "pkcs1")
				} else if public[0]["kty"] == "EC" {
					formats = append(formats, "sec1")
				}
			}
			for _, format := range formats {
				encodings := []string{"pem", "der"}
				if format == "jwk" {
					encodings = []string{"json"}
				}
				for _, encoding := range encodings {
					t.Run(format+"/"+encoding, func(t *testing.T) {
						query := "?format=" + format + "&encoding=" + encoding
						headers, exported := f.request(t, "GET", e2ePrivateKeysPath+query, admin, 200)
						if headers.Get("Content-Type") != "application/json" || headers.Get("X-Content-Type-Options") != "nosniff" {
							t.Fatal("incorrect private export headers")
						}
						for _, pair := range decodeE2EPrivateKeys(t, exported, public) {
							signer := parseE2EPrivateKey(t, pair, format, encoding)
							token := jwtlib.NewWithClaims(jwtlib.GetSigningMethod(pair.PublicKey["alg"]), jwtlib.MapClaims{"sub": "export-consumer", "exp": time.Now().Add(time.Hour).Unix()})
							if pair.PublicKey["kid"] != "" {
								token.Header["kid"] = pair.PublicKey["kid"]
							}
							signed, err := token.SignedString(signer)
							if err != nil {
								t.Fatal("consumer could not sign with exported key")
							}
							verifyE2EJWKSToken(t, public, signed, "export-consumer")
							assertE2EPrivateKeyNotLogged(t, f.logs, pair, format, encoding)
						}
						// Private-format queries cannot change the public endpoint,
						// even with an invalid Authorization header.
						_, after := f.request(t, "GET", e2eJWKSPath+query, "invalid", 200)
						if !bytes.Equal(body, after) {
							t.Fatal("private export or selectors changed public discovery")
						}
					})
				}
			}
			if mixed || tc.kind == "OKP" {
				for _, format := range []string{"pkcs1", "sec1"} {
					_, denied := f.request(t, "GET", e2ePrivateKeysPath+"?format="+format, admin, 400)
					assertE2ENoPrivateKeys(t, denied)
				}
			}
		})
	}
}

func assertE2EPrivateKeyNotLogged(t *testing.T, logs *observer.ObservedLogs, pair e2ePrivateKeyPair, format, encoding string) {
	t.Helper()
	var marker string
	if format == "jwk" {
		var key map[string]string
		if err := json.Unmarshal(pair.PrivateKey, &key); err != nil {
			t.Fatal("invalid private JWK")
		}
		marker = key["d"]
	} else {
		if err := json.Unmarshal(pair.PrivateKey, &marker); err != nil {
			t.Fatal("invalid private key string")
		}
		if encoding == "pem" {
			lines := strings.Split(marker, "\n")
			if len(lines) < 3 {
				t.Fatal("invalid private PEM")
			}
			marker = lines[1]
		}
	}
	recorded, err := json.Marshal(logs.All())
	if err != nil || marker == "" || bytes.Contains(recorded, []byte(marker)) {
		t.Fatal("private key material was logged")
	}
}

func assertE2ENoPrivateKeys(t *testing.T, data []byte) {
	t.Helper()
	for _, marker := range []string{`"keys":`, `"private_key":`, `"d":`, "PRIVATE KEY"} {
		if bytes.Contains(data, []byte(marker)) {
			t.Fatal("denied response disclosed key material")
		}
	}
}

func TestE2EPortalJWKSAuthorization(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, tc := range []struct {
		name string
		api  *authn.APIConfig
	}{
		{"omitted", nil},
		{"admin only", &authn.APIConfig{AdminEnabled: true}},
		{"export only", &authn.APIConfig{AdminFetchPrivateKeysEnabled: true}},
		{"enabled", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWKSE2EPortal(t, db, "/xauth", tc.api)
			admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
			_, public := f.request(t, "GET", e2eJWKSPath, "", 200)
			decodeE2EJWKS(t, public, 1)
			for _, query := range []string{"", "?format=jwk", "?format=pkcs8&encoding=der", "?admin_fetch_private_keys_enabled=true"} {
				status := 404
				if tc.name == "enabled" {
					status = 200
				}
				_, body := f.request(t, "GET", e2ePrivateKeysPath+query, admin, status)
				if status != 200 {
					assertE2ENoPrivateKeys(t, body)
				}
				for _, token := range []string{"", member} {
					deniedStatus := 404
					if tc.name == "enabled" {
						deniedStatus = 403
					}
					_, denied := f.request(t, "GET", e2ePrivateKeysPath+query, token, deniedStatus)
					assertE2ENoPrivateKeys(t, denied)
				}
			}
			if tc.name != "enabled" {
				return
			}
			parts := strings.Split(admin, ".")
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil || len(signature) == 0 {
				t.Fatal("invalid login token")
			}
			signature[0] ^= 1
			parts[2] = base64.RawURLEncoding.EncodeToString(signature)
			for _, token := range []string{"invalid", strings.Join(parts, ".")} {
				_, denied := f.request(t, "GET", e2ePrivateKeysPath+"?format=jwk", token, 401)
				assertE2ENoPrivateKeys(t, denied)
			}
			for _, method := range []string{"HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
				headers, denied := f.request(t, method, e2ePrivateKeysPath, admin, 405)
				if headers.Get("Allow") != "GET" {
					t.Fatal("private export did not advertise GET")
				}
				assertE2ENoPrivateKeys(t, denied)
			}
			for _, query := range []string{"?format=xml", "?format=", "?encoding=raw", "?encoding=", "?format=jwk&encoding=pem", "?format=jwk&format=pkcs8", "?%66ormat=jwk&format=pkcs8", "?encoding=pem&encoding=der", "?format=%ZZ", "?format=pkcs8;encoding=der"} {
				_, denied := f.request(t, "GET", e2ePrivateKeysPath+query, admin, 400)
				assertE2ENoPrivateKeys(t, denied)
			}
			for _, path := range []string{e2ePrivateKeysPath + "/", e2ePrivateKeysPath + ".json", e2ePrivateKeysPath + "%2fextra", "/api/server/unknown?path=" + e2ePrivateKeysPath} {
				_, denied := f.request(t, "GET", path, admin, 400)
				assertE2ENoPrivateKeys(t, denied)
			}
		})
	}
}

func TestE2EPortalJWKSSymmetricIssuer(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, laterRSA := range []bool{false, true} {
		t.Run(fmt.Sprintf("later_RSA_%t", laterRSA), func(t *testing.T) {
			keys := []string{"crypto key shared sign-verify synthetic-e2e-hmac-secret"}
			if laterRSA {
				keys = append(keys, e2eRSAKey)
			}
			f := newJWKSE2EPortal(t, db, "/tenant/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, keys...)
			admin := f.login(t, "keyadmin")
			f.request(t, "GET", "/whoami", admin, 200)
			for _, path := range []string{e2eJWKSPath, e2ePrivateKeysPath, e2ePrivateKeysPath + "?format=jwk"} {
				_, denied := f.request(t, "GET", path, admin, 404)
				assertE2ENoPrivateKeys(t, denied)
			}
		})
	}
}

func TestE2EPortalJWKSKeyPersistence(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, tc := range []struct {
		name, format string
		keys         []string
	}{
		{"autogenerated PKCS8", "pkcs8", nil},
		{"EdDSA PKCS8", "pkcs8", []string{"crypto default autogenerate algorithm EdDSA"}},
		{"RSA PKCS1", "pkcs1", []string{e2eRSAKey}},
		{"EC SEC1", "sec1", []string{e2eECKey}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := newJWKSE2EPortal(t, db, "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, tc.keys...)
			admin := original.login(t, "keyadmin")
			_, discovery := original.request(t, "GET", e2eJWKSPath, "", 200)
			public := decodeE2EJWKS(t, discovery, 1)
			_, exported := original.request(t, "GET", e2ePrivateKeysPath+"?format="+tc.format, admin, 200)
			pair := decodeE2EPrivateKeys(t, exported, public)[0]
			var privatePEM string
			if err := json.Unmarshal(pair.PrivateKey, &privatePEM); err != nil {
				t.Fatal("exported PEM is not a JSON string")
			}
			path := filepath.Join(t.TempDir(), "signing.pem")
			if err := os.WriteFile(path, []byte(privatePEM), 0600); err != nil {
				t.Fatal(err)
			}
			original.close()
			directive := "crypto key "
			if public[0]["kid"] != "" {
				directive += public[0]["kid"] + " "
			}
			directive += "sign-verify from file " + path
			restored := newJWKSE2EPortal(t, db, "/xauth", nil, directive)
			_, after := restored.request(t, "GET", e2eJWKSPath, "", 200)
			if !bytes.Equal(discovery, after) {
				t.Fatal("saved export did not restore the original public key")
			}
			// The restored portal validates a token issued before shutdown and
			// issues new tokens verifiable using the original published key.
			restored.request(t, "GET", "/whoami", admin, 200)
			verifyE2EJWKSToken(t, public, restored.login(t, "keyadmin"), "keyadmin")
			restored.request(t, "GET", e2ePrivateKeysPath, admin, 404)
		})
	}
}

func TestE2EPortalJWKSConfiguredRollover(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	original := newJWKSE2EPortal(t, db, "/xauth", nil, e2eRSAKey, e2eNextRSAKey)
	oldToken := original.login(t, "keyadmin")
	_, before := original.request(t, "GET", e2eJWKSPath, "", 200)
	oldKeys := decodeE2EJWKS(t, before, 2)
	if verifyE2EJWKSToken(t, oldKeys, oldToken, "keyadmin").Header["kid"] != "rsa-current" {
		t.Fatal("original portal selected the wrong signer")
	}
	original.close()
	// This is explicit configuration replacement, not automatic key rotation.
	rotated := newJWKSE2EPortal(t, db, "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, e2eNextRSAKey, e2eRSAKey)
	newToken := rotated.login(t, "keyadmin")
	_, after := rotated.request(t, "GET", e2eJWKSPath, "", 200)
	keys := decodeE2EJWKS(t, after, 2)
	if verifyE2EJWKSToken(t, keys, newToken, "keyadmin").Header["kid"] != "rsa-next" {
		t.Fatal("configured rollover did not change the active signer")
	}
	verifyE2EJWKSToken(t, keys, oldToken, "keyadmin")
	verifyE2EJWKSToken(t, oldKeys, newToken, "keyadmin")
	rotated.request(t, "GET", "/whoami", oldToken, 200)
	_, exported := rotated.request(t, "GET", e2ePrivateKeysPath, newToken, 200)
	for _, pair := range decodeE2EPrivateKeys(t, exported, keys) {
		parseE2EPrivateKey(t, pair, "pkcs8", "pem")
	}
}

func TestE2EPortalJWKSConcurrent(t *testing.T) {
	db := newJWKSE2EDatabase(t)
	for _, tc := range []struct {
		name string
		keys []string
	}{
		{"RSA and EC", []string{e2eRSAKey, e2eECKey}},
		{"EdDSA and RSA", []string{newJWKSE2EEd25519File(t), e2eRSAKey}},
		{"Ed25519", []string{"crypto default autogenerate algorithm Ed25519"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJWKSE2EPortal(t, db, "/xauth", &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, tc.keys...)
			admin := f.login(t, "keyadmin")
			_, baseline := f.request(t, "GET", e2eJWKSPath, "", 200)
			public := decodeE2EJWKS(t, baseline, len(tc.keys))
			for i := range 9 {
				t.Run(fmt.Sprintf("client_%d", i), func(t *testing.T) {
					t.Parallel()
					switch i % 3 {
					case 0:
						verifyE2EJWKSToken(t, public, f.login(t, "keyadmin"), "keyadmin")
					case 1:
						for range 8 {
							_, body := f.request(t, "GET", e2eJWKSPath, "", 200)
							if !bytes.Equal(body, baseline) {
								t.Fatal("concurrent discovery changed public keys")
							}
						}
					case 2:
						for range 8 {
							_, body := f.request(t, "GET", e2ePrivateKeysPath+"?format=jwk", admin, 200)
							for _, pair := range decodeE2EPrivateKeys(t, body, public) {
								parseE2EPrivateKey(t, pair, "jwk", "json")
							}
						}
					}
				})
			}
		})
	}
}

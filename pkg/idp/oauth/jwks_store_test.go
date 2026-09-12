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

package oauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// An embedded method must not be trusted just because it has a familiar name.
type oauthDisguisedMethod struct{ jwtlib.SigningMethod }

func TestOAuthSigningMethods(t *testing.T) {
	if isOAuthSigningMethod(nil) {
		t.Fatal("nil token accepted")
	}
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519"} {
		t.Run(alg, func(t *testing.T) {
			method := jwtlib.GetSigningMethod(alg)
			if !isOAuthSigningMethod(jwtlib.New(method)) {
				t.Fatal("supported method rejected")
			}
			for _, bad := range []jwtlib.SigningMethod{nil, oauthDisguisedMethod{method}, jwtlib.SigningMethodHS256, (*jwtlib.SigningMethodRSA)(nil), (*jwtlib.SigningMethodRSAPSS)(nil), (*jwtlib.SigningMethodECDSA)(nil), (*jwtlib.SigningMethodEd25519)(nil)} {
				if isOAuthSigningMethod(&jwtlib.Token{Header: map[string]any{"alg": alg}, Method: bad}) {
					t.Fatal("untrusted or nil method accepted")
				}
			}
			for _, bad := range []any{nil, 1, []string{alg}, "HS256", "none", "eddsa"} {
				if isOAuthSigningMethod(&jwtlib.Token{Header: map[string]any{"alg": bad}, Method: method}) {
					t.Fatal("mismatched algorithm accepted")
				}
			}
		})
	}
}

func TestOAuthKeySelection(t *testing.T) {
	key, private := newOAuthEdKey(t, "shared", "")
	other, _ := newOAuthEdKey(t, "other", "")
	_, rsaPrivate, rsaKey := newOAuthValidatorTestProvider(t, "id_token")
	rsaKey.KeyID = key.KeyID
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		for _, tc := range []struct {
			name         string
			id           any
			hasID, valid bool
		}{
			{"matching", key.KeyID, true, true}, {"absent", nil, false, true}, {"unknown", "unknown", true, false},
			{"other key", other.KeyID, true, false}, {"null", nil, true, false}, {"number", 1, true, false}, {"empty", "", true, false},
		} {
			t.Run(alg+"/"+tc.name, func(t *testing.T) {
				b := oauthEdProvider(t, rsaKey, other, key)
				header := map[string]any{"alg": alg}
				if tc.hasID {
					header["kid"] = tc.id
				}
				token := signOAuthEdToken(t, private, header, oauthEdClaims())
				_, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": token})
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%v: %v", tc.valid, err)
				}
			})
		}
		copy := *key
		copy.KeyID = ""
		b := oauthEdProvider(t, &copy)
		if _, err := b.parseOAuthJWT(t.Context(), "id_token", signOAuthEdToken(t, private, map[string]any{"alg": alg}, oauthEdClaims())); err != nil {
			t.Fatal("kid-less singleton rejected", err)
		}
		// Do not discard alternatives with the same kid and different metadata.
		first := *key
		first.Algorithm = "EdDSA"
		second := *key
		second.Algorithm = "Ed25519"
		b = oauthEdProvider(t, &first, &second)
		if _, err := b.parseOAuthJWT(t.Context(), "id_token", signOAuthEdToken(t, private, map[string]any{"alg": alg, "kid": key.KeyID}, oauthEdClaims())); err != nil {
			t.Fatal("same-kid algorithm alternatives rejected", err)
		}
	}
	// Lock down all preexisting built-in RSA methods, including PSS fallback.
	for _, name := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		t.Run(name, func(t *testing.T) {
			b := oauthEdProvider(t, key, rsaKey)
			token := jwtlib.NewWithClaims(jwtlib.GetSigningMethod(name), oauthEdClaims())
			token.Header["kid"] = key.KeyID
			text, err := token.SignedString(rsaPrivate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": text}); err != nil {
				t.Fatal("legacy RSA method rejected", err)
			}
		})
	}
	for _, tc := range []struct {
		alg, curve string
		c          elliptic.Curve
		width      int
	}{{"ES256", "P-256", elliptic.P256(), 32}, {"ES384", "P-384", elliptic.P384(), 48}, {"ES512", "P-521", elliptic.P521(), 66}} {
		t.Run(tc.alg, func(t *testing.T) {
			private, err := ecdsa.GenerateKey(tc.c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			ec := &JwksKey{KeyID: "shared", KeyType: "EC", Curve: tc.curve, CoordX: base64.RawURLEncoding.EncodeToString(private.X.FillBytes(make([]byte, tc.width))), CoordY: base64.RawURLEncoding.EncodeToString(private.Y.FillBytes(make([]byte, tc.width)))}
			if err := ec.Validate(); err != nil {
				t.Fatal(err)
			}
			b := oauthEdProvider(t, key, ec)
			token := jwtlib.NewWithClaims(jwtlib.GetSigningMethod(tc.alg), oauthEdClaims())
			token.Header["kid"] = key.KeyID
			text, err := token.SignedString(private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": text}); err != nil {
				t.Fatal("legacy EC method rejected", err)
			}
		})
	}
}

func TestOAuthLegacyKeyOperationsCompatibility(t *testing.T) {
	_, private, key := newOAuthValidatorTestProvider(t, "id_token")
	for _, operations := range []any{nil, "legacy-extension", 17, []any{17}, []string{"encrypt"}} {
		var fields map[string]any
		if err := json.Unmarshal(oauthTestJSON(t, key), &fields); err != nil {
			t.Fatal(err)
		}
		fields["key_ops"] = operations
		parsed, err := decodeOAuthJwk(oauthTestJSON(t, fields))
		if err != nil {
			t.Fatal("new Ed restrictions changed legacy RSA acceptance", err)
		}
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, oauthEdClaims())
		token.Header["kid"] = key.KeyID
		signed, err := token.SignedString(private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oauthEdProvider(t, parsed).parseOAuthJWT(t.Context(), "id_token", signed); err != nil {
			t.Fatal("legacy RSA verification changed", err)
		}
	}
}

func TestOAuthEd25519RejectsForgedTokens(t *testing.T) {
	key, private := newOAuthEdKey(t, "ed-key", "")
	b := oauthEdProvider(t, key)
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		valid := signOAuthEdToken(t, private, map[string]any{"alg": alg, "kid": key.KeyID}, oauthEdClaims())
		parts := strings.Split(valid, ".")
		other := "EdDSA"
		if alg == other {
			other = "Ed25519"
		}
		badHeader := base64.RawURLEncoding.EncodeToString(oauthTestJSON(t, map[string]any{"alg": other, "kid": key.KeyID})) + "." + parts[1] + "." + parts[2]
		claims := oauthEdClaims()
		claims["roles"] = []string{"admin"}
		badClaims := parts[0] + "." + base64.RawURLEncoding.EncodeToString(oauthTestJSON(t, claims)) + "." + parts[2]
		for _, text := range []string{badHeader, badClaims, parts[0] + "." + parts[1] + ".AA", parts[0] + "." + parts[1] + ".", signOAuthEdToken(t, private, map[string]any{"alg": "eddsa", "kid": key.KeyID}, claims)} {
			if _, err := b.parseOAuthJWT(t.Context(), "id_token", text); err == nil {
				t.Fatal("forged token accepted")
			}
		}
	}
	for _, method := range []jwtlib.SigningMethod{jwtlib.SigningMethodHS256, jwtlib.SigningMethodHS384, jwtlib.SigningMethodHS512, jwtlib.SigningMethodNone} {
		token := jwtlib.NewWithClaims(method, oauthEdClaims())
		token.Header["kid"] = key.KeyID
		var secret any = []byte(key.GetPublic().(ed25519.PublicKey))
		if method == jwtlib.SigningMethodNone {
			secret = jwtlib.UnsafeAllowNoneSignatureType
		}
		text, err := token.SignedString(secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.parseOAuthJWT(t.Context(), "id_token", text); err == nil {
			t.Fatal("unsafe method accepted")
		}
	}
}

func TestParseOAuthJwks(t *testing.T) {
	key, _ := newOAuthEdKey(t, "ed-key", "")
	valid := oauthTestJSON(t, map[string]any{"keys": []any{key}})
	for _, tc := range []struct {
		name                 string
		body                 []byte
		authoritative, valid bool
	}{
		{"valid", valid, true, true},
		{"mixed", oauthTestJSON(t, map[string]any{"keys": []any{nil, 17, map[string]any{"kty": "unknown"}, map[string]any{"kty": "OKP", "x": true}, key}}), true, true},
		{"empty", []byte(`{"keys":[]}`), true, false},
		{"invalid entries", []byte(`{"keys":[null,{"kty":"unknown"}]}`), true, false},
		{"null keys", []byte(`{"keys":null}`), false, false},
		{"object keys", []byte(`{"keys":{}}`), false, false},
		{"missing keys", []byte(`{}`), false, false},
		{"malformed", []byte(`{"keys":[`), false, false},
		{"trailing document", append(append([]byte(nil), valid...), []byte(`{}`)...), false, false},
		{"too many keys", []byte(`{"keys":[` + strings.Repeat(`null,`, maxOAuthJwksKeys) + `null]}`), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, authoritative, err := parseOAuthJwks(tc.body)
			if authoritative != tc.authoritative || (err == nil) != tc.valid {
				t.Fatalf("authoritative=%v valid=%v: %v", authoritative, err == nil, err)
			}
			if tc.valid && (len(keys) != 1 || keys[0].KeyID != key.KeyID) {
				t.Fatal("usable sibling lost")
			}
		})
	}
}

func TestOAuthJwksRefresh(t *testing.T) {
	old, oldPrivate := newOAuthEdKey(t, "old", "")
	next, nextPrivate := newOAuthEdKey(t, "next", "")
	var body atomic.Value
	body.Store(string(oauthTestJSON(t, map[string]any{"keys": []any{old}})))
	var count atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body.Load().(string)))
	}))
	defer server.Close()
	b := oauthEdProvider(t)
	b.keysURL = server.URL
	b.browserConfig = &browserConfig{TLSInsecureSkipVerify: true}
	if err := b.fetchKeysURL(); err != nil {
		t.Fatal(err)
	}
	oldToken := signOAuthEdToken(t, oldPrivate, map[string]any{"alg": "EdDSA", "kid": old.KeyID}, oauthEdClaims())
	if _, err := b.parseOAuthJWT(t.Context(), "id_token", oldToken); err != nil {
		t.Fatal(err)
	}
	body.Store(string(oauthTestJSON(t, map[string]any{"keys": []any{next}})))
	newToken := signOAuthEdToken(t, nextPrivate, map[string]any{"alg": "Ed25519", "kid": next.KeyID}, oauthEdClaims())
	var wg sync.WaitGroup
	failures := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.validateAccessToken(t.Context(), "ed-state", map[string]any{"id_token": newToken})
			if err != nil {
				failures <- err
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if count.Load() != 2 {
		t.Fatalf("rotation fetched %d times, want 2 total", count.Load())
	}
	if _, err := b.parseOAuthJWT(t.Context(), "id_token", oldToken); err == nil {
		t.Fatal("removed key still accepted")
	}
	// Same-kid material replacement is discovered after signature failure.
	replacement, replacementPrivate := newOAuthEdKey(t, next.KeyID, "")
	body.Store(string(oauthTestJSON(t, map[string]any{"keys": []any{replacement}})))
	replacementToken := signOAuthEdToken(t, replacementPrivate, map[string]any{"alg": "EdDSA", "kid": next.KeyID}, oauthEdClaims())
	if _, err := b.parseOAuthJWT(t.Context(), "id_token", replacementToken); err != nil {
		t.Fatal("same-kid rotation failed", err)
	}
	if count.Load() != 4 {
		t.Fatalf("unexpected total fetches: %d", count.Load())
	}
	if _, err := b.parseOAuthJWT(t.Context(), "id_token", newToken); err == nil {
		t.Fatal("replaced material still accepted")
	}
	if count.Load() != 4 {
		t.Fatal("fetch limit bypassed")
	}
	// Expired claims with a valid signature must not consume a refresh.
	claims := oauthEdClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	if _, err := b.parseOAuthJWT(t.Context(), "id_token", signOAuthEdToken(t, replacementPrivate, map[string]any{"alg": "EdDSA", "kid": next.KeyID}, claims)); err == nil {
		t.Fatal("expired token accepted")
	}
	if count.Load() != 4 {
		t.Fatal("claim validation triggered fetch")
	}
	// Verify the existing cooldown can recover, without sleeps in tests.
	b.keyFetchMu.Lock()
	b.lastKeyFetch = time.Now().Add(-oauthKeyFetchCooldown)
	b.keyFetchMu.Unlock()
	if err := b.fetchKeysURL(); err != nil {
		t.Fatal("cooldown did not recover", err)
	}
}

func TestOAuthJwksFailedRefresh(t *testing.T) {
	key, private := newOAuthEdKey(t, "old", "")
	pin, pinnedPrivate := newOAuthEdKey(t, "pin", "")
	for _, tc := range []struct {
		name, body string
		status     int
		retains    bool
	}{
		{"HTTP error", string(oauthTestJSON(t, map[string]any{"keys": []any{key}})), 503, true},
		{"malformed", "{", 200, true},
		{"wrong shape", `{"keys":null}`, 200, true},
		{"oversized", strings.Repeat(" ", maxOAuthJwksBytes+1), 200, true},
		{"empty", `{"keys":[]}`, 200, false},
		{"unsupported", `{"keys":[{"kty":"unsupported"}]}`, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()
			b := oauthEdProvider(t)
			b.config.JwksKeys = map[string]string{pin.KeyID: oauthPublicPEMFile(t, pinnedPrivate.Public())}
			if err := b.installStaticKeys(); err != nil {
				t.Fatal(err)
			}
			b.keys = newOAuthJwksSet(append([]*JwksKey{key}, b.staticKeys.all...))
			b.keysURL = server.URL
			b.browserConfig = &browserConfig{TLSInsecureSkipVerify: true}
			_, version := b.snapshotKeys()
			var wg sync.WaitGroup
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := b.refreshKeys(t.Context(), &version); err == nil {
						t.Error("failed fetch returned success")
					}
				}()
			}
			wg.Wait()
			if count.Load() != 1 {
				t.Fatalf("failed refresh not coalesced: %d", count.Load())
			}
			b.disableKeyVerification = true
			token := signOAuthEdToken(t, private, map[string]any{"alg": "EdDSA", "kid": key.KeyID}, oauthEdClaims())
			_, err := b.parseOAuthJWT(t.Context(), "id_token", token)
			if (err == nil) != tc.retains {
				t.Fatalf("retains=%v: %v", tc.retains, err)
			}
			pinnedToken := signOAuthEdToken(t, pinnedPrivate, map[string]any{"alg": "Ed25519", "kid": pin.KeyID}, oauthEdClaims())
			if _, err := b.parseOAuthJWT(t.Context(), "id_token", pinnedToken); err != nil {
				t.Fatal("failed remote refresh removed an explicit static key", err)
			}
		})
	}
}

func oauthPublicPEMFile(t *testing.T, public any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOAuthStaticKeyProvisioning(t *testing.T) {
	key, private := newOAuthEdKey(t, "pin", "")
	path := oauthPublicPEMFile(t, private.Public())
	for _, disabled := range []bool{false, true} {
		cfg := &Config{Name: "static", Realm: "static", Driver: "generic", ClientID: oauthValidatorTestClientID, ClientSecret: "synthetic", BaseAuthURL: "https://idp.example", AuthorizationURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token", JwksKeys: map[string]string{key.KeyID: path}, KeyVerificationDisabled: disabled, Issuer: oauthValidatorTestIssuer}
		b, err := NewIdentityProvider(cfg, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		if err := b.Configure(); err != nil {
			t.Fatal(err)
		}
		if b.canFetchKeys() {
			t.Fatal("static-only provider attempts discovery")
		}
		for _, alg := range []string{"EdDSA", "Ed25519"} {
			token := signOAuthEdToken(t, private, map[string]any{"alg": alg, "kid": key.KeyID}, oauthEdClaims())
			if _, err := b.parseOAuthJWT(t.Context(), "id_token", token); err != nil {
				t.Fatal("static key not installed", err)
			}
		}
	}
}

func TestOAuthStaticKeyPrecedence(t *testing.T) {
	key, private := newOAuthEdKey(t, "pin", "")
	rogue, roguePrivate := newOAuthEdKey(t, "pin", "")
	remote, remotePrivate := newOAuthEdKey(t, "remote", "")
	b := oauthEdProvider(t)
	b.config.JwksKeys = map[string]string{key.KeyID: oauthPublicPEMFile(t, private.Public())}
	if err := b.installStaticKeys(); err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{rogue, remote}})
	}))
	defer server.Close()
	b.keysURL = server.URL
	b.browserConfig = &browserConfig{TLSInsecureSkipVerify: true}
	if err := b.fetchKeysURL(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id      string
		private ed25519.PrivateKey
		valid   bool
	}{{key.KeyID, private, true}, {rogue.KeyID, roguePrivate, false}, {remote.KeyID, remotePrivate, true}} {
		// Test helpers keep the concrete key type; no production signer is used.
		token := signOAuthEdToken(t, tc.private, map[string]any{"alg": "Ed25519", "kid": tc.id}, oauthEdClaims())
		_, err := b.parseOAuthJWT(t.Context(), "id_token", token)
		if (err == nil) != tc.valid {
			t.Fatalf("pin valid=%v: %v", tc.valid, err)
		}
	}
	if count.Load() != 1 {
		t.Fatal("pinned-key failure triggered remote fallback")
	}
}

func FuzzOAuthJwks(f *testing.F) {
	for _, seed := range []string{`{"keys":[]}`, `{"keys":[null]}`, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`, `{"keys":[{"kid":"rsa","kty":"RSA","e":"AQAB","n":"AQAB"}]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxOAuthJwksBytes {
			return
		}
		keys, _, _ := parseOAuthJwks(data)
		set := newOAuthJwksSet(keys)
		for _, alg := range []string{"EdDSA", "Ed25519", "RS256", "ES256", "HS256", "none"} {
			candidates := set.verificationKeys(alg, "", false)
			if (alg == "HS256" || alg == "none") && len(candidates.Keys) != 0 {
				t.Fatal("unsafe algorithm received keys")
			}
			for _, key := range candidates.Keys {
				_ = jwtlib.GetSigningMethod(alg).Verify("e30.e30", make([]byte, 64), key)
			}
		}
	})
}

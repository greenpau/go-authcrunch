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

package authn

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func privateKeysAdminToken(t *testing.T, p *Portal, roles []string, lifetime time.Duration) string {
	t.Helper()
	usr, err := user.NewUser(map[string]any{"sub": "key-export-test", "roles": roles, "exp": time.Now().Add(lifetime).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.keystore.SignToken(nil, nil, usr); err != nil {
		t.Fatal(err)
	}
	return usr.Token
}

func privateKeysRequest(t *testing.T, p *Portal, method, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "https://auth.example.test"+target, nil)
	r.Header.Set("Accept", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	if err := p.ServeHTTP(context.Background(), w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private-key response can be cached")
	}
	return w
}

func TestAdminFetchPrivateKeysAuthorization(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	admin := privateKeysAdminToken(t, p, []string{"authp/admin"}, time.Hour)
	member := privateKeysAdminToken(t, p, []string{"authp/user"}, time.Hour)
	expired := privateKeysAdminToken(t, p, []string{"authp/admin"}, -time.Hour)
	parts := strings.Split(admin, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	tampered := strings.Join(parts, ".")
	for _, tc := range []struct {
		name         string
		cfg          *APIConfig
		token, query string
		status       int
	}{
		{"nil API config", nil, admin, "", 404},
		{"default", &APIConfig{}, admin, "", 404},
		{"admin only", &APIConfig{AdminEnabled: true}, admin, "", 404},
		{"export only", &APIConfig{AdminFetchPrivateKeysEnabled: true}, admin, "", 404},
		{"query cannot enable export", &APIConfig{AdminEnabled: true}, admin, "?admin_fetch_private_keys_enabled=true", 404},
		{"anonymous", &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, "", "", 403},
		{"member", &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, member, "", 403},
		{"invalid token", &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, "invalid", "", 401},
		{"expired admin", &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, expired, "", 401},
		{"tampered admin", &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, tampered, "", 401},
		{"authorized admin", &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}, admin, "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.config.API = tc.cfg
			w := privateKeysRequest(t, p, "GET", "/xauth"+privateKeysPath+tc.query, tc.token)
			if w.Code != tc.status {
				t.Fatalf("got %d, want %d", w.Code, tc.status)
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Fatal("expected JSON response")
			}
			if w.Code != 200 && (bytes.Contains(w.Body.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(w.Body.Bytes(), []byte("private_key"))) {
				t.Fatal("denied response disclosed key material")
			}
		})
	}
	p.config.API = &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
	for _, method := range []string{"POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			w := privateKeysRequest(t, p, method, privateKeysPath, admin)
			if w.Code != 405 || w.Header().Get("Allow") != "GET" || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE KEY")) {
				t.Fatal("unsupported method disclosed a key or was not rejected")
			}
		})
	}
	// Disabling after a successful authorized request must take effect even
	// when the admin's token is in the authorization cache.
	p.config.API.AdminFetchPrivateKeysEnabled = false
	if w := privateKeysRequest(t, p, "GET", privateKeysPath, admin); w.Code != 404 {
		t.Fatal("cached administrator bypassed disabled export")
	}
}

func TestAdminFetchPrivateKeysMatchesJWKS(t *testing.T) {
	const rsaKey = "crypto key rsa-signing sign-verify from file ../../testdata/rskeys/test_2_pri.pem"
	const ecKey = "crypto key ec-signing sign-verify from file ../../testdata/ecdsakeys/test_2_pri.pem"
	for _, tc := range []struct {
		name       string
		directives []string
		count      int
	}{
		{"autogenerated", nil, 1},
		{"RSA", []string{rsaKey}, 1},
		{"ECDSA", []string{ecKey}, 1},
		{"multiple RSA keys", []string{rsaKey, "crypto key rsa-next sign-verify from file ../../testdata/rskeys/test_1_pri.pem"}, 2},
		{"mixed key types", []string{rsaKey, ecKey}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRefreshPortal(t, false, false).portal
			cfg, err := kms.NewCryptoKeyStoreConfig(tc.directives)
			if err != nil {
				t.Fatal(err)
			}
			p.config.CryptoKeyStoreConfig = cfg
			if err := p.configureCryptoKeyStore(); err != nil {
				t.Fatal(err)
			}
			p.config.API = &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
			admin := privateKeysAdminToken(t, p, []string{"authp/admin"}, time.Hour)
			core, logs := observer.New(zap.DebugLevel)
			p.logger = zap.New(core)
			for _, base := range []string{"", "/xauth", "/tenant/xauth"} {
				exported := privateKeysRequest(t, p, "GET", base+privateKeysPath+"?format=json", admin)
				if exported.Code != 200 || exported.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Fatal("admin export failed")
				}
				var pairs struct {
					Keys []struct {
						PublicKey  json.RawMessage `json:"public_key"`
						PrivateKey string          `json:"private_key"`
					} `json:"keys"`
				}
				if err := json.Unmarshal(exported.Body.Bytes(), &pairs); err != nil {
					t.Fatal("invalid export response")
				}
				if len(pairs.Keys) != tc.count {
					t.Fatal("unexpected exported key count")
				}
				public := requestJWKS(t, p, "GET", base+jwksPath+"?private=true&format=json", nil)
				if public.Code != 200 {
					t.Fatal("public discovery failed")
				}
				var set struct {
					Keys []json.RawMessage `json:"keys"`
				}
				if err := json.Unmarshal(public.Body.Bytes(), &set); err != nil {
					t.Fatal(err)
				}
				if len(set.Keys) != tc.count {
					t.Fatal("unexpected public key count")
				}
				if bytes.Contains(public.Body.Bytes(), []byte("private_key")) || bytes.Contains(public.Body.Bytes(), []byte("PRIVATE KEY")) {
					t.Fatal("public JWKS disclosed private material")
				}
				recorded, err := json.Marshal(logs.All())
				if err != nil {
					t.Fatal(err)
				}
				for i, pair := range pairs.Keys {
					if !bytes.Equal(set.Keys[i], pair.PublicKey) {
						t.Fatal("private export is not paired with the published public key")
					}
					block, rest := pem.Decode([]byte(pair.PrivateKey))
					if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
						t.Fatal("expected PKCS#8 PEM private key")
					}
					if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
						t.Fatal("private key could not be parsed")
					}
					if bytes.Contains(recorded, []byte("PRIVATE KEY")) || bytes.Contains(recorded, []byte(strings.Split(pair.PrivateKey, "\n")[1])) {
						t.Fatal("private key was logged")
					}
				}
			}
		})
	}
}

func TestAdminFetchPrivateKeysFailuresAndRoutes(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	p.config.API = &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
	admin := privateKeysAdminToken(t, p, []string{"authp/admin"}, time.Hour)
	for _, path := range []string{
		privateKeysPath + "/", privateKeysPath + ".json", privateKeysPath + "/extra", privateKeysPath + "%2fextra",
		"/api/server/unknown?path=" + privateKeysPath,
	} {
		w := privateKeysRequest(t, p, "GET", path, admin)
		if w.Code == 200 || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE KEY")) {
			t.Fatal("near-match route exposed private keys")
		}
	}
	// The public suffix route cannot be used as an alias for private export.
	w := requestJWKS(t, p, "GET", privateKeysPath+jwksPath, nil)
	if bytes.Contains(w.Body.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(w.Body.Bytes(), []byte("private_key")) {
		t.Fatal("public suffix bypassed private-key authorization")
	}

	original := p.keystore
	p.keystore = nil
	if w := privateKeysRequest(t, p, "GET", privateKeysPath, admin); w.Code != 404 {
		t.Fatal("missing signing keys should return 404")
	}
	cfg, err := kms.NewCryptoKeyStoreConfig([]string{"crypto key sign-verify synthetic-shared-secret"})
	if err != nil {
		t.Fatal(err)
	}
	p.keystore, err = kms.NewCryptoKeyStore(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if w := privateKeysRequest(t, p, "GET", privateKeysPath, admin); w.Code != 404 {
		t.Fatal("shared keys should not be exported")
	}
	p.keystore = original
	p.keystore.GetSignKeys()[0].Sign.Secret = []byte("synthetic-invalid-private-material")
	w = privateKeysRequest(t, p, "GET", privateKeysPath, admin)
	if w.Code != 500 || bytes.Contains(w.Body.Bytes(), []byte("synthetic-invalid")) || bytes.Contains(w.Body.Bytes(), []byte("kms:")) {
		t.Fatal("invalid signer did not fail with a generic error")
	}
	// No exporting work should run once the endpoint is disabled.
	p.config.API.AdminFetchPrivateKeysEnabled = false
	if w := privateKeysRequest(t, p, "GET", privateKeysPath, admin); w.Code != 404 {
		t.Fatal("disabled endpoint inspected private material")
	}
}

func TestAdminFetchPrivateKeysWriteError(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	p.config.API = &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
	admin := privateKeysAdminToken(t, p, []string{"authp/admin"}, time.Hour)
	want := errors.New("connection closed")
	w := jwksFailingWriter{httptest.NewRecorder(), want}
	r := httptest.NewRequest("GET", privateKeysPath, nil)
	r.Header.Set("Authorization", "Bearer "+admin)
	if err := p.ServeHTTP(context.Background(), w, r, requests.NewRequest()); !errors.Is(err, want) {
		t.Fatal("private export write error was not propagated")
	}
}

func TestAdminFetchPrivateKeysFormats(t *testing.T) {
	for _, keyType := range []string{"RSA", "EC"} {
		t.Run(keyType, func(t *testing.T) {
			p := newRefreshPortal(t, false, false).portal
			if keyType == "RSA" {
				cfg, err := kms.NewCryptoKeyStoreConfig([]string{"crypto key signing sign-verify from file ../../testdata/rskeys/test_2_pri.pem"})
				if err != nil {
					t.Fatal(err)
				}
				p.config.CryptoKeyStoreConfig = cfg
				if err := p.configureCryptoKeyStore(); err != nil {
					t.Fatal(err)
				}
			}
			p.config.API = &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
			admin := privateKeysAdminToken(t, p, []string{"authp/admin"}, time.Hour)
			core, logs := observer.New(zap.DebugLevel)
			p.logger = zap.New(core)
			formats := []string{"pkcs8", "jwk"}
			if keyType == "RSA" {
				formats = append(formats, "pkcs1")
			} else {
				formats = append(formats, "sec1")
			}
			for _, format := range formats {
				encodings := []string{"pem", "der"}
				if format == "jwk" {
					encodings = []string{"json"}
				}
				for _, encoding := range encodings {
					query := "?format=" + format + "&encoding=" + encoding
					w := privateKeysRequest(t, p, "GET", "/tenant/xauth"+privateKeysPath+query, admin)
					if w.Code != 200 {
						t.Fatalf("format %s/%s returned %d", format, encoding, w.Code)
					}
					var set struct {
						Keys []struct {
							PrivateKey json.RawMessage `json:"private_key"`
						} `json:"keys"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
						t.Fatal("invalid export response")
					}
					var secretMarker string
					if format == "jwk" {
						var key map[string]any
						if err := json.Unmarshal(set.Keys[0].PrivateKey, &key); err != nil || key["kty"] != keyType {
							t.Fatal("requested JWK was not an object")
						}
						secretMarker, _ = key["d"].(string)
						if secretMarker == "" {
							t.Fatal("private JWK lacks private exponent")
						}
					} else {
						var value string
						if err := json.Unmarshal(set.Keys[0].PrivateKey, &value); err != nil {
							t.Fatal("requested private-key encoding was not a string")
						}
						var der []byte
						if encoding == "der" {
							var err error
							der, err = base64.StdEncoding.DecodeString(value)
							if err != nil {
								t.Fatal("invalid DER base64")
							}
							secretMarker = value
						} else {
							block, rest := pem.Decode([]byte(value))
							if block == nil || len(rest) != 0 {
								t.Fatal("invalid PEM")
							}
							der = block.Bytes
							secretMarker = "PRIVATE KEY"
						}
						var err error
						switch format {
						case "pkcs8":
							_, err = x509.ParsePKCS8PrivateKey(der)
						case "pkcs1":
							_, err = x509.ParsePKCS1PrivateKey(der)
						case "sec1":
							_, err = x509.ParseECPrivateKey(der)
						}
						if err != nil {
							t.Fatal("response did not use the requested key format")
						}
					}
					recorded, err := json.Marshal(logs.All())
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(recorded, []byte(secretMarker)) {
						t.Fatal("private key format leaked into logs")
					}
					public := requestJWKS(t, p, "GET", "/tenant/xauth"+jwksPath+query, nil)
					if public.Code != 200 || bytes.Contains(public.Body.Bytes(), []byte(`"d":`)) || bytes.Contains(public.Body.Bytes(), []byte("private_key")) {
						t.Fatal("format selector affected public-only discovery")
					}
				}
			}
		})
	}
}

func TestAdminFetchPrivateKeysRejectsFormatQueries(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	p.config.API = &APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
	admin := privateKeysAdminToken(t, p, []string{"authp/admin"}, time.Hour)
	for _, query := range []string{
		"?format=xml", "?encoding=raw", "?format=jwk&encoding=pem", "?format=jwk&encoding=der",
		"?format=pkcs8&encoding=json", "?format=pkcs1", "?format=", "?encoding=",
		"?format=jwk&format=pkcs8", "?encoding=pem&encoding=der", "?%66ormat=pkcs8&format=jwk",
		"?format=%ZZ", "?format=pkcs8;encoding=der",
	} {
		t.Run(query, func(t *testing.T) {
			w := privateKeysRequest(t, p, "GET", privateKeysPath+query, admin)
			if w.Code != 400 || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(w.Body.Bytes(), []byte(`"keys":`)) {
				t.Fatal("invalid format query was not rejected without keys")
			}
		})
	}
	for _, query := range []string{"?format=json", "?format=jwk", "?encoding=der"} {
		if w := privateKeysRequest(t, p, "GET", privateKeysPath+query, admin); w.Code != 200 {
			t.Fatal("valid default format or encoding was rejected")
		}
	}
	// Format parsing and private material access must remain behind both the
	// opt-in and role checks, including requests for JWK private parameters.
	if w := privateKeysRequest(t, p, "GET", privateKeysPath+"?format=jwk", ""); w.Code != 403 {
		t.Fatal("format query bypassed admin authorization")
	}
	p.config.API.AdminFetchPrivateKeysEnabled = false
	for _, query := range []string{"?format=jwk", "?format=pkcs1", "?format=xml"} {
		if w := privateKeysRequest(t, p, "GET", privateKeysPath+query, admin); w.Code != 404 {
			t.Fatal("format query bypassed disabled export")
		}
	}
}

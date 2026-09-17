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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOIDCSignedRequestObjects(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := RequestObjectKey{KeyID: "client-key", Modulus: base64.RawURLEncoding.EncodeToString(private.N.Bytes()), Exponent: "AQAB"}
	client := oidcTestConfig().Clients[0]
	client.RequestObjectKeys = []RequestObjectKey{key}
	client.RequestObjectSigningAlg = "RS256"
	if err := client.Validate(); err != nil {
		t.Fatal(err)
	}
	provider := &Provider{clients: map[string]*ClientConfig{"client": client, "other": {ClientID: "other"}}, config: Config{Issuer: "https://auth.test"}, now: func() time.Time { return time.Unix(1000, 0) }}
	for _, tc := range []struct {
		name         string
		header, body map[string]any
		tamper       bool
		client       string
		ok           bool
	}{
		{name: "valid", ok: true}, {name: "no kid single key", header: map[string]any{"alg": "RS256"}, ok: true},
		{name: "wrong kid", header: map[string]any{"alg": "RS256", "kid": "other"}},
		{name: "unsigned downgrade", header: map[string]any{"alg": "none"}},
		{name: "algorithm confusion", header: map[string]any{"alg": "HS256"}},
		{name: "remote key injection", header: map[string]any{"alg": "RS256", "jku": "https://evil.test"}},
		{name: "embedded key injection", header: map[string]any{"alg": "RS256", "jwk": map[string]any{}}},
		{name: "critical extension", header: map[string]any{"alg": "RS256", "crit": []string{"x"}}},
		{name: "wrong issuer", body: map[string]any{"iss": "other", "aud": "https://auth.test"}},
		{name: "wrong audience", body: map[string]any{"iss": "client", "aud": "https://other.test"}},
		{name: "missing audience", body: map[string]any{"iss": "client"}},
		{name: "expired", body: map[string]any{"iss": "client", "aud": "https://auth.test", "exp": 999}},
		{name: "future", body: map[string]any{"iss": "client", "aud": "https://auth.test", "nbf": 1001}},
		{name: "tampered", tamper: true}, {name: "other client", client: "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header
			if header == nil {
				header = map[string]any{"alg": "RS256", "kid": "client-key"}
			}
			body := tc.body
			if body == nil {
				body = map[string]any{"iss": "client", "aud": "https://auth.test", "exp": 1100, "iat": 999, "scope": "openid"}
			}
			a, _ := json.Marshal(header)
			b, _ := json.Marshal(body)
			raw := base64.RawURLEncoding.EncodeToString(a) + "." + base64.RawURLEncoding.EncodeToString(b)
			digest := sha256.Sum256([]byte(raw))
			sig, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if tc.tamper {
				sig[0] ^= 1
			}
			if header["alg"] == "none" {
				sig = nil
			}
			raw += "." + base64.RawURLEncoding.EncodeToString(sig)
			id := tc.client
			if id == "" {
				id = "client"
			}
			_, failure := provider.requestObjectParameters(url.Values{"client_id": {id}, "response_type": {"code"}, "scope": {"openid"}, "request": {raw}})
			if (failure == "") != tc.ok {
				t.Fatalf("unexpected verification result: %s", failure)
			}
		})
	}
	for _, mutate := range []func(*ClientConfig){
		func(c *ClientConfig) { c.RequestObjectSigningAlg = "HS256" }, func(c *ClientConfig) { c.RequestObjectKeys = nil },
		func(c *ClientConfig) { c.RequestObjectKeys[0].Modulus = "AA" }, func(c *ClientConfig) { c.RequestObjectKeys[0].Exponent = "Ag" },
		func(c *ClientConfig) { c.RequestObjectKeys[0].Exponent = "AAEAAQ" }, func(c *ClientConfig) { c.RequestObjectKeys[0].KeyID = "" },
		func(c *ClientConfig) { c.RequestObjectKeys = append(c.RequestObjectKeys, c.RequestObjectKeys[0]) },
		func(c *ClientConfig) { c.RequestObjectKeys[0].Modulus = strings.Repeat("A", 20000) },
	} {
		c := cloneClientConfig(*client)
		mutate(c)
		if c.Validate() == nil {
			t.Fatal("invalid verification registration accepted")
		}
	}
	if client.RequestObjectKeys[0].KeyID != "client-key" {
		t.Fatal("cloned key registration aliases caller")
	}
}

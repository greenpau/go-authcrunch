// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0
package authn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"testing"
)

func testOpenAPIPrivateExport(t *testing.T, validate openAPIResponseValidator) {
	t.Run("private_key_export", func(t *testing.T) {
		f := newOpenAPIPortalFixture(t, "/auth", "enable admin api\nenable admin api private key export", true)
		admin := f.login(t, "keyadmin")
		_, publicBody := f.request(t, "GET", "/.well-known/jwks.json", "", "", 200)
		public := f.publicKey(t, publicBody)
		for _, tc := range []struct{ query, format, encoding string }{
			{"?format=jwk", "jwk", ""}, {"?format=pkcs8", "pkcs8", "pem"},
			{"?format=pkcs8&encoding=der", "pkcs8", "der"}, {"?format=sec1", "sec1", "pem"},
			{"?format=json&ignored=one&ignored=two", "pkcs8", "pem"},
		} {
			t.Run(tc.format+tc.encoding, func(t *testing.T) {
				header, body := f.request(t, "GET", "/api/server/private_keys"+tc.query, admin, "", 200)
				validate(t, "/api/server/private_keys", "GET", 200, header, body)
				if header.Get("X-Content-Type-Options") != "nosniff" {
					t.Fatal("private export omitted nosniff")
				}
				f.validateExport(t, body, public, tc.format, tc.encoding)
			})
		}
		for _, query := range []string{"?format=", "?encoding=", "?format=jwk&format=jwk", "?format=PKCS8", "?format=jwk&encoding=pem", "?format=json&encoding=json", "?format=pkcs1"} {
			header, body := f.request(t, "GET", "/api/server/private_keys"+query, admin, "", 400)
			validate(t, "/api/server/private_keys", "GET", 400, header, body)
			if header.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("private export error omitted nosniff")
			}
		}
		header, body := f.request(t, "POST", "/api/server/private_keys", admin, "", 405)
		validate(t, "/api/server/private_keys", "GET", 405, header, body)
		if header.Get("Allow") != "GET" {
			t.Fatal("private export method header changed")
		}
	})
}
func (f *openAPIPortalFixture) publicKey(t *testing.T, data []byte) map[string]string {
	t.Helper()
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != 1 {
		t.Fatal("expected one public signing key")
	}
	key := set.Keys[0]
	for field := range key {
		switch field {
		case "kty", "kid", "alg", "use", "crv", "x", "y":
		default:
			t.Fatal("public JWKS contained an unexpected field")
		}
	}
	if key["kty"] != "EC" || key["crv"] != "P-256" || key["alg"] != "ES256" || key["use"] != "sig" || key["kid"] == "" {
		t.Fatal("unexpected public signing metadata")
	}
	x, xerr := base64.RawURLEncoding.DecodeString(key["x"])
	y, yerr := base64.RawURLEncoding.DecodeString(key["y"])
	if xerr != nil || yerr != nil || len(x) != 32 || len(y) != 32 {
		t.Fatal("invalid public coordinates")
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil || !public.Equal(&f.key.PublicKey) {
		t.Fatal("public JWKS did not match the configured signing key")
	}
	return key
}

func (f *openAPIPortalFixture) validateExport(t *testing.T, data []byte, public map[string]string, format, encoding string) {
	t.Helper()
	var set struct {
		Keys []struct {
			Public  map[string]string `json:"public_key"`
			Private json.RawMessage   `json:"private_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != 1 || !maps.Equal(set.Keys[0].Public, public) {
		t.Fatal("export did not match published JWKS")
	}
	if format == "jwk" {
		var private map[string]string
		if err := json.Unmarshal(set.Keys[0].Private, &private); err != nil {
			t.Fatal("invalid private JWK")
		}
		scalar, err := f.key.Bytes()
		if err != nil {
			t.Fatal("could not encode synthetic signing key")
		}
		if private["d"] != base64.RawURLEncoding.EncodeToString(scalar) {
			t.Fatal("private JWK scalar does not match signing key")
		}
		for field, value := range public {
			if private[field] != value {
				t.Fatal("private JWK public parameters changed")
			}
		}
		return
	}
	var encoded string
	if err := json.Unmarshal(set.Keys[0].Private, &encoded); err != nil {
		t.Fatal("private export was not a string")
	}
	var der []byte
	if encoding == "der" {
		var err error
		der, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal("invalid DER export encoding")
		}
	} else {
		block, rest := pem.Decode([]byte(encoded))
		label := "PRIVATE KEY"
		if format == "sec1" {
			label = "EC PRIVATE KEY"
		}
		if block == nil || block.Type != label || len(rest) != 0 {
			t.Fatal("invalid private PEM export")
		}
		der = block.Bytes
	}
	var private *ecdsa.PrivateKey
	if format == "sec1" {
		var err error
		private, err = x509.ParseECPrivateKey(der)
		if err != nil {
			t.Fatal("invalid SEC1 export")
		}
	} else {
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatal("invalid PKCS8 export")
		}
		var ok bool
		private, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("unexpected exported key type")
		}
	}
	if !private.Equal(f.key) {
		t.Fatal("exported private key does not match the public signing key")
	}
}

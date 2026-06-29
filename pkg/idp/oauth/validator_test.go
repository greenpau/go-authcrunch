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
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const (
	oauthValidatorTestAccessAudience = "https://api.example.com"
	oauthValidatorTestClientID       = "authcrunch-client"
	oauthValidatorTestIssuer         = "https://issuer.example.com"
)

func TestValidateAccessTokenMergesVerifiedAccessTokenClaims(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-1", "nonce-1"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"roles": []string{"viewer"},
		"sub":   "subject-user",
	})
	accessToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud": oauthValidatorTestClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": oauthValidatorTestIssuer,
		"realm_access": map[string]interface{}{
			"roles": []string{"editor"},
		},
	})

	got, err := provider.validateAccessToken(state, map[string]interface{}{
		"access_token": accessToken,
		"id_token":     idToken,
	})
	if err != nil {
		t.Fatalf("unexpected validateAccessToken error: %v", err)
	}

	if got["email"] != "user@example.com" {
		t.Fatalf("expected email from id_token, got %v", got["email"])
	}
	if got["sub"] != "subject-user" {
		t.Fatalf("expected sub from id_token, got %v", got["sub"])
	}
	if got["name"] != "Valid User" {
		t.Fatalf("expected name from id_token, got %v", got["name"])
	}
	if !reflect.DeepEqual(got["roles"], []string{"viewer", "editor"}) {
		t.Fatalf("expected merged roles from id_token and access_token, got %#v", got["roles"])
	}
}

func TestValidateAccessTokenRejectsUnsignedAccessTokenClaims(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-2", "nonce-2"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"roles": []string{"viewer"},
		"sub":   "subject-user",
	})
	accessToken := unsignedOAuthValidatorTestToken(t, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"roles": []string{"admin"},
	})

	if got, err := provider.validateAccessToken(state, map[string]interface{}{
		"access_token": accessToken,
		"id_token":     idToken,
	}); err == nil {
		t.Fatalf("expected unsigned access_token validation error, got claims: %#v", got)
	}
}

func TestValidateAccessTokenIgnoresOpaqueAccessTokenClaims(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-3", "nonce-3"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"roles": []string{"viewer"},
		"sub":   "subject-user",
	})

	got, err := provider.validateAccessToken(state, map[string]interface{}{
		"access_token": "opaque-access-token",
		"id_token":     idToken,
	})
	if err != nil {
		t.Fatalf("unexpected validateAccessToken error: %v", err)
	}

	if got["email"] != "user@example.com" {
		t.Fatalf("expected email from id_token, got %v", got["email"])
	}
	if !reflect.DeepEqual(got["roles"], []string{"viewer"}) {
		t.Fatalf("expected roles from id_token, got %#v", got["roles"])
	}
}

func TestValidateAccessTokenAcceptsSignedAccessTokenWhenConfiguredAsIdentityToken(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "access_token")
	state, nonce := "state-4", "nonce-4"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	accessToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"roles": []string{"viewer"},
		"sub":   "subject-user",
	})

	got, err := provider.validateAccessToken(state, map[string]interface{}{
		"access_token": accessToken,
	})
	if err != nil {
		t.Fatalf("unexpected validateAccessToken error: %v", err)
	}
	if got["email"] != "user@example.com" {
		t.Fatalf("expected email from access_token, got %v", got["email"])
	}
	if !reflect.DeepEqual(got["roles"], []string{"viewer"}) {
		t.Fatalf("expected roles from access_token, got %#v", got["roles"])
	}
}

func TestValidateAccessTokenRejectsUnsignedAccessTokenWhenConfiguredAsIdentityToken(t *testing.T) {
	provider, _, _ := newOAuthValidatorTestProvider(t, "access_token")
	state, nonce := "state-5", "nonce-5"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	accessToken := unsignedOAuthValidatorTestToken(t, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "attacker@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Attacker",
		"nonce": nonce,
		"roles": []string{"admin"},
		"sub":   "subject-attacker",
	})

	if got, err := provider.validateAccessToken(state, map[string]interface{}{"access_token": accessToken}); err == nil {
		t.Fatalf("expected unsigned access_token validation error, got claims: %#v", got)
	}
}

func TestValidateAccessTokenRejectsWrongIDTokenIssuer(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-6", "nonce-6"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   "https://other-issuer.example.com",
		"name":  "Valid User",
		"nonce": nonce,
		"sub":   "subject-user",
	})

	if got, err := provider.validateAccessToken(state, map[string]interface{}{"id_token": idToken}); err == nil {
		t.Fatalf("expected issuer validation error, got claims: %#v", got)
	} else if !strings.Contains(err.Error(), "issuer claim validation failed") {
		t.Fatalf("expected issuer validation error, got: %v", err)
	}
}

func TestValidateAccessTokenRejectsWrongIDTokenAudience(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-7", "nonce-7"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   "other-client",
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"sub":   "subject-user",
	})

	if got, err := provider.validateAccessToken(state, map[string]interface{}{"id_token": idToken}); err == nil {
		t.Fatalf("expected audience validation error, got claims: %#v", got)
	} else if !strings.Contains(err.Error(), "audience claim validation failed") {
		t.Fatalf("expected audience validation error, got: %v", err)
	}
}

func TestValidateAccessTokenRejectsWrongIDTokenAuthorizedParty(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-8", "nonce-8"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   []string{oauthValidatorTestClientID, "other-client"},
		"azp":   "other-client",
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"sub":   "subject-user",
	})

	if got, err := provider.validateAccessToken(state, map[string]interface{}{"id_token": idToken}); err == nil {
		t.Fatalf("expected authorized party validation error, got claims: %#v", got)
	} else if !strings.Contains(err.Error(), "authorized party claim validation failed") {
		t.Fatalf("expected authorized party validation error, got: %v", err)
	}
}

func TestValidateAccessTokenMergesAccessTokenClaimsWithResourceAudienceAndAzp(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-9", "nonce-9"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"roles": []string{"viewer"},
		"sub":   "subject-user",
	})
	accessToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud": oauthValidatorTestAccessAudience,
		"azp": oauthValidatorTestClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": oauthValidatorTestIssuer,
		"realm_access": map[string]interface{}{
			"roles": []string{"editor"},
		},
	})

	got, err := provider.validateAccessToken(state, map[string]interface{}{
		"access_token": accessToken,
		"id_token":     idToken,
	})
	if err != nil {
		t.Fatalf("unexpected validateAccessToken error: %v", err)
	}
	if !reflect.DeepEqual(got["roles"], []string{"viewer", "editor"}) {
		t.Fatalf("expected merged roles from id_token and access_token, got %#v", got["roles"])
	}
}

func TestValidateAccessTokenRejectsAccessTokenClaimsWithWrongAzp(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	state, nonce := "state-10", "nonce-10"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"roles": []string{"viewer"},
		"sub":   "subject-user",
	})
	accessToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud": oauthValidatorTestAccessAudience,
		"azp": "other-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": oauthValidatorTestIssuer,
		"realm_access": map[string]interface{}{
			"roles": []string{"admin"},
		},
	})

	if got, err := provider.validateAccessToken(state, map[string]interface{}{
		"access_token": accessToken,
		"id_token":     idToken,
	}); err == nil {
		t.Fatalf("expected access_token azp validation error, got claims: %#v", got)
	} else if !strings.Contains(err.Error(), "authorized party claim validation failed") {
		t.Fatalf("expected authorized party validation error, got: %v", err)
	}
}

func TestValidateAccessTokenMergesAccessTokenClaimsWithConfiguredAudience(t *testing.T) {
	provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
	provider.config.AccessTokenAudience = oauthValidatorTestAccessAudience
	state, nonce := "state-11", "nonce-11"
	if err := provider.state.add(state, nonce); err != nil {
		t.Fatalf("failed adding state: %v", err)
	}

	idToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud":   oauthValidatorTestClientID,
		"email": "user@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   oauthValidatorTestIssuer,
		"name":  "Valid User",
		"nonce": nonce,
		"roles": []string{"viewer"},
		"sub":   "subject-user",
	})
	accessToken := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, jwtlib.MapClaims{
		"aud": oauthValidatorTestAccessAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": oauthValidatorTestIssuer,
		"realm_access": map[string]interface{}{
			"roles": []string{"editor"},
		},
	})

	got, err := provider.validateAccessToken(state, map[string]interface{}{
		"access_token": accessToken,
		"id_token":     idToken,
	})
	if err != nil {
		t.Fatalf("unexpected validateAccessToken error: %v", err)
	}
	if !reflect.DeepEqual(got["roles"], []string{"viewer", "editor"}) {
		t.Fatalf("expected merged roles from id_token and access_token, got %#v", got["roles"])
	}
}

func newOAuthValidatorTestProvider(t *testing.T, identityTokenFieldName string) (*IdentityProvider, *rsa.PrivateKey, *JwksKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating RSA key: %v", err)
	}

	jwksKey, err := NewJwksKeyFromRSAPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed creating JWKS key: %v", err)
	}

	return &IdentityProvider{
		config: &Config{
			ClientID:               oauthValidatorTestClientID,
			Driver:                 "generic",
			IdentityTokenFieldName: identityTokenFieldName,
			Issuer:                 oauthValidatorTestIssuer,
		},
		keys:  map[string]*JwksKey{jwksKey.KeyID: jwksKey},
		state: newStateManager(),
	}, privateKey, jwksKey
}

func signOAuthValidatorTestToken(t *testing.T, privateKey *rsa.PrivateKey, keyID string, claims jwtlib.MapClaims) string {
	t.Helper()

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed signing token: %v", err)
	}
	return tokenString
}

func unsignedOAuthValidatorTestToken(t *testing.T, claims jwtlib.MapClaims) string {
	t.Helper()

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed creating unsigned token: %v", err)
	}
	return tokenString
}

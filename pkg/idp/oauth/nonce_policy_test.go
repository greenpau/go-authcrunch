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
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func TestValidateAccessTokenUsesTransactionNoncePolicy(t *testing.T) {
	newClaims := func() jwtlib.MapClaims {
		return jwtlib.MapClaims{
			"aud": oauthValidatorTestClientID, "email": "user@example.com",
			"exp": time.Now().Add(time.Hour).Unix(), "iss": oauthValidatorTestIssuer,
			"name": "Valid User", "roles": []string{"viewer"}, "sub": "subject-user",
		}
	}
	tests := []struct {
		name, storedNonce string
		mutateClaims      func(jwtlib.MapClaims)
		providerFlag      bool
		tamperSignature   bool
		wantErr           bool
	}{
		{name: "disabled transaction accepts omitted nonce after flag changes", providerFlag: false},
		{name: "enabled transaction rejects missing nonce after flag changes", storedNonce: "expected-nonce", providerFlag: true, wantErr: true},
		{name: "enabled transaction rejects wrong nonce", storedNonce: "expected-nonce", providerFlag: true, mutateClaims: func(claims jwtlib.MapClaims) { claims["nonce"] = "wrong-nonce" }, wantErr: true},
		{name: "disabled transaction still enforces issuer", providerFlag: false, mutateClaims: func(claims jwtlib.MapClaims) { claims["iss"] = "https://wrong.example" }, wantErr: true},
		{name: "disabled transaction still enforces audience", providerFlag: false, mutateClaims: func(claims jwtlib.MapClaims) { claims["aud"] = "wrong-client" }, wantErr: true},
		{name: "disabled transaction still enforces signature", providerFlag: false, tamperSignature: true, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, privateKey, jwksKey := newOAuthValidatorTestProvider(t, "id_token")
			const state = "transaction-state"
			if err := provider.state.addLogin(state, tc.storedNonce, "verifier", "browser", "https://portal.example/callback"); err != nil {
				t.Fatal(err)
			}
			// The callback must use the policy captured at initiation, not a
			// provider flag that may have changed since the redirect.
			provider.disableNonce = tc.providerFlag
			claims := newClaims()
			if tc.mutateClaims != nil {
				tc.mutateClaims(claims)
			}
			token := signOAuthValidatorTestToken(t, privateKey, jwksKey.KeyID, claims)
			if tc.tamperSignature {
				parts := strings.Split(token, ".")
				if len(parts) != 3 || parts[2] == "" {
					t.Fatal("fixture produced malformed JWT")
				}
				first := parts[2][0]
				replacement := byte('A')
				if first == replacement {
					replacement = 'B'
				}
				parts[2] = string(replacement) + parts[2][1:]
				token = strings.Join(parts, ".")
			}
			got, err := provider.validateAccessToken(t.Context(), state, map[string]any{"id_token": token, "access_token": "opaque"})
			if tc.wantErr {
				if err == nil {
					t.Fatal("token unexpectedly accepted")
				}
				return
			}
			if err != nil || got["sub"] != "subject-user" {
				t.Fatalf("disabled-nonce token rejected: claims=%v error=%v", got, err)
			}
		})
	}
}

func TestStateBindingCapturesNonceRequirement(t *testing.T) {
	for _, tc := range []struct {
		name, nonce string
		required    bool
	}{
		{name: "enabled", nonce: "nonce", required: true},
		{name: "disabled", required: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := newStateManager()
			if err := sm.addLogin("state", tc.nonce, "verifier", "browser", "https://portal.example/callback"); err != nil {
				t.Fatal(err)
			}
			if !tc.required {
				if sm.beginCallback("state", "browser", "https://portal.example/wrong-callback") {
					t.Fatal("disabled nonce weakened callback binding")
				}
				if !sm.beginCallback("state", "browser", "https://portal.example/callback") {
					t.Fatal("wrong callback consumed disabled-nonce transaction")
				}
			}
			required, err := sm.requiresNonce("state")
			if err != nil || required != tc.required {
				t.Fatalf("requiresNonce() = %t, %v; want %t", required, err, tc.required)
			}
		})
	}
}

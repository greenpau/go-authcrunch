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

package openapi

import (
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/validators"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/system"
	"github.com/greenpau/go-authcrunch/pkg/tagging"
)

func repositoryDocument(t *testing.T) map[string]any {
	t.Helper()
	data, err := Bundle(filepath.Join("..", "..", "assets/openapi/content"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestRepositoryFieldConstraints(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	canonical := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name, schema string
		value        any
		valid        bool
	}{
		{"unix seconds beyond 2038", "UnixTime", int64(2208988800), true},
		{"unix string rejected", "UnixTime", "1791331200", false},
		{"fractional issued time rejected", "Claims/properties/iat", 1791331200.5, false},
		{"expiry is numeric", "Claims/properties/exp", 1791334800, true},
		{"probe duration can be zero", "Claims/properties/expires_in", 0, true},
		{"refresh format", "PortalRefreshToken", "acr1_" + canonical, true},
		{"OIDC token is not portal refresh", "PortalRefreshToken", canonical, false},
		{"padding rejected", "OIDCOpaqueToken", canonical + "=", false},
		{"noncanonical final bits", "OIDCOpaqueToken", canonical[:42] + "B", false},
		{"session hex", "PortalSessionID", strings.Repeat("a", 64), true},
		{"session uppercase rejected", "PortalSessionID", strings.Repeat("A", 64), false},
		{"raw API key", "ProfileAddUserApiKey/properties/content", strings.Repeat("k", 64), true},
		{"trimmed API key", "ProfileAddUserApiKey/properties/content", "\u2003" + strings.Repeat("k", 72) + "\n", true},
		{"short API key", "ProfileAddUserApiKey/properties/content", strings.Repeat("k", 63), false},
		{"punctuated API key", "ProfileAddUserApiKey/properties/content", strings.Repeat("k", 63) + "!", false},
		{"TOTP leading zero", "ProfileTestUserAppTokenPasscode/properties/passcode", "012345", true},
		{"numeric TOTP rejected", "ProfileTestUserAppTokenPasscode/properties/passcode", 123456, false},
		{"TOTP punctuation", "ProfileTestUserAppTokenPasscode/properties/passcode", "123-45", false},
		{"TOTP saved period", "ProfileAddUserAppMultiFactorAuthenticator/properties/period", 30, true},
		{"TOTP fractional period is truncated", "ProfileAddUserAppMultiFactorAuthenticator/properties/period", 30.75, true},
		{"TOTP next integer period fails", "ProfileAddUserAppMultiFactorAuthenticator/properties/period", 31, false},
		{"TOTP numeric string fails", "ProfileAddUserAppMultiFactorAuthenticator/properties/period", "30", false},
		{"TOTP fractional width is truncated", "ProfileFetchUserAppMultiFactorAuthenticatorCode/properties/digits", 6.5, true},
		{"TOTP downstream save limit", "ProfileAddUserAppMultiFactorAuthenticator/properties/period", 15, false},
		{"TOTP QR downstream limit", "ProfileFetchUserAppMultiFactorAuthenticatorCode/properties/period", 15, false},
		{"TOTP diagnostic period", "ProfileTestUserAppMultiFactorAuthenticator/properties/period", 15, true},
		{"TOTP secret lower boundary", "ProfileAddUserAppMultiFactorAuthenticator/properties/secret", "abcdefghij", true},
		{"TOTP secret too short", "ProfileAddUserAppMultiFactorAuthenticator/properties/secret", "abcdefghi", false},
		{"TOTP title punctuation", "ProfileAddUserAppMultiFactorAuthenticator/properties/title", "my-token", false},
		{"API key title punctuation", "ProfileAddUserApiKey/properties/title", "key@example.test (work)", true},
		{"empty description allowed", "ProfileAddUserApiKey/properties/description", "", true},
		{"short nonempty description", "ProfileAddUserApiKey/properties/description", "ab", false},
		{"ASCII description whitespace", "ProfileAddUserApiKey/properties/description", "a\nb", true},
		{"Unicode description whitespace", "ProfileAddUserApiKey/properties/description", "a\u00a0b", false},
		{"tag needs value", "ProfileAddUserApiKey/properties/tags", []any{map[string]any{"key": "site"}}, false},
		{"empty tag values allowed", "ProfileAddUserApiKey/properties/tags", []any{map[string]any{"key": "", "value": ""}}, true},
		{"self-service hash import", "ProfileUpdateUserPassword/properties/new_password", "\u2003bcrypt:10:invalid", false},
		{"self-service plaintext", "ProfileUpdateUserPassword/properties/new_password", "example-plaintext", true},
		{"duplicate challenge rules", "ProfileOverwriteUserAuthChallenges/properties/challenges", []any{"password", "password"}, false},
		{"multiline challenge rule", "ProfileOverwriteUserAuthChallenges/properties/challenges/items", "password\ntotp", false},
		{"PKCE minimum verifier", "OIDCCodeExchange/properties/code_verifier", strings.Repeat("~", 43), true},
		{"PKCE maximum verifier", "OIDCCodeExchange/properties/code_verifier", strings.Repeat(".", 128), true},
		{"PKCE short verifier", "OIDCCodeExchange/properties/code_verifier", strings.Repeat("a", 42), false},
		{"PKCE long verifier", "OIDCCodeExchange/properties/code_verifier", strings.Repeat("a", 129), false},
		{"PKCE invalid alphabet", "OIDCCodeExchange/properties/code_verifier", strings.Repeat("+", 43), false},
		{"PKCE challenge", "OIDCAuthorizationRequest/properties/code_challenge", canonical, true},
		{"PKCE noncanonical challenge", "OIDCAuthorizationRequest/properties/code_challenge", canonical[:42] + "B", false},
		{"prompt none alone", "OIDCAuthorizationRequest/properties/prompt", " none ", true},
		{"prompt multiple", "OIDCAuthorizationRequest/properties/prompt", "login consent", true},
		{"prompt Unicode whitespace", "OIDCAuthorizationRequest/properties/prompt", "\u0085login\u2003consent\u00a0", true},
		{"prompt BOM is not whitespace", "OIDCAuthorizationRequest/properties/prompt", "\ufefflogin", false},
		{"prompt none conflict", "OIDCAuthorizationRequest/properties/prompt", "none login", false},
		{"terms acceptance is configuration dependent", "RegistrationRequest/properties/accept_terms", "off", true},
		{"cross-device code", "CrossDeviceStart/properties/code", strings.Repeat("A", 26), true},
		{"cross-device alphabet", "CrossDeviceStart/properties/code", strings.Repeat("0", 26), false},
		{"approval requires redirect", "CrossDeviceApproved", map[string]any{"status": "approved"}, false},
		{"approval accepts absolute portal target", "CrossDeviceApproved", map[string]any{"status": "approved", "next": "https://app.example.test/"}, true},
		{"pending cannot contain bearer credentials", "CrossDevicePending", map[string]any{"status": "pending", "access_token": "synthetic"}, false},
		{"cancellation is a distinct state", "CrossDeviceCancelled", map[string]any{"status": "unavailable"}, false},
		{"login WebAuthn transports are strings", "LoginWebAuthnOptions/properties/credentials/items/properties/transports", "usb,nfc", true},
		{"enrollment transport array is not login format", "LoginWebAuthnOptions/properties/credentials/items/properties/transports", []any{"usb"}, false},
		{"login challenge is not enrollment challenge", "LoginWebAuthnOptions/properties/challenge", canonical, false},
		{"login WebAuthn challenge", "LoginWebAuthnOptions/properties/challenge", strings.Repeat("a", 64), true},
		{"WebAuthn cross-origin assertions rejected", "WebAuthnAssertionClientData", map[string]any{"type": "webauthn.get", "crossOrigin": true}, false},
		{"WebAuthn creation is not assertion", "WebAuthnAssertionClientData", map[string]any{"type": "webauthn.create"}, false},
		{"parsed fields cannot replace signed bytes", "WebAuthnAssertion", map[string]any{"id": "synthetic", "client_data": map[string]any{"type": "webauthn.get"}}, false},
		{"SAML response needs RelayState", "SAMLCallback", map[string]any{"SAMLResponse": "PHhtbC8+"}, false},
		{"SAML RelayState canonical encoding", "SAMLRelayState", canonical, true},
		{"SAML RelayState padding rejected", "SAMLRelayState", canonical + "=", false},
		{"SAML RelayState is not an OAuth UUID", "SAMLRelayState", "dc219134-9565-4d5f-90b7-54e02a4bb301", false},
		{"claim request can be null", "OIDCClaimRequirement", nil, true},
		{"claim essential must be boolean", "OIDCClaimRequirement", map[string]any{"essential": "true"}, false},
		{"claim values cannot conflict", "OIDCClaimRequirement", map[string]any{"value": "one", "values": []any{"two"}}, false},
		{"claim value cannot be null", "OIDCClaimRequirement", map[string]any{"value": nil}, false},
		{"general claim alternatives may include null", "OIDCClaimRequirement", map[string]any{"values": []any{nil}}, true},
		{"empty claim alternatives rejected", "OIDCClaimRequirement", map[string]any{"values": []any{}}, false},
		{"identity claim requires strings", "OIDCIdentityClaimRequirement", map[string]any{"values": []any{nil}}, false},
		{"empty subject selector rejected", "OIDCClaimsRequest", map[string]any{"id_token": map[string]any{"sub": map[string]any{"value": ""}}}, false},
		{"unknown claims still require valid shape", "OIDCClaimsRequest", map[string]any{"userinfo": map[string]any{"unknown": true}}, false},
		{"unknown top-level locations ignored", "OIDCClaimsRequest", map[string]any{"extension": 123}, true},
		{"claim location must be object", "OIDCClaimsRequest", map[string]any{"userinfo": nil}, false},
		{"Request Object allows fractional NumericDate", "OIDCRequestObjectPayload/properties/iat", 1791331200.5, true},
		{"Request Object forbids negative NumericDate", "OIDCRequestObjectPayload/properties/iat", -0.5, false},
		{"Request Object forbids string NumericDate", "OIDCRequestObjectPayload/properties/exp", "1791331200", false},
		{"Request Object claims are embedded JSON", "OIDCRequestObjectPayload/properties/claims", `{"id_token":{"auth_time":null}}`, false},
		{"nested Request Object forbidden", "OIDCRequestObjectPayload", map[string]any{"request": "nested"}, false},
		{"Request Object jti type is not validated", "OIDCRequestObjectPayload", map[string]any{"jti": []any{false}}, true},
		{"Request Object audience null entry is tolerated", "OIDCRequestObjectPayload/properties/aud", []any{nil, "https://auth.example.test/auth"}, true},
		{"Request Object audience numeric entry rejected", "OIDCRequestObjectPayload/properties/aud", []any{123, "https://auth.example.test/auth"}, false},
		{"unsecured Request Object header", "OIDCRequestObjectHeader", map[string]any{"alg": "none"}, true},
		{"unsecured Request Object cannot select key", "OIDCRequestObjectHeader", map[string]any{"alg": "none", "kid": "key"}, false},
		{"registered RSA key can be selected implicitly", "OIDCRequestObjectHeader", map[string]any{"alg": "RS256"}, true},
		{"empty Request Object key ID rejected", "OIDCRequestObjectHeader", map[string]any{"alg": "RS256", "kid": ""}, false},
		{"remote Request Object key forbidden", "OIDCRequestObjectHeader", map[string]any{"alg": "RS256", "jku": "https://example.test/keys"}, false},
		{"Request Object critical header forbidden", "OIDCRequestObjectHeader", map[string]any{"alg": "RS256", "crit": []any{}}, false},
		{"RSA needs exponent", "PublicJWK", map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "n": "AQAB"}, false},
		{"public key forbids private material", "PublicJWK", map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "n": "AQAB", "e": "AQAB", "d": "secret"}, false},
		{"private key requires secret", "PrivateJWK", map[string]any{"kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256", "x": canonical, "y": canonical}, false},
		{"private RSA needs prime factors", "PrivateJWK", map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "n": "AQAB", "e": "AQAB", "d": canonical}, false},
		{"Ed25519 exports seed", "PrivateJWK", map[string]any{"kty": "OKP", "use": "sig", "alg": "EdDSA", "crv": "Ed25519", "x": canonical, "d": canonical}, true},
		{"Ed25519 does not export 64-byte secret", "PrivateJWK", map[string]any{"kty": "OKP", "use": "sig", "alg": "EdDSA", "crv": "Ed25519", "x": canonical, "d": base64.RawURLEncoding.EncodeToString(make([]byte, 64))}, false},
		{"profile serialized error", "ProfileResult", map[string]any{"status": 400, "timestamp": "2026-10-07T00:00:00Z", "message": map[string]any{}}, true},
		{"profile message cannot be a number", "ProfileResult/properties/message", 400, false},
		{"profile entry is not an arbitrary array", "ProfileResult/properties/entry", []any{}, false},
		{"profile diagnostic can fail with 200", "ProfileDiagnostic", map[string]any{"success": false}, true},
		{"QR URI is not an image", "ProfileTOTPEnrollment/properties/uri", "data:image/png;base64,AA==", false},
		{"WebAuthn timeout in milliseconds", "ProfileWebAuthnVerification/properties/timeout", 60000, true},
		{"WebAuthn timeout not seconds", "ProfileWebAuthnVerification/properties/timeout", 60, false},
		{"WebAuthn unsigned counter", "ProfileAuthenticatorRecord/allOf/1/properties/signature_counter", -1, false},
		{"admin failure needs detail", "AdminUserMutation", map[string]any{"status": "failure", "timestamp": "2026-10-07T00:00:00Z"}, false},
		{"unknown admin realm is null", "AdminUserResult", nil, true},
		{"OIDC address preserves postal zeros", "IdentityAddress/properties/postal_code", "00123", true},
		{"OIDC postal code is not numeric", "IdentityAddress/properties/postal_code", 123, false},
		{"System endpoint rejects plaintext JSON", "SystemEncryptedMessage", `{"kind":"basic_auth_request"}`, false},
		{"OIDC access token hash final bits", "OIDCIDTokenClaims/properties/at_hash", base64.RawURLEncoding.EncodeToString(make([]byte, 16)), true},
		{"OIDC noncanonical access token hash", "OIDCIDTokenClaims/properties/at_hash", strings.Repeat("A", 21) + "B", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema, err := SchemaAt(c, "/components/schemas/"+tc.schema)
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonValue(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if valid := schema.Validate(value) == nil; valid != tc.valid {
				t.Fatalf("schema accepted=%v; expected=%v (input withheld)", valid, tc.valid)
			}
		})
	}
}

func TestRepositoryClientSecretByteLength(t *testing.T) {
	// Eight four-byte characters satisfy the registration's 32-byte minimum.
	// A JSON Schema minLength: 32 would incorrectly reject this valid secret.
	secret := strings.Repeat("\U0001f511", 8)
	client := &oidc.ClientConfig{ClientID: "contract", ClientSecret: secret, TokenEndpointAuthMethod: "client_secret_post", RedirectURIs: []string{"https://rp.example.test/callback"}}
	if err := client.Validate(); err != nil {
		t.Fatal("selected registration rejected the synthetic byte-boundary secret")
	}
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"OIDCCodeExchange", "OIDCRefreshExchange"} {
		schema, err := SchemaAt(c, "/components/schemas/"+name+"/properties/client_secret")
		if err != nil || schema.Validate(secret) != nil {
			t.Fatal("schema applied a character minimum to a byte-limited secret")
		}
	}
}

// Validate selected-module serializers, including zero time and omitempty
// behavior. Request validators alone do not establish the returned wire shape.
func TestRepositoryCredentialSerializers(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(strings.Repeat("A1", 32)), 10)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewAPIKey(&requests.Request{Key: requests.Key{Usage: "api", Payload: string(hash), Prefix: strings.Repeat("A1", 12), Comment: "Example"}})
	if err != nil {
		t.Fatal("could not create synthetic credential")
	}
	key.Tags = []tagging.Tag{{Key: "", Value: ""}}
	token, err := identity.NewMfaToken(&requests.Request{MfaToken: requests.MfaToken{Type: "totp", Secret: "SyntheticSecret123", Period: 30, Digits: 6, SkipVerification: true}})
	if err != nil {
		t.Fatal("could not create synthetic authenticator")
	}
	usr := &identity.User{ID: "synthetic-user-id", Username: "alice", APIKeys: []*identity.APIKey{key}, MfaTokens: []*identity.MfaToken{token}}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"ProfileAPIKeyRecord", key}, {"ProfileAuthenticatorRecord", token},
		{"AdminUserRecord", usr}, {"UserMetadata", usr.GetMetadata()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema, err := SchemaAt(c, "/components/schemas/"+tc.name)
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonValue(tc.value)
			if err != nil || schema.Validate(value) != nil {
				t.Fatal("selected serializer disagrees with response schema (value withheld)")
			}
		})
	}
}

func TestRepositorySystemMessages(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := system.NewEncryptor("contract-test", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		message system.Message
	}{
		{"SystemBasicAuthMessage", &system.BasicAuthRequestMessage{Kind: system.BasicAuthRequestKindKeyword, Username: "alice", Password: "synthetic-password", Realm: "local", Address: "caller-supplied-address"}},
		{"SystemAPIKeyAuthMessage", &system.APIKeyAuthRequestMessage{Kind: system.APIKeyAuthRequestKindKeyword, APIKey: "synthetic-key", Realm: "local", Address: "198.51.100.10"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.message.Validate(); err != nil {
				t.Fatal("synthetic message did not pass selected validator")
			}
			value, err := jsonValue(tc.message)
			if err != nil {
				t.Fatal(err)
			}
			schema, err := SchemaAt(c, "/components/schemas/"+tc.name)
			if err != nil || schema.Validate(value) != nil {
				t.Fatal("inner message schema mismatch")
			}
			wire, err := enc.EncryptMessage(tc.message)
			if err != nil {
				t.Fatal("could not encrypt synthetic message")
			}
			schema, err = SchemaAt(c, "/components/schemas/SystemEncryptedMessage")
			if err != nil || schema.Validate(wire) != nil {
				t.Fatal("encrypted message schema mismatch")
			}
			if _, err := enc.DecryptMessage(wire); err != nil {
				t.Fatal("synthetic message did not round trip")
			}
			delete(value.(map[string]any), "address")
			schema, err = SchemaAt(c, "/components/schemas/"+tc.name)
			if err != nil || schema.Validate(value) == nil {
				t.Fatal("missing required address was accepted")
			}
		})
	}
}

// Compare the authored registration patterns against the actual exported
// validators, including boundaries that are easy to over-constrain by assuming
// every email domain needs a dot or every username follows local-store policy.
func TestRegistrationSchemaMatchesValidators(t *testing.T) {
	c, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		field, validator string
		values           []string
	}{
		{"registrant", "handle", []string{"a", "alice1", strings.Repeat("a", 25), "", "Alice", "İ", "K", "a-b", strings.Repeat("a", 26)}},
		{"registrant_email", "email", []string{"a@b", "alice+tag@example.test", "a@-example.test", "a b@example.test", "invalid", ""}},
		{"registrant_password", "secret", []string{"example-password", strings.Repeat("a", 255), strings.Repeat("a", 256), "", "bcrypt:10:hash", " argon2:hash"}},
	} {
		schema, err := SchemaAt(c, "/components/schemas/RegistrationRequest/properties/"+tc.field)
		if err != nil {
			t.Fatal(err)
		}
		for i, value := range tc.values {
			t.Run(tc.field+"/"+strconv.Itoa(i), func(t *testing.T) {
				accepted := validators.ValidateUserInput(tc.validator, value, nil) == nil
				if (schema.Validate(value) == nil) != accepted {
					t.Fatal("registration schema disagrees with the selected validator (input withheld)")
				}
			})
		}
	}
}

func TestRepositorySchemaExamplesAndEvidence(t *testing.T) {
	doc := repositoryDocument(t)
	c, err := SchemaCompiler(doc)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := Sources(t.Context(), filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"pkg/util/random.go", "pkg/util/validate/login_hint.go", "pkg/util/charset/utils.go", "pkg/authn/validators/user_input.go", "pkg/identity/qr/qr.go"} {
		if sources.Files[file] == "" {
			t.Errorf("missing validator/generator review coverage for %s", file)
		}
	}
	var walk func(any, string)
	walk = func(value any, location string) {
		switch v := value.(type) {
		case map[string]any:
			if samples, ok := v["examples"].([]any); ok {
				schema, err := SchemaAt(c, location)
				if err != nil {
					t.Fatal(err)
				}
				for _, sample := range samples {
					sample, err := jsonValue(sample)
					if err != nil || schema.Validate(sample) != nil {
						t.Errorf("invalid schema example at %s", location)
					}
				}
			}
			for _, file := range array(v["x-source-files"]) {
				if sources.Files[file.(string)] == "" {
					t.Errorf("unreviewed schema evidence %s at %s", file, location)
				}
			}
			for k, child := range v {
				if k != "examples" && k != "const" && !strings.HasPrefix(k, "x-") {
					walk(child, location+"/"+escape(k))
				}
			}
		case []any:
			for i, child := range v {
				walk(child, location+"/"+strconv.Itoa(i))
			}
		}
	}
	walk(object(object(doc["components"])["schemas"]), "/components/schemas")
}

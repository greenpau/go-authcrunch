// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/greenpau/go-authcrunch/internal/openapi"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/system"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testOpenAPIGenericContracts(t *testing.T, validate openAPIResponseValidator, validateComponent func(*testing.T, string, any)) {
	data, err := openapi.Bundle("../../assets/openapi/content")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	compiler, err := openapi.SchemaCompiler(doc)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("administration_and_profile", func(t *testing.T) {
		f := newOpenAPIPortalFixture(t, "/auth", "enable admin api", true)
		admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
		for _, tc := range []struct {
			method, path, token, body string
			status                    int
		}{
			{"GET", "/.well-known/jwks.json", "", "", 200},
			{"HEAD", "/.well-known/jwks.json", "", "", 200},
			{"GET", "/whoami", admin, "", 200},
			{"GET", "/whoami", "", "", 401},
			{"GET", "/beacon", admin, "", 200},
			{"GET", "/beacon", "", "", 401},
			{"GET", "/api/server/metadata", admin, "", 200},
			{"GET", "/api/server/metadata", member, "", 403},
			{"GET", "/api/server/metadata", "invalid-contract-token", "", 401},
			{"GET", "/api/server/private_keys", admin, "", 404},
			{"POST", "/api/server/realms", admin, `{"query":"all"}`, 200},
			{"POST", "/api/server/users", admin, `{"realm":"local","query":"all"}`, 200},
			{"POST", "/api/server/info", admin, `{"realm":"local"}`, 200},
			{"POST", "/api/server/info", admin, `{"realm":"missing"}`, 404},
			{"POST", "/api/server/user", admin, `{"realm":"local","operation":"info","user":{"username":"keymember","email":"keymember@example.test"}}`, 200},
			{"POST", "/api/profile", member, `{"kind":"fetch_user_info"}`, 200},
			{"POST", "/api/profile", member, `{"kind":"fetch_user_auth_challenges"}`, 200},
			{"POST", "/api/profile", member, `{"kind":"fetch_user_ssh_keys"}`, 200},
			{"POST", "/api/profile", member, `{"kind":"unknown"}`, 400},
		} {
			t.Run(tc.method+tc.path+"/"+strconv.Itoa(tc.status), func(t *testing.T) {
				header, body := f.request(t, tc.method, tc.path, tc.token, tc.body, tc.status)
				validate(t, tc.path, tc.method, tc.status, header, body)
			})
		}
		t.Run("claim_time_units", func(t *testing.T) {
			header, body := f.request(t, "GET", "/whoami?probe=true", member, "", 200)
			validate(t, "/whoami", "GET", 200, header, body)
			var claims map[string]any
			if json.Unmarshal(body, &claims) != nil {
				t.Fatal("invalid claims response")
			}
			now := float64(time.Now().Unix())
			for _, name := range []string{"iat", "nbf", "exp"} {
				value, ok := claims[name].(float64)
				if !ok || value < now-3600 || value > now+86400 {
					t.Fatalf("%s does not use Unix seconds", name)
				}
			}
			remaining, ok := claims["expires_in"].(float64)
			if !ok || remaining < 0 || remaining > 86400 || claims["authenticated"] != true {
				t.Fatal("probe did not return an authenticated duration in seconds")
			}
		})
		t.Run("profile_field_validators", func(t *testing.T) {
			// Every candidate is checked against the authored request schema and
			// sent through the native TLS handler. This catches constraints that
			// look plausible in YAML but differ from downstream credential logic.
			key := strings.Repeat("K", 64)
			for _, tc := range []struct {
				name, schema string
				input        map[string]any
				status       int
			}{
				{"short API key", "ProfileAddUserApiKey", map[string]any{"kind": "add_user_api_key", "content": "short", "title": "Example", "description": ""}, 400},
				{"invalid key title", "ProfileAddUserApiKey", map[string]any{"kind": "add_user_api_key", "content": key, "title": "bad!", "description": ""}, 400},
				{"short description", "ProfileAddUserApiKey", map[string]any{"kind": "add_user_api_key", "content": key, "title": "Example", "description": "ab"}, 400},
				{"missing tag value", "ProfileAddUserApiKey", map[string]any{"kind": "add_user_api_key", "content": key, "title": "Example", "description": "", "tags": []any{map[string]any{"key": "site"}}}, 400},
				{"downstream TOTP period", "ProfileAddUserAppMultiFactorAuthenticator", map[string]any{"kind": "add_user_app_multi_factor_authenticator", "period": 15, "digits": 6, "title": "Example", "description": "", "secret": "SyntheticSecret123"}, 400},
				{"downstream QR period", "ProfileFetchUserAppMultiFactorAuthenticatorCode", map[string]any{"kind": "fetch_user_app_multi_factor_authenticator_code", "period": 15, "digits": 6, "issuer": "Example", "secret": "SyntheticSecret123"}, 400},
				{"short TOTP secret", "ProfileFetchUserAppMultiFactorAuthenticatorCode", map[string]any{"kind": "fetch_user_app_multi_factor_authenticator_code", "period": 30, "digits": 6, "issuer": "Example", "secret": "short"}, 400},
				{"duplicate challenge rules", "ProfileOverwriteUserAuthChallenges", map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{"password", "password"}}, 400},
				{"TOTP enrollment", "ProfileFetchUserAppMultiFactorAuthenticatorCode", map[string]any{"kind": "fetch_user_app_multi_factor_authenticator_code", "period": 30, "digits": 6, "issuer": "Example", "secret": "SyntheticSecret123"}, 200},
				{"fractional TOTP values truncate", "ProfileFetchUserAppMultiFactorAuthenticatorCode", map[string]any{"kind": "fetch_user_app_multi_factor_authenticator_code", "period": 30.75, "digits": 6.5, "issuer": "Example", "secret": "SyntheticSecret123"}, 200},
				{"trimmed key with empty description", "ProfileAddUserApiKey", map[string]any{"kind": "add_user_api_key", "content": "\u2003" + key + "\n", "title": "Example", "description": "", "tags": []any{map[string]any{"key": "", "value": ""}}}, 200},
			} {
				t.Run(tc.name, func(t *testing.T) {
					schema, err := openapi.SchemaAt(compiler, "/components/schemas/"+tc.schema)
					if err != nil {
						t.Fatal(err)
					}
					raw, err := json.Marshal(tc.input)
					if err != nil {
						t.Fatal("could not encode synthetic profile request")
					}
					value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
					if err != nil || (schema.Validate(value) == nil) != (tc.status == 200) {
						t.Fatal("request schema disagrees with the expected handler validation")
					}
					header, body := f.request(t, "POST", "/api/profile", member, string(raw), tc.status)
					validate(t, "/api/profile", "POST", tc.status, header, body)
				})
			}
		})
		t.Run("profile_returned_records", func(t *testing.T) {
			member = f.login(t, "keymember")
			call := func(input string, status int) map[string]any {
				header, body := f.request(t, "POST", "/api/profile", member, input, status)
				validate(t, "/api/profile", "POST", status, header, body)
				var result map[string]any
				if json.Unmarshal(body, &result) != nil {
					t.Fatal("invalid profile JSON")
				}
				return result
			}
			info := call(`{"kind":"fetch_user_info"}`, 200)["entry"].(map[string]any)
			validateComponent(t, "ProfileUserInfo", info)
			var claims map[string]any
			if json.Unmarshal([]byte(info["token"].(string)), &claims) != nil || claims["authenticated"] != true {
				t.Fatal("profile token is not encoded claims JSON")
			}
			dashboard := call(`{"kind":"fetch_user_dashboard_data"}`, 200)["entry"]
			validateComponent(t, "ProfileDashboard", dashboard)
			for _, kind := range []string{"fetch_debug", "fetch_user_multi_factor_authenticators", "fetch_user_gpg_keys"} {
				call(`{"kind":"`+kind+`"}`, 200)
			}
			keys := call(`{"kind":"fetch_user_api_keys"}`, 200)["entries"].([]any)
			if len(keys) != 1 {
				t.Fatal("expected the enrolled API-key record")
			}
			record := keys[0].(map[string]any)
			validateComponent(t, "ProfileAPIKeyRecord", record)
			if bcrypt.CompareHashAndPassword([]byte(record["payload"].(string)), []byte(strings.Repeat("K", 64))) != nil {
				t.Fatal("profile API-key payload is not the stored hash")
			}
			if record["expired_at"] != "0001-01-01T00:00:00Z" || record["disabled_at"] != "0001-01-01T00:00:00Z" {
				t.Fatal("unset credential timestamps have an undocumented representation")
			}
			if len(record["tags"].([]any)[0].(map[string]any)) != 0 {
				t.Fatal("empty tag strings were not omitted")
			}
			input, _ := json.Marshal(map[string]any{"kind": "fetch_user_api_key", "id": record["id"]})
			call(string(input), 200)
			qr := call(`{"kind":"fetch_user_app_multi_factor_authenticator_code","period":30.75,"digits":6.5,"issuer":"Example","secret":"SyntheticSecret123"}`, 200)["entry"].(map[string]any)
			decoded, err := base64.StdEncoding.DecodeString(qr["uri_encoded"].(string))
			if err != nil || string(decoded) != qr["uri"] {
				t.Fatal("TOTP URI encoding differs from the contract")
			}
			u, err := url.Parse(string(decoded))
			if err != nil || u.Scheme != "otpauth" || u.Query().Get("period") != "30" || u.Query().Get("digits") != "6" {
				t.Fatal("TOTP numeric normalization differs from the contract")
			}
			check := call(`{"kind":"test_user_app_multi_factor_authenticator","period":30,"digits":8,"secret":"SyntheticSecret123","passcode":"0000"}`, 200)["entry"].(map[string]any)
			if check["success"] != false {
				t.Fatal("incorrect TOTP code did not produce success=false")
			}
			creation := call(`{"kind":"fetch_user_u2f_reg_params"}`, 200)["entry"]
			validateComponent(t, "ProfileWebAuthnCreation", creation)
			failure := call(`{"kind":"fetch_user_u2f_ver_params","webauthn_register":"invalid","webauthn_challenge":"missing"}`, 400)
			if value, ok := failure["message"].(map[string]any); !ok || len(value) != 0 {
				t.Fatal("WebAuthn error serialization differs from the contract")
			}
		})
	})
	t.Run("encrypted_system_messages", func(t *testing.T) {
		const keyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		f := newOpenAPIPortalFixture(t, "/auth", "crypto key internal system "+keyHex, true)
		secret, err := system.ParseKeyFromString(keyHex)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := system.NewEncryptor("internal", secret)
		if err != nil {
			t.Fatal(err)
		}
		for _, password := range []string{tests.TestPwd1, "incorrect-contract-password"} {
			message := &system.BasicAuthRequestMessage{Kind: system.BasicAuthRequestKindKeyword, Realm: "local", Username: "keymember", Password: password, Address: "198.51.100.10"}
			wire, err := enc.EncryptMessage(message)
			if err != nil {
				t.Fatal("could not encrypt synthetic request")
			}
			validateComponent(t, "SystemEncryptedMessage", wire)
			status := 200
			if password != tests.TestPwd1 {
				status = 401
			}
			header, body := f.request(t, "POST", "/api/system", "", wire, status, http.Header{"Content-Type": []string{"text/plain"}})
			validate(t, "/api/system", "POST", status, header, body)
			if status != 200 {
				continue
			}
			response, err := enc.DecryptMessage(string(body))
			if err != nil {
				t.Fatal("could not decrypt System API response")
			}
			raw, err := response.ToJSON()
			if err != nil {
				t.Fatal("could not serialize System API response")
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal("invalid inner response JSON")
			}
			validateComponent(t, "SystemAuthResponseMessage", value)
		}
	})
}

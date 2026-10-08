// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testOpenAPICredentials(t *testing.T, validate openAPIResponseValidator, component func(*testing.T, string, any)) {
	f := newOpenAPIPortalFixture(t, "/auth", "enable admin api", true)
	token := f.login(t, "keymember")
	profile := func(input map[string]any, want int) map[string]any {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		h, body := f.request(t, "POST", "/api/profile", token, string(raw), want)
		validate(t, "/api/profile", "POST", want, h, body)
		var result map[string]any
		if err = json.Unmarshal(body, &result); err != nil {
			t.Fatal("invalid profile response")
		}
		return result
	}
	t.Run("api_key_verifier_and_deletion", func(t *testing.T) {
		raw := strings.Repeat("Abcd1234", 9)
		input := map[string]any{"kind": "add_user_api_key", "title": "VerifierKey", "description": "", "content": " \t" + raw + "\n"}
		component(t, "ProfileAddUserApiKey", input)
		profile(input, 200)
		listing := profile(map[string]any{"kind": "fetch_user_api_keys"}, 200)
		entries := listing["entries"].([]any)
		if len(entries) != 1 {
			t.Fatal("API-key enrollment inventory changed")
		}
		record := entries[0].(map[string]any)
		component(t, "ProfileAPIKeyRecord", record)
		hash := record["payload"].(string)
		if record["prefix"] != raw[:24] || len(record["id"].(string)) != 40 || bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)) != nil {
			t.Fatal("enrollment verifier contract changed")
		}
		if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost != 10 {
			t.Fatal("API-key cost changed")
		}
		for _, candidate := range []string{raw, raw + "suffix"} {
			result := profile(map[string]any{"kind": "test_user_api_key", "id": record["id"], "content": candidate}, 200)
			if result["entry"] != "OK" {
				t.Fatal("API-key diagnostic result changed")
			}
		}
		profile(map[string]any{"kind": "test_user_api_key", "id": record["id"], "content": " " + raw}, 500)
		profile(map[string]any{"kind": "test_user_api_key", "id": "foreign-id", "content": raw}, 500)
		login := func(candidate string, want int) map[string]any {
			t.Helper()
			input := map[string]any{"realm": "local", "api_key": candidate}
			rawBody, _ := json.Marshal(input)
			h, body := f.request(t, "POST", "/login", "", string(rawBody), want)
			validate(t, "/login", "POST", want, h, body)
			var result map[string]any
			if json.Unmarshal(body, &result) != nil {
				t.Fatal("invalid API-key login response")
			}
			return result
		}
		login(raw+"suffix", 401)
		issued := login(raw, 200)
		if issued["authenticated"] != true {
			t.Fatal("API-key did not authenticate")
		}
		copied := issued["access_token"].(string)
		profile(map[string]any{"kind": "delete_user_api_key", "id": record["id"]}, 200)
		profile(map[string]any{"kind": "fetch_user_api_key", "id": record["id"]}, 500)
		login(raw, 401)
		h, body := f.request(t, "GET", "/whoami", copied, "", 200)
		validate(t, "/whoami", "GET", 200, h, body)
	})
	t.Run("totp_save_and_stateless_diagnostic", func(t *testing.T) {
		const secret = "SyntheticSecret123456789"
		profile(map[string]any{"kind": "add_user_app_multi_factor_authenticator", "title": "AuthenticatorOne", "description": "", "secret": secret, "period": 30, "digits": 6, "algorithm": "sha512", "passcode": "wrong"}, 200)
		browser := *f.client
		browser.Jar, _ = cookiejar.New(nil)
		proof := &oidcE2EFixture{server: f.server, client: &browser, issuer: f.base + f.mount}
		origin := http.Header{"Origin": {f.base}}
		start := proof.request(t, "POST", "/login", url.Values{"username": {"keymember"}, "realm": {"local"}}, origin)
		oidcE2EStatus(t, start, 303)
		sandbox := start.header.Get("Location")
		oidcE2EStatus(t, proof.request(t, "POST", sandbox, url.Values{"secret": {tests.TestPwd1}}, origin), 303)
		// MFA is required once the factor is enrolled. Complete its real
		// browser checkpoint before fetching owner records.
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write(counter[:])
		digest := mac.Sum(nil)
		offset := digest[len(digest)-1] & 15
		passcode := fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
		oidcE2EStatus(t, proof.request(t, "POST", sandbox, url.Values{"passcode": {passcode}}, origin), 303)
		oidcE2EStatus(t, proof.request(t, "GET", sandbox, nil, nil), 303)
		token = loginIdentityCookie(proof, "AUTHP_ACCESS_TOKEN")
		listing := profile(map[string]any{"kind": "fetch_user_multi_factor_authenticators"}, 200)
		entries := listing["entries"].([]any)
		if len(entries) != 1 {
			t.Fatal("TOTP enrollment inventory changed")
		}
		record := entries[0].(map[string]any)
		component(t, "ProfileAuthenticatorRecord", record)
		if record["secret"] != secret || record["algorithm"] != "sha1" {
			t.Fatal("TOTP save algorithm contract changed")
		}
		// Independent client calculation uses literal secret bytes, not Base32.
		code := func(offset int64) string {
			var counter [8]byte
			binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30+offset))
			mac := hmac.New(sha1.New, []byte(secret))
			mac.Write(counter[:])
			digest := mac.Sum(nil)
			i := digest[len(digest)-1] & 15
			value := binary.BigEndian.Uint32(digest[i:i+4]) & 0x7fffffff
			return fmt.Sprintf("%06d", value%1000000)
		}
		current := code(0)
		for _, candidate := range []string{current, current, code(-2)} {
			result := profile(map[string]any{"kind": "test_user_app_token_passcode", "id": record["id"], "passcode": candidate}, 200)
			if result["entry"].(map[string]any)["success"] != true {
				t.Fatal("TOTP diagnostic unexpectedly consumed/rejected a code")
			}
		}
		profile(map[string]any{"kind": "test_user_app_token_passcode", "id": record["id"], "passcode": " " + current}, 400)
		profile(map[string]any{"kind": "test_user_app_token_passcode", "id": "missing", "passcode": current}, 500)
	})
}

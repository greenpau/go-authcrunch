// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"encoding/json"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func testOpenAPIAdminContracts(t *testing.T, validate func(*testing.T, string, string, int, http.Header, []byte)) {
	f := newOpenAPIPortalFixture(t, "/auth", "enable admin api", true)
	admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
	post := func(path, token, body string, status int, headers ...http.Header) map[string]any {
		t.Helper()
		h, raw := f.request(t, "POST", path, token, body, status, headers...)
		validate(t, path, "POST", status, h, raw)
		var result map[string]any
		if json.Unmarshal(raw, &result) != nil {
			t.Fatal("invalid administration JSON (body withheld)")
		}
		return result
	}
	t.Run("origin_and_json_admission", func(t *testing.T) {
		for _, target := range []struct{ path, token, body string }{
			{"/api/server/users", admin, `{"realm":"local"}`},
			{"/api/profile", member, `{"kind":"fetch_user_info"}`},
		} {
			for _, tc := range []struct {
				name    string
				headers http.Header
				status  int
			}{
				{"native", nil, 200}, {"same_origin", http.Header{"Origin": {f.base}, "Sec-Fetch-Site": {"same-origin"}}, 200},
				{"no_site", http.Header{"Sec-Fetch-Site": {"none"}}, 200},
				{"empty_origin", http.Header{"Origin": {""}}, 403},
				{"duplicate_origin", http.Header{"Origin": {f.base, f.base}}, 403},
				{"foreign_origin", http.Header{"Origin": {"https://other.example.test"}}, 403},
				{"same_site", http.Header{"Sec-Fetch-Site": {"same-site"}}, 403},
				{"empty_site", http.Header{"Sec-Fetch-Site": {""}}, 403},
				{"duplicate_site", http.Header{"Sec-Fetch-Site": {"same-origin", "same-origin"}}, 403},
				{"mode_ignored", http.Header{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}}, 200},
			} {
				t.Run(target.path+"/"+tc.name, func(t *testing.T) { post(target.path, target.token, target.body, tc.status, tc.headers) })
			}
		}
		// Admission runs before token validation, and profile has a stricter
		// body/media decoder than the administrative endpoints.
		post("/api/server/users", "invalid-token", `{}`, 403, http.Header{"Origin": {""}})
		post("/api/server/users", admin, `{"realm":"local"} {"realm":"missing"}`, 200)
		post("/api/server/users", admin, `{"realm":"local"}`+strings.Repeat(" ", (1<<20)+1), 200)
		post("/api/server/users", admin, `{"realm":"local","padding":"`+strings.Repeat("x", 1<<20)+`"}`, 413)
		post("/api/server/users", admin, `{"realm":"local"}`, 200, http.Header{"Content-Type": {"text/plain"}})
		post("/api/profile", member, `{"kind":"fetch_user_info"} {}`, 400)
		post("/api/profile", member, `{"kind":"fetch_user_info"}`+strings.Repeat(" ", (1<<20)+1), 400)
		post("/api/profile", member, `{"kind":"fetch_user_info"}`, 415, http.Header{"Content-Type": {"text/plain"}})
		post("/api/profile", member, `{"kind":"fetch_user_info"}`, 200, http.Header{"Content-Type": {"application/json; charset=utf-8"}})
		post("/api/profile", member, `{"kind":"unknown","kind":"fetch_user_info","ignored":true}`, 200)
	})
	t.Run("account_lifecycle", func(t *testing.T) {
		user := func(op string, fields map[string]any, status int) map[string]any {
			t.Helper()
			if fields == nil {
				fields = map[string]any{}
			}
			if _, ok := fields["username"]; !ok {
				fields["username"] = "Spec.User"
			}
			if _, ok := fields["email"]; !ok {
				fields["email"] = "Spec@EXAMPLE.test"
			}
			raw, err := json.Marshal(map[string]any{"realm": "local", "operation": op, "user": fields})
			if err != nil {
				t.Fatal(err)
			}
			return post("/api/server/user", admin, string(raw), status)
		}
		assertStatus := func(result map[string]any, want string) {
			t.Helper()
			if result["status"] != want {
				t.Fatalf("admin action status differs from %s (body withheld)", want)
			}
		}
		created := user("add", map[string]any{"name": " Doe, Jane ", "roles": []string{" team/reader ", "team/reader", "/auditor", "team/a/b"}, "password": "ignored-client-password"}, 200)
		assertStatus(created, "success")
		password, ok := created["password"].(string)
		if !ok || len(password) != 8 || password == "ignored-client-password" {
			t.Fatal("generated password contract changed")
		}
		f.secrets = append(f.secrets, password)
		info := user("info", map[string]any{"username": "spec.user", "email": "spec@example.TEST"}, 200)
		if info["username"] != "Spec.User" || info["name"].(map[string]any)["first"] != "Jane" || info["email_address"].(map[string]any)["address"] != "Spec@EXAMPLE.test" {
			t.Fatal("account normalization changed")
		}
		roles := info["roles"].([]any)
		if len(roles) != 3 || roles[1].(map[string]any)["name"] != "auditor" || roles[2].(map[string]any)["name"] != "a/b" {
			t.Fatal("role normalization changed")
		}
		verifier := info["passwords"].([]any)[0].(map[string]any)["hash"].(string)
		if bcrypt.CompareHashAndPassword([]byte(verifier), []byte(password)) != nil {
			t.Fatal("generated password does not match stored verifier")
		}
		user("info", map[string]any{"email": "keymember@example.test"}, 500)
		user("info", map[string]any{"username": " Spec.User"}, 500)
		assertStatus(user("add", map[string]any{"username": "spec.user", "email": "different@example.test", "name": "Duplicate", "roles": []string{"authp/user"}}, 200), "failure")
		all := post("/api/server/users", admin, `{"realm":"local","query":"does-not-match-anyone"}`, 200)
		if all["count"] != float64(3) {
			t.Fatal("local query unexpectedly filtered users")
		}
		missing := post("/api/server/users", admin, `{"realm":"missing"}`, 200)
		if missing["count"] != float64(0) || len(missing["users"].([]any)) != 0 {
			t.Fatal("unknown realm listing changed")
		}
		if result := post("/api/server/user", admin, `{"realm":"missing","operation":"info","user":{"username":"x","email":"x"}}`, 200); result != nil {
			t.Fatal("unknown realm CRUD should return null")
		}
		post("/api/server/reload", admin, `{"realm":"missing"}`, 200)
		user("overwrite_roles", map[string]any{"roles": []string{}}, 400)
		assertStatus(user("overwrite_roles", map[string]any{"roles": []string{"partial/first", "\u2003"}}, 200), "failure")
		partial := user("info", nil, 200)["roles"].([]any)
		if len(partial) != 1 || partial[0].(map[string]any)["name"] != "first" {
			t.Fatal("role failure no longer exposes partial in-memory state; review contract")
		}
		assertStatus(user("overwrite_roles", map[string]any{"roles": []any{"team/reader", nil, 7, "team/reader"}}, 200), "success")
		added := user("add_roles", map[string]any{"roles": []string{"team/reader", "team/admin"}}, 200)
		assertStatus(added, "success")
		if !reflect.DeepEqual(added["roles"], []any{"team/reader", "team/admin"}) {
			t.Fatal("add_roles did not return deduplicated complete roles")
		}
		version := user("info", nil, 200)["credential_version"].(float64)
		assertStatus(user("disable", map[string]any{"username": "SPEC.USER", "email": "spec@example.test"}, 200), "success")
		user("info", nil, 500)
		assertStatus(user("enable", map[string]any{"username": "spec.user", "email": "spec@example.test"}, 200), "failure")
		assertStatus(user("enable", nil, 200), "success")
		if got := user("info", nil, 200)["credential_version"]; got != version+2 {
			t.Fatal("disable/enable credential generation changed")
		}
		assertStatus(user("enable", nil, 200), "failure")
		reset := user("reset_password", map[string]any{"password": "ignored-reset-password"}, 200)
		assertStatus(reset, "success")
		newPassword := reset["password"].(string)
		f.secrets = append(f.secrets, newPassword)
		if newPassword == password || newPassword == "ignored-reset-password" {
			t.Fatal("reset did not generate a fresh password")
		}
		info = user("info", nil, 200)
		active := 0
		for _, raw := range info["passwords"].([]any) {
			entry := raw.(map[string]any)
			if entry["disabled"] == true {
				continue
			}
			active++
			if bcrypt.CompareHashAndPassword([]byte(entry["hash"].(string)), []byte(newPassword)) != nil {
				t.Fatal("reset password does not match active verifier")
			}
		}
		if active != 1 {
			t.Fatal("reset did not retire previous enabled verifiers")
		}
		assertStatus(user("delete", nil, 200), "success")
		user("info", nil, 500)
	})
}

func testOpenAPIBrowserContracts(t *testing.T, validate func(*testing.T, string, string, int, http.Header, []byte)) {
	f := newOpenAPIPortalFixture(t, "/auth", "enable admin api\ntrust login redirect uri domain exact app.example.test path exact /home", true)
	member := f.login(t, "keymember")
	get := func(path, token, accept, cookie string, want int) http.Header {
		t.Helper()
		headers := http.Header{"Accept": {accept}}
		if token != "" {
			headers.Set("Authorization", "Bearer "+token)
		}
		if cookie != "" {
			headers.Set("Cookie", cookie)
		}
		status, header, body := registrationHTTP(t, f.client, "GET", f.base+f.mount+path, nil, headers)
		if status != want {
			t.Fatalf("browser %s returned %d, want %d", strings.Split(path, "?")[0], status, want)
		}
		validate(t, strings.Split(path, "?")[0], "GET", status, header, body)
		return header
	}
	get("/", "", "text/html", "", 302)
	get("/whoami", member, "text/html", "", 200)
	get("/whoami", "", "text/html", "", 302)
	get("/whoami", "invalid-token", "text/html", "", 302)
	get("/whoami", "", "application/json", "", 401)
	get("/whoami?format=json", member, "text/html", "", 200)
	for _, accept := range []string{"application/json; charset=utf-8", "application/json, text/html", "application/json;q=1"} {
		get("/whoami", member, accept, "", 200)
		get("/beacon", member, accept, "", 404)
	}
	get("/beacon?format=json", member, "text/html", "", 200)
	get("/portal", "", "text/html", "", 302)
	get("/portal", member, "text/html", "", 200)
	header := get("/portal", member, "text/html", "AUTHP_REDIRECT_URL=https://app.example.test/home", 303)
	if header.Get("Location") != "https://app.example.test/home" {
		t.Fatal("trusted dashboard redirect changed")
	}
	if !strings.Contains(strings.Join(header.Values("Set-Cookie"), "\n"), "AUTHP_REDIRECT_URL=") {
		t.Fatal("redirect cookie was not consumed")
	}
	get("/portal", member, "text/html", "AUTHP_REDIRECT_URL=https://untrusted.example.test/home", 200)
	// Access-only JSON login yields a valid token but no stored profile session.
	postLogin := func(input map[string]any) map[string]any {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		header, body := f.request(t, "POST", "/login", "", string(raw), 200)
		validate(t, "/login", "POST", 200, header, body)
		var result map[string]any
		if json.Unmarshal(body, &result) != nil {
			t.Fatal("invalid login response")
		}
		return result
	}
	start := postLogin(map[string]any{"username": "keymember", "realm": "local"})
	finished := postLogin(map[string]any{"username": "keymember", "realm": "local", "sandbox_id": start["sandbox_id"], "sandbox_secret": start["sandbox_secret"], "challenge_kind": "password", "challenge_response": tests.TestPwd1})
	access := finished["access_token"].(string)
	f.secrets = append(f.secrets, access)
	get("/whoami", access, "text/html", "", 200)
	get("/portal", access, "text/html", "", 302)
	header, body := f.request(t, "POST", "/api/profile", access, `{"kind":"fetch_user_info"}`, 401)
	validate(t, "/api/profile", "POST", 401, header, body)
	get("/logout", member, "text/html", "", 302)
	// Clearing browser cookies does not revoke a copied stateless access token.
	get("/whoami", member, "application/json", "", 200)
}

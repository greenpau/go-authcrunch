// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authcrunch_test

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/openapi"
)

// Drive verified provider login, application access, callback replay and logout
// through the native root server at all documented portal mount layouts.
func TestE2EOpenAPIContractDirectOAuth(t *testing.T) {
	data, err := openapi.Bundle("assets/openapi/content")
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
	validate := func(t *testing.T, path, method string, r directOAuthResponse) {
		t.Helper()
		operation := doc["paths"].(map[string]any)[path].(map[string]any)[strings.ToLower(method)].(map[string]any)
		responses := operation["responses"].(map[string]any)
		if responses[strconv.Itoa(r.status)] == nil {
			t.Fatal("undocumented direct OAuth status")
		}
		if r.status == 303 {
			if r.header.Get("Location") == "" {
				t.Fatal("callback redirect missing")
			}
			return
		}
		if r.status == 204 {
			if len(r.body) != 0 {
				t.Fatal("logout returned a body")
			}
			return
		}
		media, _, err := mime.ParseMediaType(r.header.Get("Content-Type"))
		if err != nil || media != "text/plain" || r.header.Get("Cache-Control") != "no-store" {
			t.Fatal("direct OAuth error contract changed")
		}
		plain, err := openapi.SchemaAt(compiler, "/components/responses/PlainError/content/text~1plain/schema")
		if err != nil || plain.Validate(string(r.body)) != nil {
			t.Fatal("direct OAuth body violates schema")
		}
	}
	for _, mount := range []string{"/auth", "/team/auth", ""} {
		t.Run("mount="+mount, func(t *testing.T) {
			f := newDirectOAuthFixture(t, []string{"oauth", "base", "path", mount + "/oauth2"})
			callback := f.callback(t, f.client, "/private")
			target, err := url.Parse(callback)
			if err != nil || target.Path != mount+"/oauth2/authorization-code-callback" {
				t.Fatal("callback bypassed shared mount")
			}
			completed := f.request(t, f.client, "GET", callback, nil)
			directOAuthStatus(t, completed, 303)
			validate(t, "/oauth2/authorization-code-callback", "GET", completed)
			directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 200)
			replay := f.request(t, f.client, "GET", callback, nil)
			directOAuthStatus(t, replay, 400)
			validate(t, "/oauth2/authorization-code-callback", "GET", replay)
			logout := f.request(t, f.client, "POST", mount+"/oauth2/logout", http.Header{"Origin": {f.server.URL}})
			directOAuthStatus(t, logout, 204)
			validate(t, "/oauth2/logout", "POST", logout)
			directOAuthStatus(t, f.request(t, f.client, "GET", "/private", nil), 302)
		})
	}
}

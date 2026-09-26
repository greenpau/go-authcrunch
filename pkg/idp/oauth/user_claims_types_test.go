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
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"go.uber.org/zap"
)

func TestFetchedClaimsRejectUnsafeJSONTypes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		driver     string
		claims     map[string]any
		orgFilters []*regexp.Regexp
		valid      bool
	}{
		{name: "valid github", driver: "github", claims: map[string]any{"login": "alice"}, valid: true},
		{name: "valid discord", driver: "discord", claims: map[string]any{"id": "7"}, valid: true},
		{name: "valid facebook", driver: "facebook", claims: map[string]any{"id": "7", "name": "Alice"}, valid: true},
		{name: "github error object", driver: "github", claims: map[string]any{"message": map[string]any{}, "login": "alice"}},
		{name: "github numeric login", driver: "github", claims: map[string]any{"login": float64(7)}},
		{name: "github organization URL object", driver: "github", claims: map[string]any{"login": "alice", "organizations_url": map[string]any{}}, orgFilters: []*regexp.Regexp{regexp.MustCompile(".*")}},
		{name: "discord numeric id", driver: "discord", claims: map[string]any{"id": float64(7)}},
		{name: "facebook string error code", driver: "facebook", claims: map[string]any{"error": map[string]any{"code": "bad", "message": "denied"}}},
		{name: "facebook object error text", driver: "facebook", claims: map[string]any{"error": map[string]any{"code": float64(190), "message": map[string]any{}}}},
		{name: "facebook numeric id", driver: "facebook", claims: map[string]any{"id": float64(7), "name": "Alice"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &IdentityProvider{config: &Config{Driver: tc.driver}, userOrgFilters: tc.orgFilters}
			err := provider.validateFetchedClaims(tc.claims)
			if tc.valid && err != nil {
				t.Fatalf("valid claims rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("malformed claims accepted")
			}
		})
	}
}

func TestGithubOrganizationClaimsIgnoreUnsafeLoginTypes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"login":7}]`))
	}))
	defer server.Close()
	provider := &IdentityProvider{
		config:         &Config{Driver: "github"},
		logger:         zap.NewNop(),
		browserConfig:  &browserConfig{TLSInsecureSkipVerify: true},
		userOrgFilters: []*regexp.Regexp{regexp.MustCompile(".*")},
	}
	got, err := provider.fetchGithubUserInfo(map[string]any{"url": server.URL, "method": http.MethodGet, "token": "opaque"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Groups) != 0 {
		t.Fatalf("malformed organization produced groups: %v", got.Groups)
	}
}

func TestDecodeDiscordFollowupDataRejectsUnsafeTypes(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantErr    bool
	}{
		{name: "valid guild", body: `[{"id":"42","name":"operators","permissions":"8"}]`},
		{name: "numeric guild id", body: `[{"id":42,"name":"operators","permissions":"8"}]`, wantErr: true},
		{name: "missing guild id", body: `[{"name":"operators","permissions":"8"}]`, wantErr: true},
		{name: "numeric guild name", body: `[{"id":"42","name":7,"permissions":"8"}]`, wantErr: true},
		{name: "numeric permissions", body: `[{"id":"42","name":"operators","permissions":8}]`, wantErr: true},
	} {
		t.Run("guild/"+tc.name, func(t *testing.T) {
			guilds, err := decodeDiscordGuilds([]byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("decodeDiscordGuilds() = %#v, %v; want error %t", guilds, err, tc.wantErr)
			}
		})
	}

	for _, tc := range []struct {
		name, body string
		wantErr    bool
	}{
		{name: "valid roles", body: `{"roles":["88","99"]}`},
		{name: "omitted roles", body: `{}`},
		{name: "numeric role", body: `{"roles":[88]}`, wantErr: true},
		{name: "empty role", body: `{"roles":[""]}`, wantErr: true},
	} {
		t.Run("member/"+tc.name, func(t *testing.T) {
			member, err := decodeDiscordMember([]byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("decodeDiscordMember() = %#v, %v; want error %t", member, err, tc.wantErr)
			}
		})
	}
}

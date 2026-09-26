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

package oauth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
)

func TestE2ENamedDriverRejectsUnsafeUserInfoTypes(t *testing.T) {
	if os.Getenv("AUTHCRUNCH_NAMED_DRIVER_TYPES_CHILD") == "1" {
		testNamedDriverUnsafeUserInfoTypesChild(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestE2ENamedDriverRejectsUnsafeUserInfoTypes$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_NAMED_DRIVER_TYPES_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("named-driver malformed UserInfo child failed: %v\n%s", err, output)
	}
}

func TestE2EDiscordRejectsUnsafeGuildResponses(t *testing.T) {
	if os.Getenv("AUTHCRUNCH_DISCORD_GUILDS_CHILD") == "1" {
		testDiscordUnsafeGuildResponsesChild(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestE2EDiscordRejectsUnsafeGuildResponses$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_DISCORD_GUILDS_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Discord guild response child failed: %v\n%s", err, output)
	}
}

func TestE2EGithubRejectsUnsafeFollowupResponses(t *testing.T) {
	if os.Getenv("AUTHCRUNCH_GITHUB_FOLLOWUPS_CHILD") == "1" {
		testGithubUnsafeFollowupResponsesChild(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestE2EGithubRejectsUnsafeFollowupResponses$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_GITHUB_FOLLOWUPS_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GitHub follow-up response child failed: %v\n%s", err, output)
	}
}

func testGithubUnsafeFollowupResponsesChild(t *testing.T) {
	var mu sync.Mutex
	var profileBody, emailBody, orgBody string
	var emailStatus, orgStatus int
	var emailRedirect, orgRedirect bool
	var profileCalls, emailCalls, orgCalls, unsafeCalls int
	var upstream *httptest.Server
	upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			profileCalls++
			if got := r.Header.Get("Authorization"); got != "token opaque" {
				t.Errorf("GitHub profile authorization header = %q", got)
			}
			_, _ = io.WriteString(w, profileBody)
		case "/user/emails":
			emailCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer opaque" {
				t.Errorf("GitHub email authorization header = %q", got)
			}
			if emailRedirect {
				http.Redirect(w, r, upstream.URL+"/attacker-email", http.StatusFound)
				return
			}
			if emailStatus != 0 {
				w.WriteHeader(emailStatus)
			}
			_, _ = io.WriteString(w, emailBody)
		case "/user/orgs":
			orgCalls++
			if got := r.Header.Get("Authorization"); got != "token opaque" {
				t.Errorf("GitHub organization authorization header = %q", got)
			}
			if orgRedirect {
				http.Redirect(w, r, upstream.URL+"/attacker-orgs", http.StatusFound)
				return
			}
			if orgStatus != 0 {
				w.WriteHeader(orgStatus)
			}
			_, _ = io.WriteString(w, orgBody)
		case "/attacker-orgs":
			unsafeCalls++
			_, _ = io.WriteString(w, `[{"login":"administrators"}]`)
		case "/attacker-email":
			unsafeCalls++
			_, _ = io.WriteString(w, `[{"email":"attacker@example.test","primary":true,"verified":true}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	proxy := newNamedDriverConnectProxy(t, upstream.Listener.Addr().String())
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")

	for _, tc := range []struct {
		name, profileBody, emailBody, orgBody string
		emailStatus, orgStatus                int
		emailRedirect, orgRedirect            bool
		wantErr                               string
		wantEmail, wantGroup                  string
		forbiddenEmail, forbiddenGroup        string
		wantProfiles, wantEmails, wantOrgs    int
		wantUnsafe                            int
	}{
		{
			name:        "valid follow-ups",
			profileBody: `{"login":"alice","organizations_url":"https://api.github.com/user/orgs"}`,
			emailBody:   `[{"email":"alice@example.test","primary":true,"verified":true}]`,
			orgBody:     `[{"login":"engineering"}]`,
			wantEmail:   "alice@example.test", wantGroup: "github.com/engineering/members",
			wantProfiles: 1, wantEmails: 1, wantOrgs: 1,
		},
		{
			name:        "unsafe organization URL",
			profileBody: `{"login":"alice","organizations_url":"{{UPSTREAM}}/attacker-orgs"}`,
			emailBody:   `[]`, orgBody: `[]`, wantErr: "organizations_url",
			wantProfiles: 1,
		},
		{
			name:        "organization HTTP failure",
			profileBody: `{"login":"alice","organizations_url":"https://api.github.com/user/orgs"}`,
			emailBody:   `[]`, orgBody: `[{"login":"administrators"}]`, orgStatus: http.StatusUnauthorized,
			forbiddenGroup: "github.com/administrators/members", wantProfiles: 1, wantEmails: 1, wantOrgs: 1,
		},
		{
			name:        "oversized organizations",
			profileBody: `{"login":"alice","organizations_url":"https://api.github.com/user/orgs"}`,
			emailBody:   `[]`, orgBody: `[{"login":"administrators","padding":"` + strings.Repeat("x", 1<<20) + `"}]`,
			forbiddenGroup: "github.com/administrators/members", wantProfiles: 1, wantEmails: 1, wantOrgs: 1,
		},
		{
			name:        "organization redirect",
			profileBody: `{"login":"alice","organizations_url":"https://api.github.com/user/orgs"}`,
			emailBody:   `[]`, orgBody: `[]`, orgRedirect: true,
			forbiddenGroup: "github.com/administrators/members", wantProfiles: 1, wantEmails: 1, wantOrgs: 1,
		},
		{
			name:        "email HTTP failure",
			profileBody: `{"login":"alice","organizations_url":"https://api.github.com/user/orgs"}`,
			emailBody:   `[{"email":"attacker@example.test","primary":true,"verified":true}]`, emailStatus: http.StatusUnauthorized,
			orgBody: `[]`, forbiddenEmail: "attacker@example.test", wantProfiles: 1, wantEmails: 1, wantOrgs: 1,
		},
		{
			name:        "oversized emails",
			profileBody: `{"login":"alice","organizations_url":"https://api.github.com/user/orgs"}`,
			emailBody:   `[{"email":"attacker@example.test","primary":true,"verified":true,"padding":"` + strings.Repeat("x", 1<<20) + `"}]`,
			orgBody:     `[]`, forbiddenEmail: "attacker@example.test", wantProfiles: 1, wantEmails: 1, wantOrgs: 1,
		},
		{
			name:        "email redirect",
			profileBody: `{"login":"alice","organizations_url":"https://api.github.com/user/orgs"}`,
			emailBody:   `[]`, emailRedirect: true, orgBody: `[]`,
			forbiddenEmail: "attacker@example.test", wantProfiles: 1, wantEmails: 1, wantOrgs: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			profileBody = strings.ReplaceAll(tc.profileBody, "{{UPSTREAM}}", upstream.URL)
			emailBody, orgBody = tc.emailBody, tc.orgBody
			emailStatus, orgStatus = tc.emailStatus, tc.orgStatus
			emailRedirect, orgRedirect = tc.emailRedirect, tc.orgRedirect
			profileCalls, emailCalls, orgCalls, unsafeCalls = 0, 0, 0, 0
			mu.Unlock()
			provider, err := oauth.NewIdentityProvider(&oauth.Config{
				Name: "github", Realm: "github", Driver: "github",
				ClientID: "client", ClientSecret: "secret",
				UserOrgFilters:        []string{"^(engineering|administrators)$"},
				TLSInsecureSkipVerify: true,
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.Configure(); err != nil {
				provider.Close()
				t.Fatal(err)
			}
			claims, err := provider.FetchClaimsForTesting(map[string]any{"access_token": "opaque"})
			provider.Close()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("GitHub claims error = %v, want substring %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if claims != nil {

				if tc.wantEmail != "" && claims["email"] != tc.wantEmail {
					t.Fatalf("email = %#v, want %q", claims["email"], tc.wantEmail)
				}
				if tc.forbiddenEmail != "" && claims["email"] == tc.forbiddenEmail {
					t.Fatalf("unsafe GitHub email response produced %q", tc.forbiddenEmail)
				}
				groups, _ := claims["groups"].([]string)
				if tc.wantGroup != "" && !slices.Contains(groups, tc.wantGroup) {
					t.Fatalf("groups = %v, want %q", groups, tc.wantGroup)
				}
				if tc.forbiddenGroup != "" && slices.Contains(groups, tc.forbiddenGroup) {
					t.Fatalf("unsafe GitHub organization response produced group %q", tc.forbiddenGroup)
				}
			}
			mu.Lock()
			gotProfiles, gotEmails, gotOrgs, gotUnsafe := profileCalls, emailCalls, orgCalls, unsafeCalls
			mu.Unlock()
			if gotProfiles != tc.wantProfiles || gotEmails != tc.wantEmails || gotOrgs != tc.wantOrgs || gotUnsafe != tc.wantUnsafe {
				t.Fatalf("GitHub calls profile=%d email=%d org=%d unsafe=%d, want %d/%d/%d/%d", gotProfiles, gotEmails, gotOrgs, gotUnsafe, tc.wantProfiles, tc.wantEmails, tc.wantOrgs, tc.wantUnsafe)
			}
		})
	}
}

func testDiscordUnsafeGuildResponsesChild(t *testing.T) {
	var mu sync.Mutex
	var guildBody, memberBody string
	var guildStatus, memberStatus int
	var profileCalls, guildCalls, memberCalls int
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer opaque" {
			t.Errorf("Discord authorization header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v10/users/@me":
			profileCalls++
			_, _ = io.WriteString(w, `{"id":"7","username":"alice"}`)
		case r.URL.Path == "/api/v10/users/@me/guilds":
			guildCalls++
			if guildStatus != 0 {
				w.WriteHeader(guildStatus)
			}
			_, _ = io.WriteString(w, guildBody)
		case strings.HasPrefix(r.URL.Path, "/api/v10/users/@me/guilds/"):
			memberCalls++
			if memberStatus != 0 {
				w.WriteHeader(memberStatus)
			}
			_, _ = io.WriteString(w, memberBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	proxy := newNamedDriverConnectProxy(t, upstream.Listener.Addr().String())
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")

	for _, tc := range []struct {
		name                        string
		scopes                      []string
		guildBody, memberBody       string
		guildStatus, memberStatus   int
		wantGuildCalls, wantMembers int
		wantGroup, forbiddenGroup   string
	}{
		{
			name: "valid guilds", scopes: []string{"guilds"},
			guildBody:      `[ {"id":"42","name":"operators","permissions":"8"} ]`,
			wantGuildCalls: 1, wantGroup: "discord.com/42/admins",
		},
		{
			name: "numeric guild id", scopes: []string{"guilds"},
			guildBody:      `[ {"id":42,"name":"operators","permissions":"0"} ]`,
			wantGuildCalls: 1, forbiddenGroup: "discord.com/42/members",
		},
		{
			name: "numeric permissions", scopes: []string{"guilds"},
			guildBody:      `[ {"id":"42","name":"operators","permissions":8} ]`,
			wantGuildCalls: 1, forbiddenGroup: "discord.com/42/admins",
		},
		{
			name: "guild HTTP failure", scopes: []string{"guilds"}, guildStatus: http.StatusUnauthorized,
			guildBody:      `[ {"id":"42","name":"operators","permissions":"8"} ]`,
			wantGuildCalls: 1, forbiddenGroup: "discord.com/42/admins",
		},
		{
			name: "oversized guilds", scopes: []string{"guilds"},
			guildBody:      `[{"id":"42","name":"operators","permissions":"0","padding":"` + strings.Repeat("x", 1<<20) + `"}]`,
			wantGuildCalls: 1, forbiddenGroup: "discord.com/42/members",
		},
		{
			name: "oversized member", scopes: []string{"guilds", "guilds.members.read"},
			guildBody:      `[{"id":"42","name":"operators","permissions":"0"}]`,
			memberBody:     `{"roles":["88"],"padding":"` + strings.Repeat("x", 1<<20) + `"}`,
			wantGuildCalls: 1, wantMembers: 1, forbiddenGroup: "discord.com/42/role/88",
		},
		{
			name: "member HTTP failure", scopes: []string{"guilds", "guilds.members.read"}, memberStatus: http.StatusUnauthorized,
			guildBody:      `[{"id":"42","name":"operators","permissions":"0"}]`,
			memberBody:     `{"roles":["88"]}`,
			wantGuildCalls: 1, wantMembers: 1, forbiddenGroup: "discord.com/42/role/88",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			guildBody, memberBody = tc.guildBody, tc.memberBody
			guildStatus, memberStatus = tc.guildStatus, tc.memberStatus
			profileCalls, guildCalls, memberCalls = 0, 0, 0
			mu.Unlock()
			provider, err := oauth.NewIdentityProvider(&oauth.Config{
				Name: "discord", Realm: "discord", Driver: "discord",
				ClientID: "client", ClientSecret: "secret", Scopes: tc.scopes,
				UserGroupFilters: []string{"^42$"},
				BaseAuthURL:      "https://identity.example/", TLSInsecureSkipVerify: true,
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.Configure(); err != nil {
				provider.Close()
				t.Fatal(err)
			}
			claims, err := provider.FetchClaimsForTesting(map[string]any{"access_token": "opaque"})
			provider.Close()
			if err != nil {
				t.Fatal(err)
			}
			groups, _ := claims["groups"].([]string)
			if tc.wantGroup != "" && !slices.Contains(groups, tc.wantGroup) {
				t.Fatalf("groups = %v, want %q", groups, tc.wantGroup)
			}
			if tc.forbiddenGroup != "" && slices.Contains(groups, tc.forbiddenGroup) {
				t.Fatalf("unsafe Discord response produced group %q in %v", tc.forbiddenGroup, groups)
			}
			mu.Lock()
			gotProfiles, gotGuilds, gotMembers := profileCalls, guildCalls, memberCalls
			mu.Unlock()
			if gotProfiles != 1 || gotGuilds != tc.wantGuildCalls || gotMembers != tc.wantMembers {
				t.Fatalf("Discord calls profile=%d guilds=%d members=%d, want 1/%d/%d", gotProfiles, gotGuilds, gotMembers, tc.wantGuildCalls, tc.wantMembers)
			}
		})
	}
}

func testNamedDriverUnsafeUserInfoTypesChild(t *testing.T) {
	var mu sync.Mutex
	body := "{}"
	calls := 0
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		current := body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/user/emails" {
			current = "[]"
		}
		_, _ = io.WriteString(w, current)
	}))
	defer upstream.Close()
	proxy := newNamedDriverConnectProxy(t, upstream.Listener.Addr().String())
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")

	for _, tc := range []struct {
		name, driver, response, wantErr, wantSub string
		wantCalls                                int
	}{
		{name: "valid github", driver: "github", response: `{"login":"alice"}`, wantSub: "github.com/alice", wantCalls: 2},
		{name: "valid discord", driver: "discord", response: `{"id":"7","username":"alice"}`, wantSub: "discord.com/7", wantCalls: 1},
		{name: "valid facebook", driver: "facebook", response: `{"id":"7","name":"Alice"}`, wantSub: "7", wantCalls: 1},
		{name: "github error object", driver: "github", response: `{"message":{},"login":"alice"}`, wantErr: "provider returned an error", wantCalls: 1},
		{name: "github numeric login", driver: "github", response: `{"login":7}`, wantErr: "login field not found", wantCalls: 1},
		{name: "discord numeric id", driver: "discord", response: `{"id":7}`, wantErr: "id field not found", wantCalls: 1},
		{name: "facebook string error code", driver: "facebook", response: `{"error":{"code":"bad","message":"denied"}}`, wantErr: "code=bad", wantCalls: 1},
		{name: "facebook object error text", driver: "facebook", response: `{"error":{"code":190,"message":{}}}`, wantErr: "message=invalid", wantCalls: 1},
		{name: "facebook numeric id", driver: "facebook", response: `{"id":7,"name":"Alice"}`, wantErr: "field id not found", wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			body = tc.response
			calls = 0
			mu.Unlock()
			provider, err := oauth.NewIdentityProvider(&oauth.Config{
				Name: "named", Realm: "named", Driver: tc.driver,
				ClientID: "client", ClientSecret: "secret",
				BaseAuthURL: "https://identity.example/", TLSInsecureSkipVerify: true,
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			if err := provider.Configure(); err != nil {
				t.Fatal(err)
			}
			claims, err := provider.FetchClaimsForTesting(map[string]any{"access_token": "opaque"})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("valid named-driver UserInfo rejected: %v", err)
				}
				if got, _ := claims["sub"].(string); got != tc.wantSub {
					t.Fatalf("subject = %q, want %q", got, tc.wantSub)
				}
			}
			mu.Lock()
			gotCalls := calls
			mu.Unlock()
			if gotCalls != tc.wantCalls {
				t.Fatalf("upstream calls = %d, want %d", gotCalls, tc.wantCalls)
			}
		})
	}
}

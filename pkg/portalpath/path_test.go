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

package portalpath_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/portalpath"
)

type mountCase struct {
	path     string
	reserved bool
}

func mountCases(t *testing.T) []mountCase {
	t.Helper()
	data, err := os.ReadFile("../authn/testdata/reserved_route_words.json")
	if err != nil {
		t.Fatal(err)
	}
	var words map[string]struct {
		Mount string `json:"mount"`
	}
	if json.Unmarshal(data, &words) != nil || len(words) == 0 {
		t.Fatal("missing authored mount catalogue")
	}
	names := make([]string, 0, len(words))
	for name := range words {
		names = append(names, name)
	}
	slices.Sort(names)
	cases := []mountCase{{"/", false}, {"/auth", false}, {"/tenant/security", false}}
	for _, word := range names {
		rule := words[word].Mount
		if rule != "allow" && rule != "deny_segment" && rule != "deny_prefix" {
			t.Fatal("unknown authored mount rule")
		}
		cases = append(cases, mountCase{"/" + word, rule != "allow"}, mountCase{"/tenant/" + word, rule != "allow"}, mountCase{"/" + word + "/tenant", rule != "allow"}, mountCase{"/tenant/" + word + "-service", rule == "deny_prefix"}, mountCase{"/team-" + word, false}, mountCase{"/" + strings.ToUpper(word), false})
	}
	return cases
}

func TestPortalPathReservedCatalogue(t *testing.T) {
	for _, tc := range mountCases(t) {
		t.Run(tc.path, func(t *testing.T) {
			err := portalpath.Validate(tc.path)
			if (err != nil) != tc.reserved {
				t.Fatalf("reserved=%t, validation error=%v", tc.reserved, err)
			}
			if err != nil && !errors.Is(err, portalpath.ErrReservedPrefix) && !errors.Is(err, portalpath.ErrReservedSegment) {
				t.Fatal("reserved path lost category")
			}
		})
	}
}
func TestPortalPathCanonicalShape(t *testing.T) {
	for _, bad := range []string{"", "auth", "//auth", "/auth/", "/auth//team", "/auth/../team", "/auth/./team", "/a%2fb", "/a?b", "/a#b", "/a\\b", "/a b", "/a\t", "/a\r\n", "/a\x00", "/a\x7f", "/a\u0085", "/a\u00a0", "/a\ufffd\xff", "/{env.NAME}", "/*", "/a[bc]", "/équipe/entrée", "/neutral;parameter"} {
		if !errors.Is(portalpath.Validate(bad), portalpath.ErrShape) {
			t.Fatal("noncanonical shape accepted or miscategorized")
		}
	}
	for _, good := range []string{"/", "/auth", "/tenant/security", "/saml-service", "/team-login", "/cross-device-team", "/LOGIN"} {
		if err := portalpath.Validate(good); err != nil {
			t.Fatalf("literal neutral mount rejected: %v", err)
		}
	}
}

// The public cookie factory retains its legacy API. Declared mounts must reject
// paths it cannot serialize intact; neither stripping bytes nor truncating a
// semicolon-delimited Path may silently broaden or change browser proof scope.
func TestPortalPathCookieScope(t *testing.T) {
	factory, err := cookie.NewFactory(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mount    string
		accepted bool
	}{
		{"/", true}, {"/tenant/security", true},
		{"/équipe", false}, {"/neutral;parameter", false},
	} {
		t.Run(tc.mount, func(t *testing.T) {
			issued, err := http.ParseSetCookie(factory.GetSandboxIDCookieForSession(tc.mount, "proof", strings.Repeat("a", 36)))
			if err != nil {
				t.Fatal("public proof factory did not issue a parseable cookie")
			}
			if (issued.Path == tc.mount) != tc.accepted {
				t.Fatal("cookie serialization no longer demonstrates the declared-mount scope constraint")
			}
			if err := portalpath.Validate(tc.mount); tc.accepted && err != nil || !tc.accepted && !errors.Is(err, portalpath.ErrShape) {
				t.Fatal("declared-mount validation permits a cookie scope change or rejects an intact scope")
			}
		})
	}
}

func TestPortalPathEscapedCookieScope(t *testing.T) {
	factory, err := cookie.NewFactory(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mount    string
		accepted bool
	}{
		{"/tenant/a+b", true}, {"/tenant/a,b", true},
		{"/tenant/a:b@c", true}, {"/tenant/$&=_~.suffix", true},
		{"/team<name", false}, {"/team>name", false},
		{"/team\"name", false}, {"/team^name", false},
		{"/team`name", false}, {"/team|name", false},
		{"/team!name", false}, {"/team'name", false},
		{"/team(name)", false},
	} {
		t.Run(tc.mount, func(t *testing.T) {
			issued, err := http.ParseSetCookie(factory.GetSandboxIDCookieForSession(tc.mount, "proof", strings.Repeat("a", 36)))
			wirePath := (&url.URL{Path: tc.mount}).EscapedPath()
			if (tc.mount == wirePath) != tc.accepted {
				t.Fatal("literal mount and canonical request-target spelling disagree with control")
			}
			if tc.accepted && (err != nil || issued.Path != wirePath) {
				t.Fatal("admitted mount changed its serialized cookie scope")
			}
			if !tc.accepted && err == nil && issued.Path == wirePath {
				t.Fatal("rejected control no longer demonstrates a cookie/wire scope difference")
			}
			if err := portalpath.Validate(tc.mount); tc.accepted && err != nil || !tc.accepted && !errors.Is(err, portalpath.ErrShape) {
				t.Fatal("declared mount disagrees with wire-preserving cookie scope")
			}
			if !tc.accepted {
				return
			}
			// Go's jar compares decoded URL.Path. Only use it to check admitted
			// paths, whose decoded and escaped spellings are already identical;
			// this is not evidence for browser handling of rejected encodings.
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			own := &url.URL{Scheme: "https", Host: "auth.example.test", Path: tc.mount + "/login"}
			jar.SetCookies(own, []*http.Cookie{issued})
			neighbor := &url.URL{Scheme: own.Scheme, Host: own.Host, Path: tc.mount + "-other/login"}
			if len(jar.Cookies(own)) != 1 || len(jar.Cookies(neighbor)) != 0 {
				t.Fatal("admitted punctuation changed own-child or neighboring cookie scope")
			}
		})
	}
}

// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package cookie

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestFactory(t *testing.T) {
	var testcases = []struct {
		name   string
		host   string
		config *Config
		// Expected results.
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "default config",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie with default path",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": {
						Seq:    0,
						Domain: "contoso.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie same host",
			host: "contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": {
						Seq:    0,
						Domain: "contoso.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie without domain config",
			host: "contoso.com",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie with default strict samesite",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": {
						Seq:    0,
						Domain: "contoso.com",
					},
				},
				SameSite: "strict",
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=contoso.com; Path=/; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "fail contoso.com cookie with default incorrect samesite",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": {
						Seq:    0,
						Domain: "contoso.com",
					},
				},
				SameSite: "foobar",
			},
			shouldErr: true,
			err:       fmt.Errorf("the SameSite cookie attribute %q is invalid", "foobar"),
		},
		{
			name: "contoso.com cookie with custom path",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": {
						Seq:    0,
						Domain: "contoso.com",
						Path:   "/mydir",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=contoso.com; Path=/mydir; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=contoso.com; Path=/mydir; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie custom lifetime",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": {
						Seq:      0,
						Domain:   "contoso.com",
						Lifetime: 900,
					},
					"foo.bar": {
						Seq:      0,
						Domain:   "foo.bar",
						Lifetime: 900,
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=contoso.com; Path=/; Max-Age=900; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie without domain config",
			host: "auth.contoso.com",
			config: &Config{
				Path:     "/",
				Lifetime: 900,
				SameSite: "strict",
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "localhost cookie",
			host: "localhost",
			config: &Config{
				Path:     "/",
				Lifetime: 900,
				SameSite: "strict",
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "localhost ipv4 cookie with port",
			host: "127.0.0.1:443",
			config: &Config{
				Path:     "/",
				Lifetime: 900,
				SameSite: "strict",
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "ipv6 cookie with port",
			host: "[2001:db8:3333:4444::8888]:443",
			config: &Config{
				Path:     "/",
				Lifetime: 900,
				SameSite: "strict",
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "psl co.uk subdomain without domain config",
			host: "bar.co.uk",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "psl co.uk direct without domain config",
			host: "co.uk",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "psl fly.dev subdomain without domain config",
			host: "app.fly.dev",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "psl github.io subdomain without domain config",
			host: "myapp.github.io",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "psl herokuapp.com subdomain without domain config",
			host: "myapp.herokuapp.com",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "psl deep subdomain without domain config",
			host: "auth.app.fly.dev",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "psl co.uk with explicit domain config",
			host: "bar.co.uk",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"bar.co.uk": {
						Seq:    0,
						Domain: "bar.co.uk",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=bar.co.uk; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=bar.co.uk; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=bar.co.uk; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=bar.co.uk; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "default host-only cookie without domain config",
			host: "auth.contoso.com",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "default host-only with port without domain config",
			host: "auth.contoso.com:8443",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "default host-only two-level subdomain without domain config",
			host: "bar.foo.contoso.com",
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "guess domain enabled restores parent domain guessing",
			host: "auth.contoso.com",
			config: &Config{
				GuessDomainEnabled: true,
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "guess domain with psl deep subdomain",
			host: "auth.app.fly.dev",
			config: &Config{
				GuessDomainEnabled: true,
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=app.fly.dev; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=app.fly.dev; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=app.fly.dev; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=app.fly.dev; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "guess domain with psl entry omits domain",
			host: "app.fly.dev",
			config: &Config{
				GuessDomainEnabled: true,
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "domain config substring mismatch",
			host: "evil-example.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"example.com": {
						Seq:    0,
						Domain: "example.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "domain config suffix match with dot boundary",
			host: "auth.example.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"example.com": {
						Seq:    0,
						Domain: "example.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=example.com; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=example.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "leading dot domain config suffix match",
			host: "admin.example.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					".example.com": {
						Seq:    0,
						Domain: ".example.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=example.com; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=example.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "leading dot domain config exact host match",
			host: "example.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					".example.com": {
						Seq:    0,
						Domain: ".example.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "AUTHP_ACCESS_TOKEN=foobar; Domain=example.com; Path=/; Secure; HttpOnly;",
				"delete":         "AUTHP_ACCESS_TOKEN=delete; Domain=example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=example.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=example.com; Path=/; Secure; HttpOnly;",
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			cf, err := NewFactory(tc.config)
			if tests.EvalErrWithLog(t, err, "cookie", tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["grant"] = cf.GetAccessTokenCookie(tc.host, "foobar")
			got["delete"] = cf.GetDeleteAccessTokenCookie(tc.host)
			got["session_grant"] = cf.GetSessionIDCookie(tc.host, "foobar")
			got["session_delete"] = cf.GetDeleteSessionIDCookie(tc.host)
			tests.EvalObjectsWithLog(t, "cookie", tc.want, got, msgs)
		})
	}
}

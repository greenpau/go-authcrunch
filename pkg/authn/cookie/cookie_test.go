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
	"github.com/greenpau/go-authcrunch/internal/tests"
	"testing"
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
				"grant":          "access_token=foobar; Path=/; Secure; HttpOnly;",
				"delete":         "access_token=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie with default path",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": &DomainConfig{
						Seq:    0,
						Domain: "contoso.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie same host",
			host: "contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": &DomainConfig{
						Seq:    0,
						Domain: "contoso.com",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie without domain config",
			host: "contoso.com",
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie with default strict samesite",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": &DomainConfig{
						Seq:    0,
						Domain: "contoso.com",
					},
				},
				SameSite: "strict",
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "fail contoso.com cookie with default incorrect samesite",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": &DomainConfig{
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
					"contoso.com": &DomainConfig{
						Seq:    0,
						Domain: "contoso.com",
						Path:   "/mydir",
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/mydir; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/mydir; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
			},
		},
		{
			name: "contoso.com cookie custom lifetime",
			host: "auth.contoso.com",
			config: &Config{
				Domains: map[string]*DomainConfig{
					"contoso.com": &DomainConfig{
						Seq:      0,
						Domain:   "contoso.com",
						Lifetime: 900,
					},
					"foo.bar": &DomainConfig{
						Seq:      0,
						Domain:   "foo.bar",
						Lifetime: 900,
					},
				},
			},
			want: map[string]interface{}{
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; Max-Age=900; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
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
				"grant":          "access_token=foobar; Domain=contoso.com; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "access_token=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Domain=contoso.com; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Domain=contoso.com; Path=/; Secure; HttpOnly;",
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
				"grant":          "access_token=foobar; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "access_token=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
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
				"grant":          "access_token=foobar; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "access_token=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
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
				"grant":          "access_token=foobar; Path=/; Max-Age=900; SameSite=Strict; Secure; HttpOnly;",
				"delete":         "access_token=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_delete": "AUTHP_SESSION_ID=delete; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
				"session_grant":  "AUTHP_SESSION_ID=foobar; Path=/; Secure; HttpOnly;",
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
			got["grant"] = cf.GetCookie(tc.host, "access_token", "foobar")
			got["delete"] = cf.GetDeleteCookie(tc.host, "access_token")
			got["session_grant"] = cf.GetSessionCookie(tc.host, "foobar")
			got["session_delete"] = cf.GetDeleteSessionCookie(tc.host)
			tests.EvalObjectsWithLog(t, "cookie", tc.want, got, msgs)
		})
	}
}

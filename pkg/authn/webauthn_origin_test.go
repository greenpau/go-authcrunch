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

package authn

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestGetWebAuthnExpectedOrigin(t *testing.T) {
	tests := []struct {
		name, host, forwardedHost, forwardedProto, forwardedPort, expected string
		tls                                                                bool
		wantErr                                                            bool
	}{
		{name: "TLS non-default port", host: "login.example.test:9443", tls: true, expected: "https://login.example.test:9443"},
		{name: "browser default TLS port normalization", host: "LOGIN.EXAMPLE.TEST:443", tls: true, expected: "https://login.example.test"},
		{name: "IPv6 non-default port", host: "[::1]:9443", tls: true, expected: "https://[::1]:9443"},
		{name: "trusted forwarded metadata", host: "internal:8080", forwardedHost: "login.example.test", forwardedProto: "https", forwardedPort: "10443", expected: "https://login.example.test:10443"},
		{name: "unsupported forwarded scheme fails closed", host: "login.example.test", forwardedProto: "ftp", wantErr: true},
		{name: "malformed forwarded host fails closed", host: "login.example.test", forwardedHost: "bad host", tls: true, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, "http://"+tc.host+"/auth/sandbox/id", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("X-Forwarded-Host", tc.forwardedHost)
			r.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			r.Header.Set("X-Forwarded-Port", tc.forwardedPort)
			got, err := getWebAuthnExpectedOrigin(r)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("derived origin %q from malformed metadata", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.expected {
				t.Fatalf("origin %q, want %q", got, tc.expected)
			}
		})
	}
}

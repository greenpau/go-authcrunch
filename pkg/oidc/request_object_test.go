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

package oidc

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

func oidcUnsecuredObject(header, body string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body)) + "."
}

func TestOIDCRequestObjects(t *testing.T) {
	o := &Provider{clients: map[string]*ClientConfig{"client": {ClientID: "client"}}, config: Config{Issuer: "https://auth.test"}, now: func() time.Time { return time.Unix(1000, 0) }}
	for _, tc := range []struct {
		name, header, body, failure string
		change                      func(url.Values)
	}{
		{name: "precedence", body: `{"client_id":"client","response_type":"code","redirect_uri":"https://client.test/inner","state":"inner","scope":"openid profile","max_age":60}`},
		{name: "optional JWT binding", body: `{"iss":"client","aud":"https://auth.test","exp":1001.5,"nbf":999,"iat":999}`},
		{name: "audience array", body: `{"aud":["https://auth.test"]}`},
		{name: "escaped alg", header: `{"alg":"n\u006fne"}`, body: `{}`},
		{name: "unknown structured claims ignored", body: `{"roles":["admin"],"sub":"administrator","authenticated":true,"claims":{"userinfo":{"name":{"essential":true}}}}`},
		{name: "client mismatch", body: `{"client_id":"other"}`, failure: "invalid_request_object"},
		{name: "response mismatch", body: `{"response_type":"id_token"}`, failure: "invalid_request_object"},
		{name: "issuer mismatch", body: `{"iss":"other"}`, failure: "invalid_request_object"},
		{name: "audience mismatch", body: `{"aud":"https://other.test"}`, failure: "invalid_request_object"},
		{name: "audience wrong type", body: `{"aud":1}`, failure: "invalid_request_object"},
		{name: "audience null", body: `{"aud":null}`, failure: "invalid_request_object"},
		{name: "expired", body: `{"exp":1000}`, failure: "invalid_request_object"},
		{name: "future nbf", body: `{"nbf":1001}`, failure: "invalid_request_object"},
		{name: "future iat", body: `{"iat":1001}`, failure: "invalid_request_object"},
		{name: "quoted expiry", body: `{"exp":"1001"}`, failure: "invalid_request_object"},
		{name: "null expiry", body: `{"exp":null}`, failure: "invalid_request_object"},
		{name: "overflow expiry", body: `{"exp":1e1000}`, failure: "invalid_request_object"},
		{name: "negative iat", body: `{"iat":-1}`, failure: "invalid_request_object"},
		{name: "nested request", body: `{"request":""}`, failure: "invalid_request_object"},
		{name: "nested URI", body: `{"request_uri":"https://evil.test"}`, failure: "invalid_request_object"},
		{name: "duplicate member", body: `{"scope":"openid","scope":"admin"}`, failure: "invalid_request_object"},
		{name: "escaped duplicate", body: `{"scope":"openid","scop\u0065":"admin"}`, failure: "invalid_request_object"},
		{name: "duplicate header", header: `{"alg":"RS256","alg":"none"}`, body: `{}`, failure: "invalid_request_object"},
		{name: "missing algorithm", header: `{}`, body: `{}`, failure: "invalid_request_object"},
		{name: "signed token", header: `{"alg":"RS256"}`, body: `{}`, failure: "invalid_request_object"},
		{name: "critical extension", header: `{"alg":"none","crit":[]}`, body: `{}`, failure: "invalid_request_object"},
		{name: "unencoded payload", header: `{"alg":"none","b64":false}`, body: `{}`, failure: "invalid_request_object"},
		{name: "compression", header: `{"alg":"none","zip":"DEF"}`, body: `{}`, failure: "invalid_request_object"},
		{name: "header array", header: `[]`, body: `{}`, failure: "invalid_request_object"},
		{name: "body array", body: `[]`, failure: "invalid_request_object"},
		{name: "body null", body: `null`, failure: "invalid_request_object"},
		{name: "trailing data", body: `{} {}`, failure: "invalid_request_object"},
		{name: "malformed", body: `{"scope":`, failure: "invalid_request_object"},
		{name: "malformed separator", body: `{"scope":"openid" "state":"x"}`, failure: "invalid_request_object"},
		{name: "unterminated", body: `{"scope":"openid"`, failure: "invalid_request_object"},
		{name: "invalid UTF8", body: "{\"state\":\"\xff\"}", failure: "invalid_request_object"},
		{name: "nonstring scope", body: `{"scope":["openid"]}`, failure: "invalid_request_object"},
		{name: "null nonce", body: `{"nonce":null}`, failure: "invalid_request_object"},
		{name: "fractional max age", body: `{"max_age":1.5}`, failure: "invalid_request_object"},
		{name: "quoted max age", body: `{"max_age":"1"}`, failure: "invalid_request_object"},
		{name: "missing outer response", body: `{}`, change: func(v url.Values) { v.Del("response_type") }, failure: "invalid_request"},
		{name: "missing outer client", body: `{}`, change: func(v url.Values) { v.Del("client_id") }, failure: "invalid_request"},
		{name: "missing outer openid", body: `{"scope":"openid"}`, change: func(v url.Values) { v.Set("scope", "profile") }, failure: "invalid_request"},
		{name: "request and URI", body: `{}`, change: func(v url.Values) { v.Set("request_uri", "https://evil.test") }, failure: "invalid_request"},
		{name: "signature present", body: `{}`, change: func(v url.Values) { v.Set("request", v.Get("request")+"signature") }, failure: "invalid_request_object"},
		{name: "malformed encoding", body: `{}`, change: func(v url.Values) { v.Set("request", "%%.%%.") }, failure: "invalid_request_object"},
		{name: "oversized", body: `{}`, change: func(v url.Values) { v.Set("request", strings.Repeat("x", oidcMaxRequestBytes+1)) }, failure: "invalid_request_object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header
			if header == "" {
				header = `{"alg":"none"}`
			}
			outer := url.Values{"client_id": {"client"}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {"https://client.test/outer"}, "state": {"outer"}, "request": {oidcUnsecuredObject(header, tc.body)}}
			if tc.change != nil {
				tc.change(outer)
			}
			before := outer.Encode()
			merged, failure := o.requestObjectParameters(outer)
			if failure != tc.failure {
				t.Fatalf("error = %q, expected %q", failure, tc.failure)
			}
			if before != outer.Encode() {
				t.Fatal("assembly mutated outer request")
			}
			if failure == "" {
				if merged.Get("client_id") != "client" || merged.Get("response_type") != "code" || merged.Has("request") || merged.Has("sub") || merged.Has("roles") || merged.Has("authenticated") {
					t.Fatal("request object escaped parameter boundary")
				}
				if tc.name == "precedence" && (merged.Get("state") != "inner" || merged.Get("redirect_uri") != "https://client.test/inner" || merged.Get("max_age") != "60" || merged.Get("scope") != "openid profile") {
					t.Fatal("request object precedence not applied")
				}
			}
		})
	}
}

func FuzzOIDCRequestObjects(f *testing.F) {
	f.Add(`{"alg":"none"}`, `{"client_id":"client","response_type":"code","scope":"openid"}`)
	f.Add(`{"alg":"none"}`, `{"exp":1001,"aud":"https://auth.test","max_age":60}`)
	f.Add(`{"alg":"none","crit":[]}`, `{"scope":"openid","scope":"admin"}`)
	f.Fuzz(func(t *testing.T, header, body string) {
		if len(header)+len(body) > oidcMaxRequestBytes {
			return
		}
		o := &Provider{clients: map[string]*ClientConfig{"client": {ClientID: "client"}}, config: Config{Issuer: "https://auth.test"}, now: func() time.Time { return time.Unix(1000, 0) }}
		v := url.Values{"client_id": {"client"}, "response_type": {"code"}, "scope": {"openid"}, "request": {oidcUnsecuredObject(header, body)}}
		merged, failure := o.requestObjectParameters(v)
		if failure == "" && (merged.Get("client_id") != "client" || merged.Get("response_type") != "code" || merged.Has("request") || merged.Has("request_uri")) {
			t.Fatal("request object changed client binding or nested request")
		}
	})
}

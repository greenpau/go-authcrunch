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

package authz

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"net/http/httptest"
	"testing"
)

type testRequest struct {
	id          string
	roles       []string
	method      string
	path        string
	headers     map[string]string
	query       map[string]string
	contentType string
	token       string
}

func TestAuthenticate(t *testing.T) {
	logger := logutil.NewLogger()

	cfg := &PolicyConfig{
		Name:        "mygatekeeper",
		AuthURLPath: "/auth",
		AccessListRules: []*acl.RuleConfiguration{
			{
				Conditions: []string{
					"match roles authp/admin authp/user",
				},
				Action: "allow stop",
			},
		},
		cryptoRawConfigs: []string{"key verify " + testutils.GetSharedKey()},
	}

	gatekeeper, err := NewGatekeeper(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}

	var testcases = []struct {
		name      string
		want      map[string]interface{}
		shouldErr bool
		err       error
		disabled  bool
		req       *testRequest
	}{
		{
			name: "admin accesses version with get",
			req: &testRequest{
				roles:  []string{"authp/admin"},
				method: "GET",
				path:   "/version",
			},
			want: map[string]interface{}{
				"response": map[string]interface{}{
					"authorized": true,
				},
				"status_code":  200,
				"content_type": "text/plain; charset=utf-8",
			},
		},
	}

	// Initialize HTTP server.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := requests.NewAuthorizationRequest()
		err := gatekeeper.Authenticate(w, r, rr)
		resp := make(map[string]interface{})
		if err != nil {
			resp["error"] = err
		}
		resp["response"] = rr.Response
		b, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("failed to marshal %T: %v", resp, err)
		}
		fmt.Fprintln(w, string(b))
	}))
	defer ts.Close()

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]interface{})
			if tc.req.method == "" {
				tc.req.method = "GET"
			}
			if tc.disabled {
				return
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("HTTP %s %s", tc.req.method, ts.URL+tc.req.path))

			client := buildClient(t, ts, tc.req)
			if len(tc.req.roles) > 0 {
				msgs = append(msgs, fmt.Sprintf("roles: %s", tc.req.roles))
			}
			if tc.req.token != "" {
				msgs = append(msgs, fmt.Sprintf("token: %s", tc.req.token))
			}

			req := buildRequest(t, ts, tc.req)

			resp, err := client.Do(req)
			if tests.EvalErrWithLog(t, err, "response error", tc.shouldErr, tc.err, msgs) {
				return
			}

			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}

			got["status_code"] = resp.StatusCode
			got["content_type"] = resp.Header.Get("Content-Type")
			switch resp.Header.Get("Content-Type") {
			case "image/png":
			default:
				msgs = append(msgs, fmt.Sprintf("response body: %s", body))
			}

			switch {
			case bytes.HasPrefix(body, []byte(`{`)):
				var decodedResponse map[string]interface{}
				json.Unmarshal(body, &decodedResponse)
				for k, v := range decodedResponse {
					got[k] = v
				}
			default:
				t.Fatalf("detected non-JSON body: %s", strings.Join(msgs, "\n"))
			}
			tests.EvalObjectsWithLog(t, "response body", tc.want, got, msgs)
		})
	}
}

func buildClient(t *testing.T, ts *httptest.Server, req *testRequest) http.Client {
	cert, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("failed extracting server certs: %v", err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(cert)

	cj, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("failed adding cookie jar: %v", err)
	}

	if len(req.roles) > 0 {
		usr := testutils.NewTestUser()
		usr.SetRolesClaim(req.roles)

		ks := testutils.NewTestCryptoKeyStore()
		if err := ks.SignToken("access_token", "HS512", usr); err != nil {
			t.Fatalf("Failed to get JWT token for %v: %v", usr.AsMap(), err)
		}
		cookies := []*http.Cookie{
			&http.Cookie{Name: "access_token", Value: usr.Token},
		}
		req.token = usr.Token

		tsURL, _ := url.Parse(ts.URL)
		cj.SetCookies(tsURL, cookies)
	}

	return http.Client{
		Jar:     cj,
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{
				RootCAs: cp,
			},
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			// Do not follow redirects.
			return http.ErrUseLastResponse
		},
	}
}

func buildRequest(t *testing.T, ts *httptest.Server, req *testRequest) *http.Request {
	r, err := http.NewRequest(req.method, ts.URL+req.path, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(req.headers) > 0 {
		for k, v := range req.headers {
			r.Header.Add(k, v)
		}
	}

	if len(req.query) > 0 {
		q := r.URL.Query()
		for k, v := range req.query {
			q.Set(k, v)
		}
		r.URL.RawQuery = q.Encode()
	}
	return r
}

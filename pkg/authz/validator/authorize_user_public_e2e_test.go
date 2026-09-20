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

package validator_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestE2EAuthorizeUserPublicContract(t *testing.T) {
	keyConfig, err := kms.NewCryptoKeyStoreConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := validator.NewTokenValidator(keyConfig, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)

	viewer, err := user.NewUser(`{"sub":"viewer","roles":["viewer"]}`)
	if err != nil {
		t.Fatal(err)
	}
	nonViewer, err := user.NewUser(`{"sub":"other","roles":["other"]}`)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(w http.ResponseWriter, r *http.Request) {
		usr := viewer
		if r.Header.Get("X-Test-Role") == "other" {
			usr = nonViewer
		}
		if err := v.AuthorizeUser(r.Context(), r, usr); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	request := func(role string, want int) {
		t.Helper()
		srv := httptest.NewTLSServer(http.HandlerFunc(serve))
		defer srv.Close()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/private", nil)
		if err != nil {
			t.Fatal(err)
		}
		if role != "" {
			req.Header.Set("X-Test-Role", role)
		}
		client := srv.Client()
		client.Timeout = 5 * time.Second
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("status %d, want %d", resp.StatusCode, want)
		}
	}

	request("", http.StatusForbidden)
	list := acl.NewAccessList()
	list.SetLogger(zap.NewNop())
	if err := list.AddRules(t.Context(), []*acl.RuleConfiguration{
		{Conditions: []string{"match roles viewer"}, Action: "allow stop"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.Configure(t.Context(), list, options.NewTokenValidatorOptions()); err != nil {
		t.Fatal(err)
	}
	request("", http.StatusNoContent)
	request("other", http.StatusForbidden)
	if err := v.AuthorizeUser(t.Context(), nil, viewer); err == nil {
		t.Fatal("validator accepted a nil request")
	}
}

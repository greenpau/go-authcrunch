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

package authproxy

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"go.uber.org/zap"
)

func TestRemoteAuthenticatorRejectsMalformedBasicCredentials(t *testing.T) {
	authenticator := &RemoteAuthenticator{realmName: "local"}
	for _, credentials := range []string{"alice", ":password", "alice:"} {
		t.Run(credentials, func(t *testing.T) {
			r := &Request{Secret: base64.StdEncoding.EncodeToString([]byte(credentials))}
			if err := authenticator.BasicAuth(r); err == nil {
				t.Fatal("BasicAuth() accepted malformed credentials")
			}
		})
	}
}

func TestE2ERemoteAuthenticatorResponseBoundary(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	newAuthenticator := func(t *testing.T, handler http.HandlerFunc) *RemoteAuthenticator {
		t.Helper()
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		authenticator, err := NewRemoteAuthenticator(
			"local",
			&kms.CryptoKey{Config: &kms.CryptoKeyConfig{ID: "internal", Secret: secret}},
			&RealmAuthProxyConfig{RemoteAddr: server.URL},
			zap.NewNop(),
		)
		if err != nil {
			t.Fatal(err)
		}
		return authenticator
	}
	request := func(authenticator *RemoteAuthenticator) error {
		return authenticator.BasicAuth(&Request{Address: "192.0.2.1", Secret: base64.StdEncoding.EncodeToString([]byte("alice:password"))})
	}

	t.Run("oversized response", func(t *testing.T) {
		var reached atomic.Bool
		authenticator := newAuthenticator(t, func(w http.ResponseWriter, _ *http.Request) {
			reached.Store(true)
			w.Header().Set("Content-Length", strconv.FormatInt(util.MaxHTTPResponseBodySize+1, 10))
			w.WriteHeader(http.StatusOK)
		})
		if err := request(authenticator); !errors.Is(err, util.ErrHTTPResponseBodyTooLarge) {
			t.Fatalf("error = %v, want %v", err, util.ErrHTTPResponseBodyTooLarge)
		}
		if !reached.Load() {
			t.Fatal("remote authentication server was not reached")
		}
	})

	t.Run("unexpected response remains private", func(t *testing.T) {
		const privateResponse = "synthetic-private-auth-response"
		authenticator := newAuthenticator(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(privateResponse))
		})
		err := request(authenticator)
		if err == nil || strings.Contains(err.Error(), privateResponse) {
			t.Fatalf("unsafe error = %v", err)
		}
	})
}

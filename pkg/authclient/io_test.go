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

package authclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

type failingResponseBody struct {
	err    error
	closed bool
}

func (b *failingResponseBody) Read([]byte) (int, error) { return 0, b.err }
func (b *failingResponseBody) Close() error             { b.closed = true; return nil }

type authRoundTripper func(*http.Request) (*http.Response, error)

func (f authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthenticateReadFailure(t *testing.T) {
	body := &failingResponseBody{err: io.ErrUnexpectedEOF}
	calls := 0
	client, err := NewClient(&Config{BaseURL: "https://portal.test/auth", Username: "user", Realm: "local"}, Options{
		HTTPClient: &http.Client{Transport: authRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			// Even a valid-looking prefix must not yield credentials if reading
			// the remainder fails. This models a connection cut during a response.
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: struct {
					io.Reader
					io.Closer
				}{io.MultiReader(strings.NewReader(`{"authenticated":true,"access_token":"test"}`), body), body},
			}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(context.Background())
	if credentials != nil || !errors.Is(err, io.ErrUnexpectedEOF) || !strings.Contains(err.Error(), "read authentication response") {
		t.Fatalf("expected wrapped response read failure, got %v", err)
	}
	if !body.closed {
		t.Fatal("failed response body was not closed")
	}
	if calls != 1 {
		t.Fatal("failed authentication request was retried")
	}
}

func TestExchangeInvalidContext(t *testing.T) {
	calls := 0
	client, err := NewClient(&Config{BaseURL: "https://portal.test", Username: "user", Realm: "local"}, Options{
		HTTPClient: &http.Client{Transport: authRoundTripper(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("unexpected HTTP request")
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The exchange helper preserves errors from HTTP request construction.
	response, err := client.exchange(nil, &apiauth.AuthRequest{Username: "user", Realm: "local"})
	if response != nil || err == nil || !strings.Contains(err.Error(), "create authentication request") {
		t.Fatalf("expected request construction failure, got %v", err)
	}
	if calls != 0 {
		t.Fatal("invalid request reached the HTTP transport")
	}
}

func TestAuthorizationRejectsInvalidCredentials(t *testing.T) {
	for _, tc := range []struct {
		name        string
		credentials Credentials
		want        string
	}{
		{name: "empty token", want: "access token is empty"},
		{name: "invalid name", credentials: Credentials{AccessToken: "private", AccessTokenName: "bad name"}, want: "invalid access token name"},
		{name: "invalid token", credentials: Credentials{AccessToken: "private\r\n"}, want: "invalid access token transport value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header, err := tc.credentials.Authorization()
			if header != "" || err == nil || err.Error() != tc.want {
				t.Fatalf("expected safe credential rejection, got %v", err)
			}
		})
	}
}

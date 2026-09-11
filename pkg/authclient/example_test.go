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

package authclient_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func ExampleClient_Authenticate() {
	// The example portal has a login endpoint and no admin API.
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/auth/login" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authenticated":true,"access_token":"example-token","access_token_name":"AUTHP_ACCESS_TOKEN"}`))
	}))
	defer portal.Close()

	client, err := authclient.NewClient(&authclient.Config{
		BaseURL:  portal.URL + "/auth",
		Username: "jsmith",
		Realm:    "local",
	}, authclient.Options{
		UserAgent: "caddy-authenticator",
		// A real CLI supplies Prompt, or configured password/TOTP credentials.
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	credentials, err := client.Authenticate(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}

	// The application chooses whether and where to persist the credentials.
	// Use os.UserHomeDir() in a CLI; use an isolated directory in this example.
	home, err := os.MkdirTemp("", "authclient-example-*")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.RemoveAll(home)
	store, err := authclient.NewFileTokenStore(filepath.Join(home, ".config", "caddy-authenticator", "token.jwt"))
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := store.Save(credentials); err != nil {
		fmt.Println(err)
		return
	}
	saved, err := store.Load()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(saved.AccessTokenName)
	// Output: authp_access_token
}

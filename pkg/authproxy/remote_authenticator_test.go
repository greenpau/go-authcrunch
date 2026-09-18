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
	"testing"
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

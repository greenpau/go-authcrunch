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

package user

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestSessionStateRestoresPrivateEvidenceAndACL(t *testing.T) {
	u, err := NewUser(map[string]any{"sub": "transformed", "email": "public@example.test", "jti": strings.Repeat("a", 32), "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"authp/user"}, "amr": []string{"pwd", "otp"}, "custom": map[string]any{"flag": "value"}})
	if err != nil {
		t.Fatal(err)
	}
	u.LoginEvidence = requests.AuthenticationEvidence{UserID: "immutable", BackendVersion: "epoch", CredentialVersion: 3, AuthenticatedAt: time.Now().Unix(), Method: "pwd"}
	u.LoginUsername = "canonical"
	u.LoginEmail = "canonical@example.test"
	u.LoginMethods = []string{"pwd", "otp"}
	u.Authenticator.TempSecret = "must not persist"
	u.Authenticator.TempChallenge = "unfinished challenge"
	u.Authenticator.TempSessionID = "unfinished session"
	u.Authenticator.NextChallenge = "totp"
	data, err := u.MarshalSession()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(u.Authenticator.TempSecret)) {
		t.Fatal("temporary factor secret persisted")
	}
	got, err := UnmarshalSession(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.LoginEvidence != u.LoginEvidence || got.LoginUsername != u.LoginUsername || !reflect.DeepEqual(got.LoginMethods, u.LoginMethods) || !reflect.DeepEqual(got.GetData(), u.GetData()) {
		t.Fatal("private proof or ACL state lost")
	}
	if got.Authenticator.TempSecret != "" || got.Authenticator.TempSessionID != "" || got.Authenticator.TempChallenge != "" || got.Authenticator.NextChallenge != "" {
		t.Fatal("unfinished authentication restored")
	}
	got.LoginMethods[0] = "modified"
	if u.LoginMethods[0] != "pwd" {
		t.Fatal("restoration aliases source")
	}
	public, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte("canonical")) || bytes.Contains(public, []byte("immutable")) {
		t.Fatal("private proof leaked in ordinary serialization")
	}
	if _, err := UnmarshalSession([]byte("invalid")); err == nil {
		t.Fatal("invalid state accepted")
	}
}

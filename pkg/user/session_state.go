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
	"encoding/gob"
	"encoding/json"
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type sessionState struct {
	Version                    int
	User, Claims               []byte
	Evidence                   requests.AuthenticationEvidence
	Username, Email, Transport string
	Methods                    []string
}

// MarshalSession encodes trusted completed-session state, including private
// login evidence. Store it only in authenticated private storage. It must never
// be returned through profile/config APIs or accepted as client authentication.
func (u *User) MarshalSession() ([]byte, error) {
	if u == nil || u.Claims == nil {
		return nil, fmt.Errorf("invalid session user")
	}
	snapshot := u.Clone()
	snapshot.Authenticator.TempSecret = ""
	snapshot.Authenticator.TempSessionID = ""
	snapshot.Authenticator.TempChallenge = ""
	snapshot.Authenticator.NextChallenge = ""
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode session user")
	}
	claims, err := json.Marshal(u.AsMap())
	if err != nil {
		return nil, fmt.Errorf("encode session claims")
	}
	v := sessionState{Version: 1, User: raw, Claims: claims, Evidence: u.LoginEvidence, Username: u.LoginUsername, Email: u.LoginEmail, Transport: u.RefreshTransport, Methods: u.LoginMethods}
	var out bytes.Buffer
	if gob.NewEncoder(&out).Encode(v) != nil {
		return nil, fmt.Errorf("encode session state")
	}
	return out.Bytes(), nil
}

// UnmarshalSession restores private trusted state and rebuilds derived ACL/role
// maps. It does not authenticate untrusted input or authorize a request.
func UnmarshalSession(data []byte) (*User, error) {
	var v sessionState
	if gob.NewDecoder(bytes.NewReader(data)).Decode(&v) != nil || v.Version != 1 {
		return nil, fmt.Errorf("invalid session state")
	}
	restored, err := NewUser(v.Claims)
	if err != nil {
		return nil, fmt.Errorf("invalid session claims")
	}
	var u User
	if json.Unmarshal(v.User, &u) != nil {
		return nil, fmt.Errorf("invalid session user")
	}
	u.Claims, u.mkv, u.tkv, u.rkv = restored.Claims, restored.mkv, restored.tkv, restored.rkv
	u.LoginEvidence, u.LoginUsername, u.LoginEmail = v.Evidence, v.Username, v.Email
	u.LoginMethods, u.RefreshTransport = v.Methods, v.Transport
	u.Cached = false
	return &u, nil
}

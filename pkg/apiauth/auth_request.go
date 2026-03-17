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

package apiauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// AuthRequest is authentication request.
type AuthRequest struct {
	Username            string `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	SandboxID           string `json:"sandbox_id,omitempty" xml:"sandbox_id,omitempty" yaml:"sandbox_id,omitempty"`
	SandboxSecret       string `json:"sandbox_secret,omitempty" xml:"sandbox_secret,omitempty" yaml:"sandbox_secret,omitempty"`
	ChallengeKind       string `json:"challenge_kind,omitempty" xml:"challenge_kind,omitempty" yaml:"challenge_kind,omitempty"`
	ChallengeResponse   string `json:"challenge_response,omitempty" xml:"challenge_response,omitempty" yaml:"challenge_response,omitempty"`
	Realm               string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	isChallengeResponse bool
}

// ParseAuthRequest parses AuthRequest.
func ParseAuthRequest(_ context.Context, w http.ResponseWriter, r *http.Request) (*AuthRequest, error) {
	authRequest := &AuthRequest{}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	respDecoder := json.NewDecoder(r.Body)
	respDecoder.DisallowUnknownFields()
	if err := respDecoder.Decode(authRequest); err != nil {
		return nil, err
	}
	if err := authRequest.Validate(); err != nil {
		return nil, err
	}
	return authRequest, nil
}

// HasChallengeResponse returns true if the AuthRequest contains challenge response.
func (r *AuthRequest) HasChallengeResponse() bool {
	return r.isChallengeResponse
}

// AsStringMap returns key-value map.
func (r *AuthRequest) AsStringMap() map[string]string {
	m := make(map[string]string)
	m["username"] = r.Username
	m["realm"] = r.Realm
	if r.isChallengeResponse {
		m["sandbox_id"] = r.SandboxID
		m["sandbox_secret"] = r.SandboxSecret
		m["challenge_kind"] = r.ChallengeKind
		m["challenge_response"] = r.ChallengeResponse
	}
	return m
}

// Validate validates the required AuthRequest fields.
func (r *AuthRequest) Validate() error {
	r.Username = strings.TrimSpace(r.Username)
	r.Realm = strings.TrimSpace(r.Realm)
	r.SandboxID = strings.TrimSpace(r.SandboxID)
	r.ChallengeResponse = strings.TrimSpace(r.ChallengeResponse)
	if r.Username == "" {
		return errors.New("required username field is empty")
	}
	if r.Realm == "" {
		return errors.New("required realm field is empty")
	}
	if r.SandboxID != "" || r.ChallengeResponse != "" || r.ChallengeKind != "" || r.SandboxSecret != "" {
		if r.SandboxID == "" {
			return errors.New("required sandbox_id field is empty")
		}
		if r.SandboxSecret == "" {
			return errors.New("required sandbox_secret field is empty")
		}
		if r.ChallengeKind == "" {
			return errors.New("required challenge_kind field is empty")
		}
		if r.ChallengeResponse == "" {
			return errors.New("required challenge_response field is empty")
		}
		r.isChallengeResponse = true
	}
	return nil
}

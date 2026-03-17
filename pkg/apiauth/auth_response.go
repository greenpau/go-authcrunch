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

// AuthResponse is the response to authentication request.
type AuthResponse struct {
	Authenticated    bool   `json:"authenticated,omitempty" xml:"authenticated,omitempty" yaml:"authenticated,omitempty"`
	AccessToken      string `json:"access_token,omitempty" xml:"access_token,omitempty" yaml:"access_token,omitempty"`
	AccessTokenName  string `json:"access_token_name,omitempty" xml:"access_token_name,omitempty" yaml:"access_token_name,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty" xml:"refresh_token,omitempty" yaml:"refresh_token,omitempty"`
	RefreshTokenName string `json:"refresh_token_name,omitempty" xml:"refresh_token_name,omitempty" yaml:"refresh_token_name,omitempty"`
	SandboxID        string `json:"sandbox_id,omitempty" xml:"sandbox_id,omitempty" yaml:"sandbox_id,omitempty"`
	SandboxSecret    string `json:"sandbox_secret,omitempty" xml:"sandbox_secret,omitempty" yaml:"sandbox_secret,omitempty"`
	NextChallenge    string `json:"next_challenge,omitempty" xml:"next_challenge,omitempty" yaml:"next_challenge,omitempty"`
}

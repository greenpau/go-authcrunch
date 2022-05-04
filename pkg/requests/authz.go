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

package requests

// AuthorizationRequest hold the data associated with request authorization.
type AuthorizationRequest struct {
	ID        string                `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	SessionID string                `json:"session_id,omitempty" xml:"session_id,omitempty" yaml:"session_id,omitempty"`
	Response  AuthorizationResponse `json:"response,omitempty" xml:"response,omitempty" yaml:"response,omitempty"`
	Redirect  RedirectResponse      `json:"-"`
	Token     AuthorizationToken    `json:"-"`
}

// AuthorizationResponse holds the response associated with AuthorizationRequest.
type AuthorizationResponse struct {
	User       map[string]interface{} `json:"-"`
	Authorized bool                   `json:"authorized" xml:"authorized" yaml:"authorized"`
	Bypassed   bool                   `json:"bypassed,omitempty" xml:"bypassed,omitempty" yaml:"bypassed,omitempty"`
	Error      error                  `json:"error,omitempty" xml:"error,omitempty" yaml:"error,omitempty"`
}

// AuthorizationToken holds the token found in an authorization request.
type AuthorizationToken struct {
	Found   bool   `json:"found,omitempty" xml:"found,omitempty" yaml:"found,omitempty"`
	Payload string `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
	Name    string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Source  string `json:"source,omitempty" xml:"source,omitempty" yaml:"source,omitempty"`
}

// RedirectResponse holds the redirect parameters associated with the
// response to AuthorizationRequest.
type RedirectResponse struct {
	Enabled          bool   `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	AuthURL          string `json:"auth_url,omitempty" xml:"auth_url,omitempty" yaml:"auth_url,omitempty"`
	Separator        string `json:"separator,omitempty" xml:"separator,omitempty" yaml:"separator,omitempty"`
	QueryParameter   string `json:"query_parameter,omitempty" xml:"query_parameter,omitempty" yaml:"query_parameter,omitempty"`
	QueryDisabled    bool   `json:"query_disabled,omitempty" xml:"query_disabled,omitempty" yaml:"query_disabled,omitempty"`
	URL              string `json:"url,omitempty" xml:"url,omitempty" yaml:"url,omitempty"`
	StatusCode       int    `json:"status_code,omitempty" xml:"status_code,omitempty" yaml:"status_code,omitempty"`
	LoginHint        string `json:"login_hint,omitempty" xml:"login_hint,omitempty" yaml:"login_hint,omitempty"`
	AdditionalScopes string `json:"additional_scopes,omitempty" xml:"additional_scopes,omitempty" yaml:"additional_scopes,omitempty"`
}

// NewAuthorizationRequest returns an instance of AuthorizationRequest.
func NewAuthorizationRequest() *AuthorizationRequest {
	return &AuthorizationRequest{}
}

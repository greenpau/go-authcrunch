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
	ID       string                `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Response AuthorizationResponse `json:"response,omitempty" xml:"response,omitempty" yaml:"response,omitempty"`
}

// AuthorizationResponse hold the response associated with AuthorizationRequest.
type AuthorizationResponse struct {
	Authorized bool  `json:"authorized,omitempty" xml:"authorized,omitempty" yaml:"authorized,omitempty"`
	Error      error `json:"error,omitempty" xml:"error,omitempty" yaml:"error,omitempty"`
}

// NewAuthorizationRequest returns an instance of AuthorizationRequest.
func NewAuthorizationRequest() *AuthorizationRequest {
	return &AuthorizationRequest{}
}

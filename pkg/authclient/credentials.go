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
	"fmt"
	"net/http"
)

// Credentials contains opaque portal credentials. The JSON fields retain the
// authdbctl token.jwt format, which is a JSON object rather than a bare JWT.
// Expiry and session fields are optional metadata from the portal, not locally
// verified claims. RefreshToken is retained when returned, but is never renewed
// by this package. Do not log this type or its Authorization value.
type Credentials struct {
	AccessToken      string `json:"access_token" xml:"access_token" yaml:"access_token"`
	AccessTokenName  string `json:"access_token_name,omitempty" xml:"access_token_name,omitempty" yaml:"access_token_name,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty" xml:"refresh_token,omitempty" yaml:"refresh_token,omitempty"`
	RefreshTokenName string `json:"refresh_token_name,omitempty" xml:"refresh_token_name,omitempty" yaml:"refresh_token_name,omitempty"`
	CreatedAt        string `json:"created_at,omitempty" xml:"created_at,omitempty" yaml:"created_at,omitempty"`
	SessionID        string `json:"session_id,omitempty" xml:"session_id,omitempty" yaml:"session_id,omitempty"`
	AccessExpiresAt  int64  `json:"access_expires_at,omitempty" xml:"access_expires_at,omitempty" yaml:"access_expires_at,omitempty"`
	RefreshExpiresAt int64  `json:"refresh_expires_at,omitempty" xml:"refresh_expires_at,omitempty" yaml:"refresh_expires_at,omitempty"`
	SessionExpiresAt int64  `json:"session_expires_at,omitempty" xml:"session_expires_at,omitempty" yaml:"session_expires_at,omitempty"`
}

// Validate checks transport syntax, not token authenticity or expiry. An omitted
// token name is allowed for legacy files and uses DefaultAccessTokenName.
func (c Credentials) Validate() error {
	if c.AccessToken == "" {
		return fmt.Errorf("access token is empty")
	}
	name := c.AccessTokenName
	if name == "" {
		name = DefaultAccessTokenName
	}
	if err := validateTokenName(name); err != nil {
		return err
	}
	if err := (&http.Cookie{Name: name, Value: c.AccessToken}).Valid(); err != nil {
		return fmt.Errorf("invalid access token transport value")
	}
	return nil
}

// Authorization returns the portal's name=token Authorization header value.
// Callers are responsible for sending it only to their intended trusted service.
func (c Credentials) Authorization() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	name := c.AccessTokenName
	if name == "" {
		name = DefaultAccessTokenName
	}
	return name + "=" + c.AccessToken, nil
}

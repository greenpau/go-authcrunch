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

package idp

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

// LoginIdentity is authenticated provider output, not caller-submitted claims.
// It deliberately cannot assert password/MFA evidence or reserved JWT fields.
type LoginIdentity struct {
	Subject string   `json:"subject,omitempty" xml:"subject,omitempty" yaml:"subject,omitempty"`
	Email   string   `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Name    string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Roles   []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
}

// Validate bounds authenticated identity data without changing it.
func (i *LoginIdentity) Validate() error {
	valid := func(value string, limit int) bool {
		return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
	}
	if i == nil || !valid(i.Subject, 256) || !valid(i.Email, 254) || (i.Name != "" && !valid(i.Name, 256)) || len(i.Roles) == 0 || len(i.Roles) > 32 {
		return fmt.Errorf("invalid provider login identity")
	}
	address, err := mail.ParseAddress(i.Email)
	if err != nil || address.Address != i.Email {
		return fmt.Errorf("invalid provider login identity")
	}
	for _, role := range i.Roles {
		if !valid(role, 128) {
			return fmt.Errorf("invalid provider login identity")
		}
	}
	return nil
}

// HTTPLoginResult returns exactly one of a pinned redirect or authenticated
// identity. Cookie is optional browser binding/deletion state; no HTTP output is
// published until Login succeeds. A supplied cookie must use the declared name,
// exact callback path, Secure, HttpOnly, host-only scope, and SameSite Lax or
// Strict. All fields are runtime-only.
type HTTPLoginResult struct {
	RedirectURL string         `json:"-" xml:"-" yaml:"-"`
	Identity    *LoginIdentity `json:"-" xml:"-" yaml:"-"`
	Cookie      *http.Cookie   `json:"-" xml:"-" yaml:"-"`
}

// HTTPLoginProvider optionally authenticates an injected IdentityProvider at
// /provider/<realm>. Implementations own protocol verification, browser binding,
// pinned destinations, expiry and replay prevention. Returned identity must be
// verified before success. The portal applies transforms, challenge policy and
// signing; this capability provides federated evidence, never local MFA evidence.
// The embedding host owns backend lifecycle and trusted issuance APIs.
type HTTPLoginProvider interface {
	Login(context.Context, *http.Request) (*HTTPLoginResult, error)
	// GetLoginCookieName declares binding state; empty forbids returned cookies.
	GetLoginCookieName() string
}

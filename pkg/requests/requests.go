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

import (
	"go.uber.org/zap"
	"net/http"
)

// Request hold the data associated with identity database
type Request struct {
	ID       string      `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Upstream Upstream    `json:"upstream,omitempty" xml:"upstream,omitempty" yaml:"upstream,omitempty"`
	Sandbox  Sandbox     `json:"sandbox,omitempty" xml:"sandbox,omitempty" yaml:"sandbox,omitempty"`
	User     User        `json:"user,omitempty" xml:"user,omitempty" yaml:"user,omitempty"`
	Query    Query       `json:"query,omitempty" xml:"query,omitempty" yaml:"query,omitempty"`
	Key      Key         `json:"key,omitempty" xml:"key,omitempty" yaml:"key,omitempty"`
	MfaToken MfaToken    `json:"mfa_token,omitempty" xml:"mfa_token,omitempty" yaml:"mfa_token,omitempty"`
	WebAuthn WebAuthn    `json:"web_authn,omitempty" xml:"web_authn,omitempty" yaml:"web_authn,omitempty"`
	Flags    Flags       `json:"flags,omitempty" xml:"flags,omitempty" yaml:"flags,omitempty"`
	Response Response    `json:"response,omitempty" xml:"response,omitempty" yaml:"response,omitempty"`
	Logger   *zap.Logger `json:"-"`
}

// Response hold the response associated with identity database
type Response struct {
	Code                int                 `json:"code,omitempty" xml:"code,omitempty" yaml:"code,omitempty"`
	RedirectURL         string              `json:"redirect_url,omitempty" xml:"redirect_url,omitempty" yaml:"redirect_url,omitempty"`
	Payload             interface{}         `json:"-"`
	RedirectTokenName   string              `json:"redirect_token_name,omitempty" xml:"redirect_token_name,omitempty" yaml:"redirect_token_name,omitempty"`
	Authenticated       bool                `json:"authenticated,omitempty" xml:"authenticated,omitempty" yaml:"authenticated,omitempty"`
	Authorized          bool                `json:"authorized,omitempty" xml:"authorized,omitempty" yaml:"authorized,omitempty"`
	IdentityTokenCookie IdentityTokenCookie `json:"-" xml:"-" yaml:"-"`
	// Workflow is the type of workflow the response should follow.
	Workflow string `json:"workflow,omitempty" xml:"workflow,omitempty" yaml:"workflow,omitempty"`
	Title    string `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	Message  string `json:"message,omitempty" xml:"message,omitempty" yaml:"message,omitempty"`
}

// IdentityTokenCookie holds the id_token cookie name and payload.
type IdentityTokenCookie struct {
	Name    string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Payload string `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
	Enabled bool   `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
}

// Upstream hold the upstream request handler metadata.
type Upstream struct {
	Request     *http.Request `json:"-"`
	Name        string        `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	SessionID   string        `json:"session_id,omitempty" xml:"session_id,omitempty" yaml:"session_id,omitempty"`
	BaseURL     string        `json:"base_url,omitempty" xml:"base_url,omitempty" yaml:"base_url,omitempty"`
	BasePath    string        `json:"base_path,omitempty" xml:"base_path,omitempty" yaml:"base_path,omitempty"`
	Method      string        `json:"method,omitempty" xml:"method,omitempty" yaml:"method,omitempty"`
	Realm       string        `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	ContentType string        `json:"content_type,omitempty" xml:"content_type,omitempty" yaml:"content_type,omitempty"`
	CookieNames []string      `json:"cookie_names,omitempty" xml:"cookie_names,omitempty" yaml:"cookie_names,omitempty"`
}

// Sandbox hold the data relevant to the user sandbox.
type Sandbox struct {
	ID     string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	View   string `json:"view,omitempty" xml:"view,omitempty" yaml:"view,omitempty"`
	Action string `json:"action,omitempty" xml:"action,omitempty" yaml:"action,omitempty"`
}

// Query hold request query attributes.
type Query struct {
	ID   string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
}

// User hold user attributes.
type User struct {
	Username    string   `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Email       string   `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Password    string   `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	OldPassword string   `json:"old_password,omitempty" xml:"old_password,omitempty" yaml:"old_password,omitempty"`
	FullName    string   `json:"full_name,omitempty" xml:"full_name,omitempty" yaml:"full_name,omitempty"`
	Roles       []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
	Disabled    bool     `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
	Challenges  []string `json:"challenges,omitempty" xml:"challenges,omitempty" yaml:"challenges,omitempty"`
}

// Key holds crypto key attributes.
type Key struct {
	ID       string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Prefix   string `json:"prefix,omitempty" xml:"prefix,omitempty" yaml:"prefix,omitempty"`
	Comment  string `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Usage    string `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	Payload  string `json:"payload,omitempty" xml:"payload,omitempty" yaml:"payload,omitempty"`
	Disabled bool   `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// MfaToken holds MFA token attributes.
type MfaToken struct {
	ID        string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Comment   string `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Type      string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Secret    string `json:"secret,omitempty" xml:"secret,omitempty" yaml:"secret,omitempty"`
	Algorithm string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Period    int    `json:"period,omitempty" xml:"period,omitempty" yaml:"period,omitempty"`
	Digits    int    `json:"digits,omitempty" xml:"digits,omitempty" yaml:"digits,omitempty"`
	Passcode  string `json:"passcode,omitempty" xml:"passcode,omitempty" yaml:"passcode,omitempty"`
	Disabled  bool   `json:"disabled,omitempty" xml:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// WebAuthn holds WebAuthn messages.
type WebAuthn struct {
	Register  string `json:"register,omitempty" xml:"register,omitempty" yaml:"register,omitempty"`
	Challenge string `json:"challenge,omitempty" xml:"challenge,omitempty" yaml:"challenge,omitempty"`
	Request   string `json:"request,omitempty" xml:"request,omitempty" yaml:"request,omitempty"`
}

// Flags holds various flags.
type Flags struct {
	Enabled       bool `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	MfaRequired   bool `json:"mfa_required,omitempty" xml:"mfa_required,omitempty" yaml:"mfa_required,omitempty"`
	MfaConfigured bool `json:"mfa_configured,omitempty" xml:"mfa_configured,omitempty" yaml:"mfa_configured,omitempty"`
	MfaApp        bool `json:"mfa_app,omitempty" xml:"mfa_app,omitempty" yaml:"mfa_app,omitempty"`
	MfaUniversal  bool `json:"mfa_universal,omitempty" xml:"mfa_universal,omitempty" yaml:"mfa_universal,omitempty"`
}

// NewRequest returns an instance of Request.
func NewRequest() *Request {
	return &Request{}
}

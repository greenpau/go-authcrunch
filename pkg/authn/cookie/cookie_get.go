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

package cookie

import (
	"fmt"
	"strings"
)

// GetAccessTokenCookie returns raw access token cookie string.
func (f *Factory) GetAccessTokenCookie(h, v string) string {
	var sb strings.Builder
	sb.WriteString(f.AccessTokenCookieName + "=" + v + ";")

	entry := f.evalHost(h)
	if entry != nil && entry.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", entry.Domain))
	}

	switch {
	case entry != nil && entry.Path != "":
		sb.WriteString(fmt.Sprintf(" Path=%s;", entry.Path))
	case f.config.Path != "":
		sb.WriteString(fmt.Sprintf(" Path=%s;", f.config.Path))
	default:
		sb.WriteString(" Path=/;")
	}

	switch {
	case entry != nil && entry.Lifetime != 0:
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", entry.Lifetime))
	case f.config.Lifetime != 0:
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}

	switch {
	case entry != nil && entry.SameSite != "":
		sb.WriteString(fmt.Sprintf(" SameSite=%s;", entry.SameSite))
	case f.config.SameSite != "":
		sb.WriteString(fmt.Sprintf(" SameSite=%s;", f.config.SameSite))
	}

	switch {
	case entry != nil && !entry.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	case !f.config.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	}

	return sb.String()
}

// GetIdentityTokenCookie returns raw identity token cookie string from key-value input.
func (f *Factory) GetIdentityTokenCookie(basePath string, k, v string) string {
	var sb strings.Builder
	sb.WriteString(k + "=" + v + ";")
	if !strings.HasSuffix(basePath, "/") {
		basePath = basePath + "/"
	}
	sb.WriteString(" Path=" + basePath + "whoami;")
	if f.config.Lifetime != 0 {
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}
	// sb.WriteString(" SameSite=Strict;")
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetRefererCookie returns raw identity token cookie string from key-value input.
func (f *Factory) GetRefererCookie(basePath string, v string) string {
	var sb strings.Builder
	sb.WriteString(f.RefererCookieName + "=" + v + ";")
	basePath = strings.TrimSuffix(basePath, "/")
	sb.WriteString(" Path=" + basePath + ";")
	if f.config.Lifetime != 0 {
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}
	// sb.WriteString(" SameSite=Strict;")
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetRefreshTokenCookie returns raw refresh token cookie string from key-value input.
func (f *Factory) GetRefreshTokenCookie(basePath string, v string) string {
	var sb strings.Builder
	sb.WriteString(f.RefreshTokenCookieName + "=" + v + ";")
	if !strings.HasSuffix(basePath, "/") {
		basePath = basePath + "/"
	}
	sb.WriteString(" Path=" + basePath + "api/refresh_token;")
	if f.config.Lifetime != 0 {
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}
	// sb.WriteString(" SameSite=Strict;")
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetSandboxIDCookie returns raw identity token cookie string from key-value input.
func (f *Factory) GetSandboxIDCookie(basePath string, v string) string {
	var sb strings.Builder
	sb.WriteString(f.SandboxIDCookieName + "=" + v + ";")
	basePath = strings.TrimSuffix(basePath, "/")
	sb.WriteString(" Path=" + basePath + ";")
	if f.config.Lifetime != 0 {
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}
	// sb.WriteString(" SameSite=Strict;")
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetSessionIDCookie return cookie holding session information
func (f *Factory) GetSessionIDCookie(h, s string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s=%s;", f.SessionIDCookieName, s))
	entry := f.evalHost(h)
	if entry != nil && entry.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", entry.Domain))
	}

	sb.WriteString(" Path=/;")

	switch {
	case entry != nil && !entry.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	case !f.config.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	}

	return sb.String()
}

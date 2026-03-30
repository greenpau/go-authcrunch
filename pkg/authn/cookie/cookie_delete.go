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

// GetDeleteAccessTokenCookie returns raw cookie with attributes for delete action.
func (f *Factory) GetDeleteAccessTokenCookie(h string) string {
	var sb strings.Builder
	sb.WriteString(f.AccessTokenCookieName)
	sb.WriteString("=delete;")
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

	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteSessionIDCookie returns raw cookie with attributes for delete action
// for session id cookie.
func (f *Factory) GetDeleteSessionIDCookie(h string) string {
	var sb strings.Builder
	sb.WriteString(f.SessionIDCookieName)
	sb.WriteString("=delete;")
	entry := f.evalHost(h)
	if entry != nil && entry.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", entry.Domain))
	}
	sb.WriteString(" Path=/;")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteIdentityTokenCookie returns raw identity token cookie with attributes for delete action.
func (f *Factory) GetDeleteIdentityTokenCookie(s, basePath string) string {
	var sb strings.Builder
	sb.WriteString(s)
	sb.WriteString("=delete;")
	if !strings.HasSuffix(basePath, "/") {
		basePath = basePath + "/"
	}
	sb.WriteString(" Path=" + basePath + "whoami;")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteRefreshTokenCookie returns raw refresh token cookie with attributes for delete action.
func (f *Factory) GetDeleteRefreshTokenCookie(basePath string) string {
	var sb strings.Builder
	sb.WriteString(f.RefreshTokenCookieName)
	sb.WriteString("=delete;")
	if !strings.HasSuffix(basePath, "/") {
		basePath = basePath + "/"
	}
	sb.WriteString(" Path=" + basePath + "api/refresh_token;")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteSandboxIDCookie returns raw sandbox ID cookie with attributes for delete action.
func (f *Factory) GetDeleteSandboxIDCookie(basePath string) string {
	var sb strings.Builder
	sb.WriteString(f.SandboxIDCookieName)
	sb.WriteString("=delete;")
	basePath = strings.TrimSuffix(basePath, "/")
	sb.WriteString(" Path=" + basePath + ";")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteRefererCookie returns raw sandbox ID cookie with attributes for delete action.
func (f *Factory) GetDeleteRefererCookie(basePath string) string {
	var sb strings.Builder
	sb.WriteString(f.RefererCookieName)
	sb.WriteString("=delete;")
	basePath = strings.TrimSuffix(basePath, "/")
	sb.WriteString(" Path=" + basePath + ";")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

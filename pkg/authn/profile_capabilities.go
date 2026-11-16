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

package authn

import (
	"context"
	"errors"
	"net/http"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func profileOperationSupported(c identity.StoreCapabilities, kind string) bool {
	switch kind {
	case "fetch_user_info", "fetch_user_dashboard_data", "fetch_debug":
		return c.ProfileRead
	case "update_user_password":
		return c.PasswordChange
	case "fetch_user_api_keys", "fetch_user_api_key", "delete_user_api_key", "add_user_api_key", "test_user_api_key":
		return c.APIKeys
	case "fetch_user_ssh_keys", "fetch_user_ssh_key", "delete_user_ssh_key", "add_user_ssh_key", "test_user_ssh_key",
		"fetch_user_gpg_keys", "fetch_user_gpg_key", "delete_user_gpg_key", "add_user_gpg_key", "test_user_gpg_key":
		return c.PublicKeys
	case "fetch_user_auth_challenges", "overwrite_user_auth_challenges":
		return c.AuthenticationFlows
	case "delete_user_multi_factor_authenticator", "fetch_user_multi_factor_authenticators", "fetch_user_multi_factor_authenticator",
		"fetch_user_app_multi_factor_authenticator_code", "test_user_app_multi_factor_authenticator", "add_user_app_multi_factor_authenticator",
		"test_user_webauthn_token", "test_user_app_token_passcode", "fetch_user_u2f_reg_params", "fetch_user_u2f_ver_params",
		"test_user_u2f_reg", "add_user_u2f_token":
		return c.MFA
	default:
		return false
	}
}

func profileBackendError(w http.ResponseWriter, rr *requests.Request, resp map[string]any, err error, fallback int) error {
	status, code := fallback, "operation_failed"
	switch {
	// Storage/commit uncertainty takes precedence over joined denial errors.
	case errors.Is(err, sqlitedb.ErrCommitUncertain):
		status, code = http.StatusServiceUnavailable, "commit_uncertain"
	case errors.Is(err, sqlitedb.ErrUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// SQLite preserves context errors when its transaction/lock budget ends.
		// They are backend failures, even when a mutation uses a 400 fallback.
		status, code = http.StatusServiceUnavailable, "storage_unavailable"
	case errors.Is(err, identity.ErrIdentityRequestDenied), errors.Is(err, identity.ErrRefreshIdentityDenied):
		status, code = http.StatusUnauthorized, "identity_required"
	}
	resp["message"], resp["code"] = http.StatusText(status), code
	return handleAPIProfileResponse(w, rr, status, resp)
}

// Omit unavailable dates instead of inventing creation or modification times.
func profileMetadata(u *identity.User) map[string]any {
	m := u.GetMetadata()
	out := map[string]any{"id": m.ID, "username": m.Username, "email": m.Email, "name": m.Name, "disabled": m.Disabled}
	if !m.Created.IsZero() {
		out["created"] = m.Created
	}
	if !m.LastModified.IsZero() {
		out["last_modified"] = m.LastModified
	}
	if m.Revision != 0 {
		out["revision"] = m.Revision
	}
	if m.Title != "" {
		out["title"] = m.Title
	}
	if m.Avatar != "" {
		out["avatar"] = m.Avatar
	}
	return out
}

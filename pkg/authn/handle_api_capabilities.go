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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// FeatureAvailability separates configuration, implementation and permission.
// It is informational: every API still performs its own authorization checks.
type FeatureAvailability struct {
	Enabled   bool   `json:"enabled" xml:"enabled" yaml:"enabled"`
	Supported bool   `json:"supported" xml:"supported" yaml:"supported"`
	Allowed   bool   `json:"allowed" xml:"allowed" yaml:"allowed"`
	Reason    string `json:"reason" xml:"reason" yaml:"reason"`
}

func featureAvailability(enabled, supported, permitted bool) FeatureAvailability {
	reason := "available"
	switch {
	case !enabled:
		reason = "disabled"
	case !permitted:
		reason = "forbidden"
	case !supported:
		reason = "unsupported_capability"
	}
	return FeatureAvailability{Enabled: enabled, Supported: supported, Allowed: enabled && supported && permitted, Reason: reason}
}

func writeCapabilityError(w http.ResponseWriter, rr *requests.Request, status int, code string) error {
	w.Header().Set("Content-Type", "application/json")
	rr.Response.Code = status
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "message": http.StatusText(status)})
}

// This endpoint needs a cached exact-token login, even when the caller only
// wants to learn that Profile/Admin/Documents is disabled. It is scoped to the
// logged-in backend; it cannot enumerate other stores or inspect accounts.
func (p *Portal) handleAPICapabilities(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, parsed *user.User) error {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		return writeCapabilityError(w, rr, http.StatusMethodNotAllowed, "invalid_request")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(body) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return writeCapabilityError(w, rr, http.StatusBadRequest, "invalid_request")
	}
	if parsed == nil {
		return writeCapabilityError(w, rr, http.StatusUnauthorized, "identity_required")
	}
	usr, err := p.sessions.GetForToken(parsed.Claims.ID, parsed.Token)
	if err != nil {
		return writeCapabilityError(w, rr, http.StatusUnauthorized, "identity_required")
	}
	if err := p.authorizedRole(usr, []role.Kind{role.User, role.Admin}, rr.Response.Authenticated); err != nil {
		return writeCapabilityError(w, rr, http.StatusForbidden, "forbidden")
	}
	admin := p.authorizedRole(usr, []role.Kind{role.Admin}, rr.Response.Authenticated) == nil
	caps := identity.StoreCapabilities{AdminOperations: []string{}}
	store := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
	bound := store != nil && store.GetKind() == usr.Authenticator.Method && store.GetName() == usr.Authenticator.Name
	// Descriptive metadata can survive a host wrapper that erases the actual
	// authenticated operation interface. Match the profile handler's contract.
	_, profileOperations := store.(ids.IdentityRequestStore)
	documentsSupported := false
	if bound {
		if verifier, ok := store.(refreshIdentityStore); ok {
			err := verifier.WithRefreshIdentity(ctx, usr.LoginEvidence, func(current identity.RefreshIdentity) error {
				if usr.LoginUsername == "" || current.Username != usr.LoginUsername || current.Email != usr.LoginEmail {
					return identity.ErrRefreshIdentityDenied
				}
				if _, err := p.sessions.GetForToken(parsed.Claims.ID, parsed.Token); err != nil {
					return identity.ErrRefreshIdentityDenied
				}
				return nil
			})
			if err != nil {
				switch {
				case errors.Is(err, sqlitedb.ErrCommitUncertain):
					return writeCapabilityError(w, rr, 503, "commit_uncertain")
				case errors.Is(err, sqlitedb.ErrUnavailable):
					return writeCapabilityError(w, rr, 503, "storage_unavailable")
				case errors.Is(err, identity.ErrRefreshIdentityDenied):
					return writeCapabilityError(w, rr, 401, "identity_required")
				default:
					return writeCapabilityError(w, rr, 503, "storage_unavailable")
				}
			}
			documentsSupported = true
		}
		if provider, ok := store.(identity.StoreCapabilityProvider); ok {
			caps = provider.GetCapabilities()
		}
	}
	if caps.AdminOperations == nil {
		caps.AdminOperations = []string{}
	}
	// Only public bytes are consulted; capability reads never export private keys.
	legacyKeys, err := p.keystore.GetJWKS()
	if err != nil {
		return writeCapabilityError(w, rr, 503, "storage_unavailable")
	}
	publicKeys := legacyKeys
	if p.accessSigner != nil {
		publicKeys = p.accessJWKS
	}
	jwks := featureAvailability(true, len(publicKeys) > 0, true)
	if !jwks.Supported {
		jwks.Reason = "no_eligible_keys"
	}
	// API configuration is optional for library consumers. Discovery remains
	// available when every configurable API has been omitted.
	api := p.config.API
	if api == nil {
		api = &APIConfig{}
	}
	export := featureAvailability(api.AdminEnabled && api.AdminFetchPrivateKeysEnabled, len(legacyKeys) > 0, admin)
	if export.Enabled && admin && !export.Supported {
		export.Reason = "no_eligible_keys"
	}
	docsAllowed := p.documentsConfig != nil && slices.Contains(p.documentsConfig.Realms, usr.Authenticator.Realm)
	// Partial providers may expose mutations without information reads. Any
	// implemented Profile operation family makes the API supported.
	profileSupported := profileOperations && (caps.ProfileRead || caps.PasswordChange ||
		caps.APIKeys || caps.PublicKeys || caps.MFA || caps.AuthenticationFlows)
	result := map[string]any{
		"backend":   map[string]string{"kind": usr.Authenticator.Method, "name": usr.Authenticator.Name, "realm": usr.Authenticator.Realm},
		"store":     caps,
		"profile":   featureAvailability(api.ProfileEnabled, profileSupported, true),
		"admin":     featureAvailability(api.AdminEnabled, len(caps.AdminOperations) > 0, admin),
		"documents": featureAvailability(p.documents != nil, documentsSupported, docsAllowed),
		"oidc":      featureAvailability(p.oidc != nil, bound && store.GetKind() == "local", p.oidcRealm(usr.Authenticator.Realm)),
		"jwks":      jwks, "private_key_export": export,
	}
	w.Header().Set("Content-Type", "application/json")
	rr.Response.Code = http.StatusOK
	return json.NewEncoder(w).Encode(result)
}

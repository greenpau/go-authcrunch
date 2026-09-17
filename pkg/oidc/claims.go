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

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// AuthenticationContext binds an operator-defined ACR value to all required
// completed authentication methods. The verifier must validate these methods;
// no authorization parameter supplies evidence. Order chooses the default ACR.
type AuthenticationContext struct {
	Value   string   `json:"value,omitempty" xml:"value,omitempty" yaml:"value,omitempty"`
	Methods []string `json:"methods,omitempty" xml:"methods,omitempty" yaml:"methods,omitempty"`
}

func validateAuthenticationContexts(contexts []AuthenticationContext) error {
	seen := map[string]bool{}
	for _, c := range contexts {
		if c.Value == "" || len(c.Value) > 256 || strings.ContainsAny(c.Value, " \t\r\n") || seen[c.Value] || len(c.Methods) == 0 || !oidcUniqueStrings(c.Methods) {
			return fmt.Errorf("invalid oidc authentication context")
		}
		seen[c.Value] = true
		for _, method := range c.Methods {
			if !slices.Contains([]string{"pwd", "otp", "hwk", "swk", "mfa", "sms", "tel", "email", "fpt", "face", "pin", "rba", "sc", "user", "wia"}, method) {
				return fmt.Errorf("unsupported oidc authentication context method")
			}
		}
	}
	return nil
}

var oidcScopeClaims = map[string][]string{
	"profile": {"name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email", "email_verified"}, "address": {"address"}, "phone": {"phone_number", "phone_number_verified"},
}

type oidcClaimRequest struct {
	essential bool
	values    []any
}
type oidcClaimsRequest map[string]map[string]oidcClaimRequest

// Parse each JSON object independently so duplicate members never become an
// ambiguous consent request. Unknown claims/extensions are ignored by Core.
func oidcClaimObject(data []byte) (map[string]json.RawMessage, error) {
	return oidcRequestObjectPart(base64.RawURLEncoding.EncodeToString(data))
}
func parseOIDCClaims(raw string, client *ClientConfig) (oidcClaimsRequest, error) {
	result := oidcClaimsRequest{}
	if raw == "" {
		return result, nil
	}
	object, err := oidcClaimObject([]byte(raw))
	if err != nil {
		return nil, err
	}
	for _, location := range []string{"userinfo", "id_token"} {
		data, ok := object[location]
		if !ok {
			continue
		}
		claims, err := oidcClaimObject(data)
		if err != nil {
			return nil, err
		}
		result[location] = map[string]oidcClaimRequest{}
		for name, data := range claims {
			req := oidcClaimRequest{}
			if string(data) != "null" {
				spec, err := oidcClaimObject(data)
				if err != nil {
					return nil, err
				}
				if essential, ok := spec["essential"]; ok {
					if string(essential) != "true" && string(essential) != "false" {
						return nil, fmt.Errorf("invalid essential claim")
					}
					req.essential = string(essential) == "true"
				}
				value, one := spec["value"]
				values, many := spec["values"]
				if one && many {
					return nil, fmt.Errorf("conflicting claim values")
				}
				if one {
					var v any
					if json.Unmarshal(value, &v) != nil || v == nil {
						return nil, fmt.Errorf("invalid claim value")
					}
					req.values = []any{v}
				}
				if many {
					if json.Unmarshal(values, &req.values) != nil || len(req.values) == 0 {
						return nil, fmt.Errorf("invalid claim values")
					}
				}
			}
			if name == "acr" || name == "sub" {
				for _, v := range req.values {
					if s, ok := v.(string); !ok || s == "" {
						return nil, fmt.Errorf("invalid identity claim value")
					}
				}
			}
			permitted := slices.Contains([]string{"sub", "acr", "auth_time", "amr"}, name)
			for scope, names := range oidcScopeClaims {
				if slices.Contains(names, name) && slices.Contains(client.Scopes, scope) {
					permitted = true
				}
			}
			if permitted {
				result[location][name] = req
			}
		}
	}
	return result, nil
}

func (r *oidcAuthorization) consentItems() []string {
	items := slices.Clone(r.scopes)
	for location, claims := range r.claims {
		for name := range claims {
			items = append(items, location+":"+name)
		}
	}
	slices.Sort(items)
	return items
}

func oidcCurrentClaims(current Identity, subject string) map[string]any {
	result := map[string]any{"sub": subject, "preferred_username": current.Username}
	if current.Name != "" {
		result["name"] = current.Name
	}
	if current.Email != "" {
		result["email"] = current.Email
		result["email_verified"] = current.EmailVerified
	}
	if current.Profile != nil {
		// Serialize only the closed, typed attribute model; it cannot introduce
		// issuer, subject, authentication or other protocol claims.
		data, _ := json.Marshal(current.Profile)
		var attributes map[string]any
		_ = json.Unmarshal(data, &attributes)
		if current.Profile.PhoneNumber == "" {
			delete(attributes, "phone_number_verified")
		}
		maps.Copy(result, attributes)
	}
	return result
}

func (o *Provider) authenticationContext(s *oidcSession, r *oidcAuthorization) string {
	var available []string
	for _, c := range o.config.AuthenticationContexts {
		if !slices.ContainsFunc(c.Methods, func(method string) bool { return !slices.Contains(s.methods, method) }) {
			available = append(available, c.Value)
		}
	}
	requested := r.acrValues
	if req, ok := r.claims["id_token"]["acr"]; ok && len(req.values) > 0 {
		requested = nil
		for _, v := range req.values {
			requested = append(requested, v.(string))
		}
	}
	for _, value := range requested {
		if slices.Contains(available, value) {
			return value
		}
	}
	if len(available) > 0 {
		return available[0]
	}
	return ""
}
func (o *Provider) satisfiesClaims(s *oidcSession, r *oidcAuthorization) bool {
	for _, location := range []string{"userinfo", "id_token"} {
		if req, ok := r.claims[location]["sub"]; ok && len(req.values) > 0 && !slices.Contains(req.values, any(s.subject)) {
			return false
		}
	}
	if req, ok := r.claims["id_token"]["acr"]; ok && req.essential {
		acr := o.authenticationContext(s, r)
		if acr == "" || (len(req.values) > 0 && !slices.Contains(req.values, any(acr))) {
			return false
		}
	}
	return true
}
func oidcDisclose(result, current map[string]any, r *oidcAuthorization, location string) {
	names := map[string]bool{}
	if location == "userinfo" {
		for _, scope := range r.scopes {
			for _, name := range oidcScopeClaims[scope] {
				names[name] = true
			}
		}
	}
	for name := range r.claims[location] {
		names[name] = true
	}
	for name := range names {
		if _, exists := result[name]; exists {
			continue
		}
		if value, ok := current[name]; ok {
			result[name] = value
		}
	}
}

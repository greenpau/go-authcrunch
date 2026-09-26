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

package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

type googleResponse struct {
	Response struct {
		Groups []struct {
			DisplayName string `json:"displayName"`
		} `json:"groups"`
	} `json:"response"`
}

func decodeGoogleUserGroups(data []byte) ([]string, error) {
	var parsed googleResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("failed to decode Google user groups: %w", err)
	}
	groups := make([]string, 0, len(parsed.Response.Groups))
	for i, group := range parsed.Response.Groups {
		if strings.TrimSpace(group.DisplayName) == "" {
			return nil, fmt.Errorf("google user group %d has no valid display name", i)
		}
		groups = append(groups, group.DisplayName)
	}
	return groups, nil
}

func mergeGoogleUserGroups(userData map[string]any, groups []string) error {
	roles := make([]string, 0, len(groups))
	if rawRoles, exists := userData["roles"]; exists {
		switch values := rawRoles.(type) {
		case []string:
			roles = append(roles, values...)
		case []any:
			for i, value := range values {
				role, ok := value.(string)
				if !ok || strings.TrimSpace(role) == "" {
					return fmt.Errorf("existing user role %d is invalid", i)
				}
				roles = append(roles, role)
			}
		default:
			return fmt.Errorf("existing user roles have invalid type %T", rawRoles)
		}
	}
	roles = append(roles, groups...)
	userData["roles"] = roles
	return nil
}

func (b *IdentityProvider) fetchUserGroups(tokenData, userData map[string]interface{}) error {
	var userURL string
	var req *http.Request
	var err error

	if b.config.Driver != "google" || !b.ScopeExists(
		"https://www.googleapis.com/auth/cloud-identity.groups.readonly",
		"https://www.googleapis.com/auth/cloud-identity.groups",
	) {
		return nil
	}
	if tokenData == nil || userData == nil {
		return nil
	}

	accessToken, exists := tokenData["access_token"].(string)
	if !exists || strings.TrimSpace(accessToken) == "" {
		return fmt.Errorf("access_token is missing or is not a non-empty string")
	}
	email, exists := userData["email"].(string)
	if !exists || strings.TrimSpace(email) == "" {
		return fmt.Errorf("email is missing or is not a non-empty string")
	}

	cli, err := b.newBrowser()
	if err != nil {
		return err
	}

	switch b.config.Driver {
	case "google":
		userURL = "https://cloudidentity.googleapis.com/v1/groups/-/memberships:getMembershipGraph?query="
		userURL += url.QueryEscape("'cloudidentity.googleapis.com/groups.discussion_forum' in labels && member_key_id=='" + email + "'")

		req, err = http.NewRequest("GET", userURL, nil)
		if err != nil {
			return err
		}
		req.Header.Add("Authorization", "Bearer "+accessToken)
	default:
		return fmt.Errorf("provider %s is unsupported for fetching user groups", b.config.Driver)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	respBody, err := readOAuthSuccessResponse(resp, "Google user groups")
	if err != nil {
		return err
	}

	b.logger.Debug(
		"User groups received",
		zap.Any("body", respBody),
		zap.String("url", userURL),
	)

	switch b.config.Driver {
	case "google":
		userGroups, err := decodeGoogleUserGroups(respBody)
		if err != nil {
			return err
		}
		if err := mergeGoogleUserGroups(userData, userGroups); err != nil {
			return err
		}

	default:
		return fmt.Errorf("provider %s is unsupported for fetching user groups", b.config.Driver)
	}

	return nil
}

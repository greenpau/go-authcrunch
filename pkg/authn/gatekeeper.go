// Copyright 2024 Paul Greenberg greenpau@outlook.com
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
	"fmt"
	"slices"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func (p *Portal) authorizedRole(usr *user.User, authorizedRoles []role.Kind, authenticated bool) error {
	if !authenticated {
		if slices.Contains(authorizedRoles, role.Anonymous) {
			return nil
		}
		return fmt.Errorf("user is not authenticated")
	}

	if slices.Contains(authorizedRoles, role.User) {
		for roleName := range p.config.PortalUserRoles {
			if usr.HasRole(roleName) {
				return nil
			}
		}
		for _, roleNamePattern := range p.config.userRolePatterns {
			if usr.HasRolePattern(roleNamePattern) {
				return nil
			}
		}
	}

	if slices.Contains(authorizedRoles, role.Admin) {
		for roleName := range p.config.PortalAdminRoles {
			if usr.HasRole(roleName) {
				return nil
			}
		}
		for _, roleNamePattern := range p.config.adminRolePatterns {
			if usr.HasRolePattern(roleNamePattern) {
				return nil
			}
		}
	}

	return fmt.Errorf("user is not authorized")
}

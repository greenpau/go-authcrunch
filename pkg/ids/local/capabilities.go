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

package local

import "github.com/greenpau/go-authcrunch/pkg/identity"

// GetCapabilities describes the local store's implemented self-service and
// administration operations. Connected-account self-service is not implemented.
func (b *IdentityStore) GetCapabilities() identity.StoreCapabilities {
	return identity.StoreCapabilities{
		ProfileRead: true, PasswordChange: true, APIKeys: true, PublicKeys: true,
		MFA: true, AuthenticationFlows: true, Documents: true,
		AdminOperations: []string{"info", "add", "delete", "disable", "enable", "reset_password", "overwrite_roles", "add_roles", "overwrite_auth_challenges"},
	}
}

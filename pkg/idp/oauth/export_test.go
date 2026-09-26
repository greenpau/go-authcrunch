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

package oauth

// SetStateCapacityForTesting sets the provider's bounded login-state capacity.
func (b *IdentityProvider) SetStateCapacityForTesting(capacity int) {
	b.state.mux.Lock()
	defer b.state.mux.Unlock()
	b.state.maxStates = capacity
}

// StateCountForTesting returns the current number of provider login states.
func (b *IdentityProvider) StateCountForTesting() int {
	b.state.mux.Lock()
	defer b.state.mux.Unlock()
	return len(b.state.states)
}

// FetchClaimsForTesting exercises the named-driver UserInfo claim path.
func (b *IdentityProvider) FetchClaimsForTesting(data map[string]any) (map[string]any, error) {
	return b.fetchClaims(data)
}

// FetchUserGroupsForTesting exercises provider-specific group enrichment.
func (b *IdentityProvider) FetchUserGroupsForTesting(tokenData, userData map[string]any) error {
	return b.fetchUserGroups(tokenData, userData)
}

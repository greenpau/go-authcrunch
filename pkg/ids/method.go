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

package ids

import (
	"fmt"
)

// IdentityStoreType identifies identity store type.
type IdentityStoreType int

const (
	// UNKNOWN is unknown identity store type.
	UNKNOWN IdentityStoreType = iota
	// LOCAL identifies local identity store.
	LOCAL
	// LDAP identifies local LDAP identity store.
	LDAP
)

// String returns the description for IdentityStoreType enum.
func (m IdentityStoreType) String() string {
	switch m {
	case UNKNOWN:
		return "UNKNOWN"
	case LOCAL:
		return "LOCAL"
	case LDAP:
		return "LDAP"
	}
	return fmt.Sprintf("IdentityStoreType(%d)", int(m))
}

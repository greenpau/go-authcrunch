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

package role

import (
	"fmt"
)

// Kind is the type of a role.
type Kind int

const (
	// Unknown operator signals invalid role type.
	Unknown Kind = iota
	// Anonymous indicates anonymous.
	Anonymous
	// Admin indicates role with administrative privileges.
	Admin
	// User indicates role with user privileges.
	User
	// Guest indicates role with guest privileges.
	Guest
)

// String returns string representation of a role type.
func (e Kind) String() string {
	switch e {
	case Unknown:
		return "Unknown"
	case Anonymous:
		return "Anonymous"
	case Admin:
		return "Admin"
	case User:
		return "User"
	case Guest:
		return "Guest"
	}
	return fmt.Sprintf("RoleKind(%d)", int(e))
}

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

package identity

import (
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"strings"
)

// Role is the user role or entitlement in a system.
type Role struct {
	Name         string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Organization string `json:"organization,omitempty" xml:"organization,omitempty" yaml:"organization,omitempty"`
}

// NewRole returns an instance of Role.
func NewRole(s string) (*Role, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.ErrRoleEmpty
	}
	parts := strings.Split(s, "/")
	role := &Role{}
	if len(parts) == 1 {
		role.Name = s
		return role, nil
	}
	role.Organization = parts[0]
	role.Name = strings.Join(parts[1:], "/")
	return role, nil
}

// String returns string representation of Role instance.
func (r *Role) String() string {
	if r.Organization == "" {
		return r.Name
	}
	return r.Organization + "/" + r.Name
}

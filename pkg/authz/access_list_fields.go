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

package authz

import (
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// ConfigureAccessListFields replaces the policy's custom ACL declarations with
// an independently owned snapshot. Call once with all parsed declarations before
// Validate or runtime construction. Rules and unrelated settings are preserved.
// Nil clears the declarations; duplicate or invalid definitions leave the policy
// unchanged. A live policy must not be reconfigured while serving requests.
func (cfg *PolicyConfig) ConfigureAccessListFields(fields []*acl.FieldConfig) error {
	if cfg == nil {
		return errors.ErrACLFieldConfig.WithArgs("policy must not be nil")
	}
	if _, err := acl.NewAccessListWithFields(fields); err != nil {
		return err
	}
	var snapshot []*acl.FieldConfig
	if fields != nil {
		snapshot = make([]*acl.FieldConfig, len(fields))
		for i, field := range fields {
			copy := *field
			snapshot[i] = &copy
		}
	}
	cfg.AccessListFields = snapshot
	cfg.validated = false
	return nil
}

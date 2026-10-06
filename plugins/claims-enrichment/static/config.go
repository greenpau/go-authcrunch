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

// Package static adds configured, literal JSON claims to authorization decisions.
package static

import (
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
)

// Source identifies this backend in the consumer's trusted binding.
const Source = "static"

// Version identifies this backend's claim contract.
const Version = "v1"

// Config supplies the same JSON claims for every identity accepted by the
// consumer's binding. It contains no templates or identity-specific records.
type Config struct {
	Claims map[string]any `json:"claims,omitempty" xml:"claims,omitempty" yaml:"claims,omitempty"`
}

// Validate rejects invalid names, protected claims and oversized values.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("static claims config is required")
	}
	if len(c.Claims) == 0 || len(c.Claims) > 32 {
		return fmt.Errorf("static claims requires 1-32 claims")
	}
	for name, value := range c.Claims {
		if err := (enrichment.AttributeConfig{Name: name, Type: "json"}).Validate(); err != nil {
			return err
		}
		if _, err := enrichment.CopyAttribute(value, "json"); err != nil {
			return err
		}
	}
	return nil
}

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

// Package config owns serialized transform settings and their runtime snapshot.
package config

import (
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authchal"
)

// Config represents one matching user transformation. Order is significant.
// The parser package decodes the established encoded matcher/action lists.
type Config struct {
	Matchers []string `json:"matchers,omitempty" xml:"matchers,omitempty" yaml:"matchers,omitempty"`
	Actions  []string `json:"actions,omitempty" xml:"actions,omitempty" yaml:"actions,omitempty"`
}

// RuntimeConfig is compiled, detached runtime state, never persisted configuration.
type RuntimeConfig struct {
	Matcher                  *acl.AccessList   `json:"-" xml:"-" yaml:"-"`
	Actions                  [][]string        `json:"-" xml:"-" yaml:"-"`
	AuthenticationChallenges *authchal.Ruleset `json:"-" xml:"-" yaml:"-"`
}

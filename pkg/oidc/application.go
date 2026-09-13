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

package oidc

import (
	"fmt"
	"strings"
)

// OAuthApplicationConfig associates a configuration nickname with a persisted
// client registration. Name is independent of the protocol client ID and display
// name. This configuration contains credentials and belongs in trusted storage.
type OAuthApplicationConfig struct {
	Name   string        `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Client *ClientConfig `json:"client,omitempty" xml:"client,omitempty" yaml:"client,omitempty"`
}

// NewOAuthApplicationConfig validates and copies a named registration. It never
// generates credentials. Provision a client with NewClientConfig first when
// needed, then persist this result before adapting configuration or serving it.
func NewOAuthApplicationConfig(name string, client *ClientConfig) (*OAuthApplicationConfig, error) {
	config := &OAuthApplicationConfig{Name: name}
	if client != nil {
		config.Client = cloneClientConfig(*client)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// Validate normalizes a named registration without provisioning credentials.
func (c *OAuthApplicationConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("oauth application is nil")
	}
	if c.Name == "" || len(c.Name) > 256 || strings.TrimSpace(c.Name) != c.Name || strings.ContainsAny(c.Name, "\r\n\t") {
		return fmt.Errorf("invalid oauth application nickname")
	}
	return c.Client.Validate()
}

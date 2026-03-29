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

package system

import (
	"encoding/json"
	"fmt"
)

// APIKeyAuthRequestKindKeyword is the keyword associated with APIKeyAuthRequestMessage.
const APIKeyAuthRequestKindKeyword = "api_key_auth_request"

// APIKeyAuthRequestMessage represents API key authentication.
type APIKeyAuthRequestMessage struct {
	Kind    string `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	APIKey  string `json:"api_key,omitempty" xml:"api_key,omitempty" yaml:"api_key,omitempty"`
	Realm   string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Address string `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
}

// ToJSON implements the Message interface for APIKeyAuthRequestMessage.
func (m *APIKeyAuthRequestMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// AsMap returns the APIKeyAuthRequestMessage as a map of strings to any values.
func (m *APIKeyAuthRequestMessage) AsMap() (map[string]any, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal APIKeyAuthRequestMessage: %w", err)
	}

	var res map[string]any
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal into map: %w", err)
	}

	return res, nil
}

// Validate validates APIKeyAuthRequestMessage.
func (m *APIKeyAuthRequestMessage) Validate() error {
	if m.Kind != APIKeyAuthRequestKindKeyword {
		return fmt.Errorf("kind field mismatch, want %q, got %q", APIKeyAuthRequestKindKeyword, m.Kind)
	}
	if m.APIKey == "" {
		return fmt.Errorf("api_key field empty")
	}
	if m.Realm == "" {
		return fmt.Errorf("realm field empty")
	}
	if m.Address == "" {
		return fmt.Errorf("address field empty")
	}
	return nil
}

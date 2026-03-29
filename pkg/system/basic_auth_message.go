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

// BasicAuthRequestKindKeyword is the keyword associated with BasicAuthRequestMessage.
const BasicAuthRequestKindKeyword = "basic_auth_request"

// BasicAuthRequestMessage represents username/password authentication.
type BasicAuthRequestMessage struct {
	Kind     string `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	Username string `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	Realm    string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Address  string `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
}

// ToJSON implements the Message interface for BasicAuthRequestMessage.
func (m *BasicAuthRequestMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// AsMap returns BasicAuthRequestMessage as a map of strings to any values.
func (m *BasicAuthRequestMessage) AsMap() (map[string]any, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal BasicAuthRequestMessage: %w", err)
	}

	var res map[string]any
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal into map: %w", err)
	}

	return res, nil
}

// Validate validates BasicAuthRequestMessage.
func (m *BasicAuthRequestMessage) Validate() error {
	if m.Kind != BasicAuthRequestKindKeyword {
		return fmt.Errorf("kind field mismatch, want %q, got %q", BasicAuthRequestKindKeyword, m.Kind)
	}
	if m.Username == "" {
		return fmt.Errorf("username field empty")
	}
	if m.Password == "" {
		return fmt.Errorf("password field empty")
	}
	if m.Realm == "" {
		return fmt.Errorf("realm field empty")
	}
	if m.Address == "" {
		return fmt.Errorf("address field empty")
	}
	return nil
}

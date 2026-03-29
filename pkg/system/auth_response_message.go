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

// AuthResponseKindKeyword is the keyword associated with AuthResponseKindKeyword.
const AuthResponseKindKeyword = "auth_response"

// AuthResponseMessage represents authentication response.
type AuthResponseMessage struct {
	ID            string         `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Kind          string         `json:"kind,omitempty" xml:"kind,omitempty" yaml:"kind,omitempty"`
	Authenticated bool           `json:"authenticated" xml:"authenticated" yaml:"authenticated"`
	UserData      map[string]any `json:"user_data,omitempty" xml:"user_data,omitempty" yaml:"user_data,omitempty"`
	Reason        string         `json:"reason,omitempty" xml:"reason,omitempty" yaml:"reason,omitempty"`
	Timestamp     string         `json:"timestamp,omitempty" xml:"timestamp,omitempty" yaml:"timestamp,omitempty"`
}

// ToJSON implements the Message interface for AuthResponseMessage.
func (m *AuthResponseMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// AsMap returns AuthResponseMessage as a map of strings to any values.
func (m *AuthResponseMessage) AsMap() (map[string]any, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AuthResponseMessage: %w", err)
	}

	var res map[string]any
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal into map: %w", err)
	}

	return res, nil
}

// Validate validates AuthResponseMessage.
func (m *AuthResponseMessage) Validate() error {
	if m.Kind != BasicAuthRequestKindKeyword {
		return fmt.Errorf("kind field mismatch, want %q, got %q", BasicAuthRequestKindKeyword, m.Kind)
	}
	if m.ID == "" {
		return fmt.Errorf("id field empty")
	}
	return nil
}

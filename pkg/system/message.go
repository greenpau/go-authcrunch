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

// Message interface defines the behavior for system messages.
type Message interface {
	ToJSON() ([]byte, error)
	AsMap() (map[string]any, error)
	Validate() error
}

// ParseMessage takes in either JSON string or JSON []byte and returns a Message.
func ParseMessage(data interface{}) (Message, error) {
	var b []byte

	switch v := data.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	case *BasicAuthRequestMessage:
		return v, nil
	case *APIKeyAuthRequestMessage:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported data type: %T", data)
	}

	// Helper to extract the "kind" field
	var base struct {
		Kind string `json:"kind"`
	}

	if err := json.Unmarshal(b, &base); err != nil {
		return nil, fmt.Errorf("failed to parse message kind: %v", err)
	}

	switch base.Kind {
	case BasicAuthRequestKindKeyword:
		msg := &BasicAuthRequestMessage{}
		if err := json.Unmarshal(b, msg); err != nil {
			return nil, err
		}
		return msg, nil
	case APIKeyAuthRequestKindKeyword:
		msg := &APIKeyAuthRequestMessage{}
		if err := json.Unmarshal(b, msg); err != nil {
			return nil, err
		}
		return msg, nil
	case AuthResponseKindKeyword:
		msg := &AuthResponseMessage{}
		if err := json.Unmarshal(b, msg); err != nil {
			return nil, err
		}
		return msg, nil
	default:
		return nil, fmt.Errorf("unknown message kind: %s", base.Kind)
	}
}

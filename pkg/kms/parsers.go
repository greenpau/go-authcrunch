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

package kms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ParsePayloadFromToken extracts payload from a token.
func ParsePayloadFromToken(s string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	arr := strings.SplitN(s, ".", 3)
	if len(arr) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	payload := arr[1]
	if i := len(payload) % 4; i != 0 {
		payload += strings.Repeat("=", 4-i)
	}
	var decodedStr []byte
	var err error
	if strings.ContainsAny(payload, "/+") {
		// This decoding works with + and / signs. (legacy)
		decodedStr, err = base64.StdEncoding.DecodeString(payload)
	} else {
		// This decoding works with - and _ signs.
		decodedStr, err = base64.URLEncoding.DecodeString(payload)
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(decodedStr, &m); err != nil {
		return nil, err
	}
	return m, nil
}

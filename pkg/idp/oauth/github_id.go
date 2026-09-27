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

package oauth

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Read id from the original JSON, before a generic map can round a number to
// float64. Missing IDs remain compatible with legacy profile responses; a
// supplied ID must be a positive JSON integer representable as uint64.
func githubIDFromProfile(body []byte) (string, error) {
	var profile map[string]json.RawMessage
	if err := json.Unmarshal(body, &profile); err != nil {
		return "", fmt.Errorf("invalid GitHub profile")
	}
	rawID, exists := profile["id"]
	if !exists {
		return "", nil
	}
	var id uint64
	if err := json.Unmarshal(rawID, &id); err != nil || id == 0 {
		return "", fmt.Errorf("GitHub profile id must be a positive unsigned 64-bit integer")
	}
	return strconv.FormatUint(id, 10), nil
}

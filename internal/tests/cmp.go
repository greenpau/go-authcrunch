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

package tests

import (
	"encoding/json"
	"testing"
)

// Unpack converts input to map.
func Unpack(t *testing.T, i interface{}) (m map[string]interface{}) {
	switch v := i.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			t.Fatalf("failed to parse %q: %v", v, err)
		}
	default:
		b, err := json.Marshal(i)
		if err != nil {
			t.Fatalf("failed to marshal %T: %v", i, err)
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("failed to parse %q: %v", b, err)
		}
	}
	return m
}

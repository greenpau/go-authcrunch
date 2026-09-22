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

package identity

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestPasswordHashConfig(t *testing.T) {
	for _, c := range []PasswordHashConfig{{}, {Algorithm: "argon2"}, {Algorithm: "argon2", Memory: 8192, Iterations: 2, Parallelism: 2}, {Algorithm: "bcrypt", Cost: 8}} {
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, codec := range []struct {
			marshal   func(any) ([]byte, error)
			unmarshal func([]byte, any) error
		}{{json.Marshal, json.Unmarshal}, {xml.Marshal, xml.Unmarshal}, {yaml.Marshal, yaml.Unmarshal}} {
			data, err := codec.marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var got PasswordHashConfig
			if err := codec.unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(c, got); diff != "" {
				t.Fatal(diff)
			}
		}
	}
	for _, c := range []*PasswordHashConfig{nil, {Algorithm: "unknown"}, {Cost: 7}, {Cost: 32}, {Memory: 8192}, {Iterations: 1}, {Parallelism: 1}, {Algorithm: "argon2", Cost: 10}, {Algorithm: "argon2", Memory: -1}, {Algorithm: "argon2", Iterations: -1}, {Algorithm: "argon2", Parallelism: 17}, {Algorithm: "argon2", Memory: 262144, Iterations: 10}} {
		if c.Validate() == nil {
			t.Fatal("invalid configuration accepted")
		}
		if p, err := NewPasswordWithConfig("password", "generic", c); err == nil || p != nil {
			t.Fatal("invalid constructor configuration accepted")
		}
	}
}

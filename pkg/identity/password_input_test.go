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

import "testing"

func TestIsPasswordHashImport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{name: "bcrypt prefix", candidate: "bcrypt:malformed", want: true},
		{name: "padded argon2 prefix", candidate: " \targon2:malformed\n", want: true},
		{name: "similar prefix", candidate: "argon2x:plaintext"},
		{name: "plaintext", candidate: "ordinary plaintext"},
		{name: "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPasswordHashImport(tc.candidate); got != tc.want {
				t.Errorf("IsPasswordHashImport result = %t, want %t", got, tc.want)
			}
		})
	}
}

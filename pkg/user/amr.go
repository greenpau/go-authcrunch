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

package user

// amrMap translates internal challenge keywords to RFC 8176 amr values.
var amrMap = map[string]string{
	"password": "pwd",
	"totp":     "otp",
	"u2f":      "hwk",
	"mfa":      "mfa",
	"email":    "mail",
}

// ToAuthMethodReferences maps internal challenge keywords to RFC 8176 amr
// values. Unknown keywords are skipped; order is preserved; duplicates removed.
func ToAuthMethodReferences(internal []string) []string {
	if len(internal) == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, in := range internal {
		mapped, ok := amrMap[in]
		if !ok {
			continue
		}
		if seen[mapped] {
			continue
		}
		seen[mapped] = true
		out = append(out, mapped)
	}
	return out
}

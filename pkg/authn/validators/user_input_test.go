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

package validators

import "testing"

func TestValidateRegistrationSecretRejectsPasswordHashImports(t *testing.T) {
	for i, candidate := range []string{
		"bcrypt:malformed",
		" \targon2:malformed\n",
		"bcrypt:10:$2a$10$7EqJtq98hPqEX7fNZaFWoO5yK2ZBq9S5O5zGxF5g4x8k.rV9pYH3K",
		"argon2:$argon2id$v=19$m=8,t=1,p=1$MDEyMzQ1Njc$MDEyMzQ1Njc4OWFiY2RlZg",
	} {
		if err := ValidateUserInput("secret", candidate, nil); err == nil {
			t.Errorf("password hash import case %d passed registration validation", i)
		}
	}
	for i, candidate := range []string{"ordinary plaintext", "argon2x:plaintext", "bcryptx:plaintext"} {
		if err := ValidateUserInput("secret", candidate, nil); err != nil {
			t.Errorf("plaintext case %d failed registration validation: %v", i, err)
		}
	}
}

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
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// This synthetic credential is never eligible to authenticate an identity.
// Its salt and checksum remain fixed; only the work factor is substituted.
const dummyPasswordHash = "$2a$10$4xaU6KMqOfcdoZ5DhtIvKuePgy62eGAvZYYwGM/f5/fwB9ZXEAgtG"

// passwordVerifier gives every identity the same bcrypt comparison schedule.
// Each cost gets the largest active-password count at that cost in the store.
// This also covers databases with mixed costs or multiple active passwords.
type passwordVerifier struct {
	checks  [bcrypt.MaxCost + 1]int
	compare func([]byte, []byte) error
}

// The caller must hold the database read lock throughout construction and use.
// Rebuilding from current records avoids stale work factors after password or
// account changes, including changes made through the exported user model.
func newPasswordVerifier(users []*User) *passwordVerifier {
	v := &passwordVerifier{compare: bcrypt.CompareHashAndPassword}
	var hasChecks bool
	for _, user := range users {
		if user == nil || user.Disabled {
			continue
		}
		var counts [bcrypt.MaxCost + 1]int
		for _, password := range user.Passwords {
			if cost, ok := activePasswordCost(password); ok {
				counts[cost]++
			}
		}
		for cost, count := range counts {
			if count > v.checks[cost] {
				v.checks[cost] = count
				hasChecks = true
			}
		}
	}
	if !hasChecks {
		v.checks[bcrypt.DefaultCost] = 1
	}
	return v
}

func activePasswordCost(password *Password) (int, bool) {
	if password == nil || password.Disabled || password.Expired {
		return 0, false
	}
	// Verification follows the hash's encoded cost, not the separate metadata.
	cost, err := bcrypt.Cost([]byte(password.Hash))
	return cost, err == nil
}

func (v *passwordVerifier) verify(user *User, candidate string) error {
	var hashes [bcrypt.MaxCost + 1][]string
	if user != nil && !user.Disabled {
		for _, password := range user.Passwords {
			if cost, ok := activePasswordCost(password); ok {
				hashes[cost] = append(hashes[cost], password.Hash)
			}
		}
	}

	var matched bool
	for cost, count := range v.checks {
		if count == 0 {
			continue
		}
		dummy := fmt.Sprintf("$2a$%02d$%s", cost, dummyPasswordHash[7:])
		for i := 0; i < count; i++ {
			hash := dummy
			real := i < len(hashes[cost])
			if real {
				hash = hashes[cost][i]
			}
			// Compare plaintext directly. Password creation/import parsing can
			// skip bcrypt for whitespace, bcrypt: prefixes, or overlength input.
			err := v.compare([]byte(hash), []byte(candidate))
			if real && err == nil {
				matched = true
			}
			if real && err != nil && err != bcrypt.ErrMismatchedHashAndPassword {
				// Cost parsing alone cannot detect a malformed salt. Replace a
				// comparison that failed before hashing with the scheduled work.
				v.compare([]byte(dummy), []byte(candidate))
			}
		}
	}
	// Do not return early on a match, and never accept a matching dummy hash.
	if matched {
		return nil
	}
	if user != nil && len(user.Passwords) == 0 {
		return errors.ErrUserPasswordNotFound
	}
	return errors.ErrUserPasswordInvalid
}

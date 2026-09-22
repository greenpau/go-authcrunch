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
	"crypto/subtle"
	"fmt"
	"sort"

	"golang.org/x/crypto/bcrypt"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// This synthetic credential is never eligible to authenticate an identity.
// Its salt and checksum remain fixed; only the work factor is substituted.
const dummyPasswordHash = "$2a$10$4xaU6KMqOfcdoZ5DhtIvKuePgy62eGAvZYYwGM/f5/fwB9ZXEAgtG"

// passwordVerifier gives every identity the same password hashing schedule.
// Each work profile gets the largest active-password count in any one account.
type passwordVerifier struct {
	checks       [bcrypt.MaxCost + 1]int
	compare      func([]byte, []byte) error
	argon2Checks map[argon2Parameters]int
	argon2Order  []argon2Parameters
	derive       func([]byte, []byte, argon2Parameters) []byte
}

// The caller must hold the database read lock throughout construction and use.
// Rebuilding from current records avoids stale work factors after password or
// account changes, including changes made through the exported user model.
func newPasswordVerifier(users []*User) *passwordVerifier {
	v := &passwordVerifier{compare: bcrypt.CompareHashAndPassword, argon2Checks: make(map[argon2Parameters]int), derive: deriveArgon2}
	var hasChecks bool
	for _, user := range users {
		if user == nil || user.Disabled {
			continue
		}
		var counts [bcrypt.MaxCost + 1]int
		argon2Counts := make(map[argon2Parameters]int)
		for _, password := range user.Passwords {
			if cost, ok := activePasswordCost(password); ok {
				counts[cost]++
			}
			if hash, ok := activeArgon2Password(password); ok {
				argon2Counts[hash.parameters]++
			}
		}
		for cost, count := range counts {
			if count > v.checks[cost] {
				v.checks[cost] = count
				hasChecks = true
			}
		}
		for parameters, count := range argon2Counts {
			if count > v.argon2Checks[parameters] {
				v.argon2Checks[parameters] = count
				hasChecks = true
			}
		}
	}
	for parameters := range v.argon2Checks {
		v.argon2Order = append(v.argon2Order, parameters)
	}
	// Fix the order independently of map iteration and the requested identity.
	sort.Slice(v.argon2Order, func(i, j int) bool {
		a, b := v.argon2Order[i], v.argon2Order[j]
		left := [...]int{a.memory, a.iterations, a.parallelism, a.saltSize, a.keySize}
		right := [...]int{b.memory, b.iterations, b.parallelism, b.saltSize, b.keySize}
		for n := range left {
			if left[n] != right[n] {
				return left[n] < right[n]
			}
		}
		return false
	})
	if !hasChecks {
		v.checks[bcrypt.DefaultCost] = 1
	}
	return v
}

func activePasswordCost(password *Password) (int, bool) {
	if password == nil || password.Disabled || password.Expired {
		return 0, false
	}
	if password.Algorithm != "" && password.Algorithm != PasswordAlgorithmBcrypt {
		return 0, false
	}
	// Verification follows the hash's encoded cost, not the separate metadata.
	cost, err := bcrypt.Cost([]byte(password.Hash))
	return cost, err == nil
}

func activeArgon2Password(password *Password) (*argon2Hash, bool) {
	if password == nil || password.Disabled || password.Expired || password.Algorithm != PasswordAlgorithmArgon2 {
		return nil, false
	}
	hash, err := parseArgon2(password.Hash)
	return hash, err == nil
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
		for i := range count {
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
	argon2Matched := v.verifyArgon2(user, candidate)
	matched = matched || argon2Matched
	// Do not return early on a match, and never accept a matching dummy hash.
	if matched {
		return nil
	}
	if user != nil && len(user.Passwords) == 0 {
		return errors.ErrUserPasswordNotFound
	}
	return errors.ErrUserPasswordInvalid
}

func (v *passwordVerifier) verifyArgon2(user *User, candidate string) bool {
	hashes := make(map[argon2Parameters][]*argon2Hash)
	if user != nil && !user.Disabled {
		for _, password := range user.Passwords {
			if hash, ok := activeArgon2Password(password); ok {
				hashes[hash.parameters] = append(hashes[hash.parameters], hash)
			}
		}
	}
	var matched bool
	for _, parameters := range v.argon2Order {
		dummy := &argon2Hash{parameters: parameters, salt: make([]byte, parameters.saltSize), key: make([]byte, parameters.keySize)}
		for i := range v.argon2Checks[parameters] {
			hash := dummy
			real := i < len(hashes[parameters])
			if real {
				hash = hashes[parameters][i]
			}
			key := v.derive([]byte(candidate), hash.salt, parameters)
			equal := subtle.ConstantTimeCompare(key, hash.key) == 1
			if real && equal {
				matched = true
			}
		}
	}
	return matched
}

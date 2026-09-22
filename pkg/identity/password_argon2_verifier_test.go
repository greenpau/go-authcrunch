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
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/bcrypt"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func argon2TestPassword(t *testing.T, candidate string, memory int) *Password {
	t.Helper()
	p, err := NewPasswordWithOptions(candidate, "generic", "argon2", map[string]any{"memory": memory, "iterations": 1, "parallelism": 1})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPasswordVerifierArgon2Schedule(t *testing.T) {
	first := argon2TestPassword(t, "first", 256)
	second := argon2TestPassword(t, "second", 512)
	legacy := verifierTestPassword(t, "legacy", 8)
	users := []*User{
		{Passwords: []*Password{first, first, legacy}},
		{Passwords: []*Password{second}},
		{Passwords: []*Password{first}},
		{Disabled: true, Passwords: []*Password{first}},
		{Passwords: []*Password{nil, {Algorithm: "argon2", Hash: first.Hash, Disabled: true}, {Algorithm: "argon2", Hash: second.Hash, Expired: true}}},
		{Passwords: []*Password{{Algorithm: "argon2", Hash: "invalid"}, {Algorithm: "unknown", Hash: legacy.Hash}}},
		{}, nil,
	}
	want := []argon2Parameters{{256, 1, 1, 16, 32}, {256, 1, 1, 16, 32}, {512, 1, 1, 16, 32}}
	for index, user := range users {
		for _, candidate := range []string{"first", "second", "legacy", "wrong", "argon2:invalid", "bcrypt:invalid", "   ", strings.Repeat("x", 73)} {
			v := newPasswordVerifier(users)
			var profiles []argon2Parameters
			v.derive = func(raw, salt []byte, p argon2Parameters) []byte {
				if string(raw) != candidate {
					t.Fatal("plaintext candidate changed")
				}
				profiles = append(profiles, p)
				return deriveArgon2(raw, salt, p)
			}
			var costs []int
			v.compare = func(hash, raw []byte) error {
				cost, _ := bcrypt.Cost(hash)
				costs = append(costs, cost)
				return bcrypt.CompareHashAndPassword(hash, raw)
			}
			err := v.verify(user, candidate)
			allowed := (index == 0 && (candidate == "first" || candidate == "legacy")) || (index == 1 && candidate == "second") || (index == 2 && candidate == "first")
			if (err == nil) != allowed {
				t.Fatal("mixed verifier returned incorrect decision")
			}
			if diff := cmp.Diff(want, profiles, cmp.AllowUnexported(argon2Parameters{})); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff([]int{8}, costs); diff != "" {
				t.Fatal(diff)
			}
		}
	}
	// Force successful dummy comparisons. They must never become credentials.
	v := newPasswordVerifier([]*User{{Passwords: []*Password{first}}})
	v.derive = func(_, _ []byte, p argon2Parameters) []byte { return make([]byte, p.keySize) }
	if v.verify(nil, "any") == nil {
		t.Fatal("dummy Argon2 match authenticated")
	}
	if len(v.argon2Order) != 1 || v.checks[bcrypt.DefaultCost] != 0 {
		t.Fatal("homogeneous Argon2 store added bcrypt work")
	}
}

func TestPasswordVerifierArgon2CurrentRecords(t *testing.T) {
	p := argon2TestPassword(t, "password", 256)
	user := &User{Passwords: []*Password{p}}
	check := func(count int, memory int) {
		t.Helper()
		v := newPasswordVerifier([]*User{user})
		if len(v.argon2Order) != count {
			t.Fatal("stale Argon2 work profile")
		}
		if count > 0 && v.argon2Order[0].memory != memory {
			t.Fatal("wrong memory cost")
		}
		if count == 0 && v.checks[bcrypt.DefaultCost] != 1 {
			t.Fatal("empty-store fallback missing")
		}
	}
	check(1, 256)
	user.Passwords[0] = argon2TestPassword(t, "password", 512)
	check(1, 512)
	user.Passwords[0].Disabled = true
	check(0, 0)
	user.Passwords[0].Disabled = false
	user.Passwords[0].Expired = true
	check(0, 0)
	user.Passwords[0].Expired = false
	user.Disabled = true
	check(0, 0)
	user.Disabled = false
	user.Passwords[0].Hash = "malformed"
	check(0, 0)
}

func TestUserArgon2PasswordLifecycle(t *testing.T) {
	for _, operation := range []string{"add", "reset", "change", "update"} {
		for _, state := range []string{"active", "disabled", "expired"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				current := argon2TestPassword(t, tests.TestPwd1, 256)
				other := passwordMutationFixture(t, tests.TestPwd2)
				current.Disabled = state == "disabled"
				current.Expired = state == "expired"
				user := NewUser("alice")
				user.Passwords = []*Password{current, other}
				if err := applyPasswordMutation(user, operation, current.EncodedHash(), tests.TestPwd2); err != nil {
					t.Fatal(err)
				}
				if user.VerifyPassword(tests.TestPwd1) != nil || user.VerifyPassword(tests.TestPwd2) == nil || !other.Disabled {
					t.Fatal("replacement did not revoke history")
				}
				reused := user.Passwords[0] == current
				if reused != (state == "active" && operation != "reset") {
					t.Fatal("incorrect active import reuse")
				}
				before := passwordMutationSnapshot(t, user)
				if err := applyPasswordMutation(user, operation, "argon2:invalid", tests.TestPwd1); err == nil {
					t.Fatal("invalid import accepted")
				}
				if !bytes.Equal(before, passwordMutationSnapshot(t, user)) {
					t.Fatal("rejected import mutated credentials")
				}
			})
		}
		t.Run(operation+"/plaintext", func(t *testing.T) {
			user := NewUser("alice")
			user.Passwords = []*Password{argon2TestPassword(t, tests.TestPwd1, 256)}
			long := strings.Repeat("A9!", 30)
			if err := applyPasswordMutation(user, operation, long, tests.TestPwd1); err != nil {
				t.Fatal(err)
			}
			current := user.Passwords[0]
			if current.Algorithm != "argon2" || !current.Match(long) || user.VerifyPassword(tests.TestPwd1) == nil {
				t.Fatal("plaintext replacement downgraded Argon2 or retained old credential")
			}
			parsed, err := parseArgon2(current.Hash)
			if err != nil || parsed.parameters.memory != 65536 || parsed.parameters.iterations != 3 {
				t.Fatal("replacement did not use generation defaults")
			}
		})
	}
	// Reapplying a matching plaintext retains the imported hash and timestamps.
	user := NewUser("alice")
	user.Passwords = []*Password{argon2TestPassword(t, tests.TestPwd1, 256)}
	before := passwordMutationSnapshot(t, user)
	if err := user.AddPassword(tests.TestPwd1, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, passwordMutationSnapshot(t, user)) {
		t.Fatal("plaintext duplicate replaced Argon2 record")
	}
	// Explicit bcrypt imports still permit deliberate algorithm migration.
	if err := user.AddPassword(tests.TestPwd2Hash(t), 0); err != nil {
		t.Fatal(err)
	}
	if user.Passwords[0].Algorithm != "bcrypt" || user.VerifyPassword(tests.TestPwd2) != nil {
		t.Fatal("explicit bcrypt migration failed")
	}
}

func TestPasswordVerifierArgon2ProfileDimensions(t *testing.T) {
	profiles := []argon2Parameters{{256, 1, 1, 16, 32}, {256, 2, 1, 16, 32}, {256, 1, 2, 16, 32}, {256, 1, 1, 8, 32}, {256, 1, 1, 16, 16}}
	var users []*User
	for _, p := range profiles {
		salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, p.saltSize))
		key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, p.keySize))
		hash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.memory, p.iterations, p.parallelism, salt, key)
		users = append(users, &User{Passwords: []*Password{{Algorithm: "argon2", Hash: hash, Cost: 31}}})
	}
	for _, target := range append(users, nil) {
		v := newPasswordVerifier(users)
		seen := make(map[argon2Parameters]int)
		v.derive = func(_, salt []byte, p argon2Parameters) []byte {
			if len(salt) != p.saltSize {
				t.Fatal("dummy salt does not match the profile")
			}
			seen[p]++
			return make([]byte, p.keySize)
		}
		if v.verify(target, "candidate") == nil {
			t.Fatal("synthetic password accepted")
		}
		if len(seen) != len(profiles) {
			t.Fatal("work profiles were merged")
		}
		for _, p := range profiles {
			if seen[p] != 1 {
				t.Fatal("unequal work across profile dimensions")
			}
		}
	}
}

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
	"math"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

// Independent vectors from the Argon2 reference implementation's src/test.c:
// https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
const argon2ReferenceHash = "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4"

func TestDeriveArgon2Bounds(t *testing.T) {
	valid := argon2Parameters{256, 2, 1, 8, 32}
	salt := []byte("somesalt")
	key := deriveArgon2([]byte("password"), salt, valid)
	if base64.RawStdEncoding.EncodeToString(key) != "nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4" {
		t.Fatal("reference derivation failed")
	}
	for _, tc := range []struct {
		name   string
		values []int
		set    func(*argon2Parameters, int)
	}{
		{"memory", []int{-1, 0, 7, maxArgon2Memory + 1, math.MaxInt}, func(p *argon2Parameters, n int) { p.memory = n }},
		{"iterations", []int{-1, 0, maxArgon2Iterations + 1, math.MaxInt}, func(p *argon2Parameters, n int) { p.iterations = n }},
		{"parallelism", []int{-1, 0, maxArgon2Parallelism + 1, 256, 257, math.MaxInt}, func(p *argon2Parameters, n int) { p.parallelism = n }},
		{"key size", []int{-1, 0, 15, 65, math.MaxInt}, func(p *argon2Parameters, n int) { p.keySize = n }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, value := range tc.values {
				p := valid
				tc.set(&p, value)
				if key := deriveArgon2([]byte("password"), salt, p); key != nil {
					t.Fatalf("unsupported value %d produced a key", value)
				}
			}
		})
	}
}

func TestPasswordArgon2Reference(t *testing.T) {
	for _, hash := range []string{argon2ReferenceHash, "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc"} {
		p, err := ParseHashedPassword("argon2:" + hash)
		if err != nil {
			t.Fatal(err)
		}
		if p.Algorithm != PasswordAlgorithmArgon2 || p.Cost != 0 || p.Hash != hash || !p.Match("password") {
			t.Fatal("reference hash failed")
		}
		for _, candidate := range []string{"Password", " password", "password ", "argon2:" + hash, hash, ""} {
			if p.Match(candidate) {
				t.Fatal("invalid plaintext accepted")
			}
		}
		p.Algorithm = "unknown"
		if p.Match("password") {
			t.Fatal("unknown algorithm accepted")
		}
		p.Algorithm = PasswordAlgorithmBcrypt
		if p.Match("password") {
			t.Fatal("algorithm mismatch accepted")
		}
	}
}

func TestPasswordArgon2Generation(t *testing.T) {
	c := &PasswordHashConfig{Algorithm: PasswordAlgorithmArgon2}
	p, err := NewPasswordWithConfig("  "+tests.TestPwd1+"  ", "generic", c)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseArgon2(p.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.parameters != (argon2Parameters{65536, 3, 4, 16, 32}) || c.Memory != 0 {
		t.Fatal("defaults or configuration snapshot failed")
	}
	if !p.Match(tests.TestPwd1) || p.Match(" "+tests.TestPwd1) {
		t.Fatal("creation/verification whitespace contract changed")
	}
	c.Memory, c.Iterations, c.Parallelism = 256, 1, 1
	for _, candidate := range []string{tests.TestPwd1, strings.Repeat("long-é", 30)} {
		first, err := NewPasswordWithConfig(candidate, "generic", c)
		if err != nil {
			t.Fatal(err)
		}
		second, err := NewPasswordWithOptions(candidate, "generic", "argon2", map[string]any{"memory": 256, "iterations": 1, "parallelism": 1})
		if err != nil {
			t.Fatal(err)
		}
		if first.Hash == second.Hash || !first.Match(candidate) || first.Match(candidate+"x") {
			t.Fatal("salt uniqueness or exact matching failed")
		}
		imported, err := NewPassword(first.EncodedHash())
		if err != nil || imported.Hash != first.Hash || imported.Algorithm != "argon2" || !imported.Match(candidate) {
			t.Fatal("Argon2 import round trip failed")
		}
	}
	// The submitted plaintext is never interpreted as an import during login.
	parameters := argon2Parameters{256, 1, 1, 16, 32}
	for _, candidate := range []string{"argon2:literal", "bcrypt:literal", "   ", strings.Repeat("x", 73)} {
		salt := bytes.Repeat([]byte{1}, parameters.saltSize)
		key := deriveArgon2([]byte(candidate), salt, parameters)
		raw := "$argon2id$v=19$m=256,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
		password := &Password{Algorithm: "argon2", Hash: raw}
		if !password.Match(candidate) || newPasswordVerifier([]*User{{Passwords: []*Password{password}}}).verify(&User{Passwords: []*Password{password}}, candidate) != nil {
			t.Fatal("literal plaintext failed")
		}
	}
}

func TestPasswordArgon2Invalid(t *testing.T) {
	invalid := []string{"", "$argon2id$", strings.Repeat("x", 257),
		strings.Replace(argon2ReferenceHash, "argon2id", "argon2i", 1),
		strings.Replace(argon2ReferenceHash, "argon2id", "argon2d", 1),
		strings.Replace(argon2ReferenceHash, "v=19", "v=16", 1),
		strings.Replace(argon2ReferenceHash, "v=19$", "", 1),
		argon2ReferenceHash + "$extra", argon2ReferenceHash + "=",
		strings.Replace(argon2ReferenceHash, "c29tZXNhbHQ", "c29tZXNhbHQ=", 1),
		strings.Replace(argon2ReferenceHash, "c29tZXNhbHQ", "c29tZXNhbHR", 1),
		strings.Replace(argon2ReferenceHash, "c29tZXNhbHQ", "c29tZXNhbHQ\n", 1),
		strings.Replace(argon2ReferenceHash, "c29tZXNhbHQ", "c2hvcnQ", 1),
		strings.Replace(argon2ReferenceHash, "c29tZXNhbHQ", base64.RawStdEncoding.EncodeToString(make([]byte, 65)), 1),
		strings.Replace(argon2ReferenceHash, "nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", "c2hvcnQ", 1),
	}
	for _, params := range []string{"m=0,t=2,p=1", "m=7,t=2,p=1", "m=256,t=0,p=1", "m=256,t=2,p=0", "m=256,t=11,p=1", "m=262145,t=1,p=1", "m=262144,t=5,p=1", "m=256,t=1,p=17", "m=256,t=1,p=256", "m=256,t=1,p=-1", "m=+256,t=2,p=1", "m=0256,t=2,p=1", "m=9999999999999999999999,t=2,p=1", "m=256,m=2,p=1", "t=2,m=256,p=1", "m=256,t=2,p=1,extra=1"} {
		invalid = append(invalid, strings.Replace(argon2ReferenceHash, "m=256,t=2,p=1", params, 1))
	}
	for i, raw := range invalid {
		if p, err := ParseHashedPassword("argon2:" + raw); err == nil || p != nil {
			t.Fatalf("invalid case %d imported", i)
		}
		if p, err := NewPassword("argon2:" + raw); err == nil || p != nil {
			t.Fatalf("invalid case %d created", i)
		}
		if (&Password{Algorithm: "argon2", Hash: raw}).Match("password") {
			t.Fatalf("invalid case %d matched", i)
		}
	}
	for _, params := range []map[string]any{{"memory": "256"}, {"parallelism": uint8(1)}, {"iterations": -1}, {"memory": 0}, {"cost": 8}, {"unknown": 1}} {
		if p, err := NewPasswordWithOptions("password", "generic", "argon2", params); err == nil || p != nil {
			t.Fatal("invalid generation parameters accepted")
		}
	}
	if p, err := NewPasswordWithOptions("password", "generic", "bcrypt", map[string]any{"cost": "10"}); err == nil || p != nil {
		t.Fatal("non-integer bcrypt cost accepted")
	}
}

func TestPasswordBcryptImportValidation(t *testing.T) {
	good := tests.TestPwd1Hash(t)
	p, err := ParseHashedPassword(good)
	if err != nil || !p.Match(tests.TestPwd1) || p.EncodedHash() != good {
		t.Fatal("legacy import failed")
	}
	for _, prefix := range []string{"$2$", "$2a$", "$2b$", "$2x$", "$2y$"} {
		hash := prefix + p.Hash[4:]
		imported, err := NewPassword("bcrypt:10:" + hash)
		if err != nil || !imported.Match(tests.TestPwd1) {
			t.Fatalf("supported bcrypt prefix %q failed", prefix)
		}
	}
	low, err := NewPasswordWithOptions(tests.TestPwd1, "generic", "bcrypt", map[string]any{"cost": 8})
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalSalt := p.Hash[:28] + "/" + p.Hash[29:]
	noncanonicalChecksum := p.Hash[:59] + "H"
	for _, invalid := range []string{
		"bcrypt:10:invalid",
		"bcrypt:31:" + p.Hash,
		"bcrypt:10:" + p.Hash[:20] + "!" + p.Hash[21:],
		"argon2:" + p.Hash,
		"bcrypt:10:" + argon2ReferenceHash,
		"bcrypt:010:" + p.Hash,
		"bcrypt:+10:" + p.Hash,
		"bcrypt:10:$1a$" + p.Hash[4:],
		"bcrypt:10:$2z$" + p.Hash[4:],
		"bcrypt:10:$2a!" + p.Hash[4:],
		"bcrypt:10:" + p.Hash[:6] + "!" + p.Hash[7:],
		"bcrypt:8:" + low.Hash[:4] + "+8" + low.Hash[6:],
		"bcrypt:10:" + noncanonicalSalt,
		"bcrypt:10:" + noncanonicalChecksum,
	} {
		if p, err := NewPassword(invalid); err == nil || p != nil {
			t.Fatal("malformed or inconsistent import accepted")
		}
	}
}

func FuzzParseArgon2(f *testing.F) {
	for _, seed := range []string{argon2ReferenceHash, "", "$argon2id$v=19$m=0,t=0,p=0$$"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h, err := parseArgon2(s)
		if err != nil {
			if h != nil {
				t.Fatal("partial result")
			}
			return
		}
		if h == nil || validateArgon2Parameters(h.parameters.memory, h.parameters.iterations, h.parameters.parallelism) != nil {
			t.Fatal("unbounded hash accepted")
		}
	})
}

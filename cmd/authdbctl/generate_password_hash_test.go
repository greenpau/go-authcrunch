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

package main

import (
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestGenerateArgon2Hash(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags map[string]string
		ok    bool
	}{
		{"defaults", map[string]string{"password": tests.TestPwd1, "algorithm": "argon2"}, true},
		{"custom", map[string]string{"password": tests.TestPwd1, "algorithm": "argon2", "memory": "1024", "iterations": "1", "parallelism": "1"}, true},
		{"wrong algorithm", map[string]string{"password": tests.TestPwd1, "algorithm": "unknown"}, false},
		{"bcrypt option", map[string]string{"password": tests.TestPwd1, "algorithm": "argon2", "cost": "10"}, false},
		{"argon2 option", map[string]string{"password": tests.TestPwd1, "memory": "1024"}, false},
		{"zero lanes", map[string]string{"password": tests.TestPwd1, "algorithm": "argon2", "parallelism": "0"}, false},
		{"excessive memory", map[string]string{"password": tests.TestPwd1, "algorithm": "argon2", "memory": "262145"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := captureCommand(t, generatePasswordHash, commandContext(t, tc.flags))
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected generation result: %v", err)
			}
			if strings.Contains(output, tests.TestPwd1) {
				t.Fatal("generation leaked plaintext")
			}
			if !tc.ok {
				return
			}
			match := regexp.MustCompile(`password "(argon2:[^"\n]+)"`).FindStringSubmatch(output)
			if len(match) != 2 {
				t.Fatal("missing Argon2 configuration output")
			}
			p, err := identity.ParseHashedPassword(match[1])
			if err != nil || !p.Match(tests.TestPwd1) {
				t.Fatal("unusable generated import")
			}
			if tc.name == "custom" {
				parts := strings.Split(p.Hash, "$")
				if parts[3] != "m=1024,t=1,p=1" {
					t.Fatal("custom Argon2 parameters ignored")
				}
				salt, err := base64.RawStdEncoding.DecodeString(parts[4])
				if err != nil {
					t.Fatal(err)
				}
				expected := argon2.IDKey([]byte(tests.TestPwd1), salt, 1, 1024, 1, 32)
				if base64.RawStdEncoding.EncodeToString(expected) != parts[5] {
					t.Fatal("independent generated hash verification failed")
				}
			}
		})
	}
}

func TestGenerateArgon2HashDatabasePasswordPolicy(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "policy.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Policy.User.MinLength = 20
	db.Policy.Password.MinLength = 8
	db.Policy.Password.MaxLength = 12
	if err := db.Save(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		password  string
		shouldErr bool
	}{
		{name: "minimum length", password: strings.Repeat("a", 8)},
		{name: "maximum length", password: strings.Repeat("a", 12)},
		{name: "padded minimum length", password: "  " + strings.Repeat("a", 8) + "  "},
		{name: "below minimum", password: strings.Repeat("a", 7), shouldErr: true},
		{name: "padded below minimum", password: "  " + strings.Repeat("a", 7) + "  ", shouldErr: true},
		{name: "above maximum", password: strings.Repeat("a", 13), shouldErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := captureCommand(t, generatePasswordHash, commandContext(t, map[string]string{
				"algorithm": "argon2", "memory": "1024", "iterations": "1", "parallelism": "1",
				"password": tc.password, "db-path": dbPath,
			}))
			if (err != nil) != tc.shouldErr {
				t.Fatalf("unexpected generation result: %v", err)
			}
			if strings.Contains(output, strings.TrimSpace(tc.password)) {
				t.Fatal("generation disclosed plaintext")
			}
			if !tc.shouldErr && !strings.Contains(output, `password "argon2:`) {
				t.Fatal("valid policy-boundary password did not produce a hash")
			}
		})
	}
}

func testCLIArgon2PasswordHash(t *testing.T, binary string) {
	t.Helper()
	home := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "policy.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Policy.User.MinLength = len(tests.TestUser1) + 10
	db.Policy.Password.MinLength = len(tests.TestPwd1)
	db.Policy.Password.MaxLength = len(tests.TestPwd1)
	if err := db.Save(); err != nil {
		t.Fatal(err)
	}
	output, diagnostic, err := runCLIProcess(t, binary, home, "", nil, "generate", "password", "hash", "--algorithm", "argon2", "--password", tests.TestPwd1, "--memory", "1024", "--iterations", "1", "--parallelism", "1", "--db-path", dbPath)
	if err != nil {
		t.Fatal("Argon2 hash command failed")
	}
	if strings.Contains(output+diagnostic, tests.TestPwd1) {
		t.Fatal("hash command leaked plaintext")
	}
	match := regexp.MustCompile(`password "(argon2:[^"\n]+)"`).FindStringSubmatch(output)
	if len(match) != 2 {
		t.Fatal("hash command did not emit an Argon2 import")
	}
	p, err := identity.ParseHashedPassword(match[1])
	if err != nil || !p.Match(tests.TestPwd1) || !strings.Contains(p.Hash, "m=1024,t=1,p=1") {
		t.Fatal("hash command ignored parameters or generated an unusable import")
	}
	padded := "  " + tests.TestPwd1 + "  "
	output, diagnostic, err = runCLIProcess(t, binary, home, "", nil, "generate", "password", "hash", "--algorithm", "argon2", "--password", padded, "--memory", "1024", "--iterations", "1", "--parallelism", "1", "--db-path", dbPath)
	if err != nil || strings.Contains(output+diagnostic, tests.TestPwd1) {
		t.Fatal("executable rejected or disclosed padded compliant plaintext")
	}
	match = regexp.MustCompile(`password "(argon2:[^"\n]+)"`).FindStringSubmatch(output)
	if len(match) != 2 {
		t.Fatal("padded compliant plaintext did not produce an Argon2 import")
	}
	p, err = identity.ParseHashedPassword(match[1])
	if err != nil || !p.Match(tests.TestPwd1) || p.Match(padded) {
		t.Fatal("executable did not hash the normalized compliant plaintext")
	}
	for _, candidate := range []string{tests.TestPwd1[:len(tests.TestPwd1)-1], "  " + tests.TestPwd1[:len(tests.TestPwd1)-1] + "  ", tests.TestPwd1 + "x"} {
		out, diagnostic, err := runCLIProcess(t, binary, home, "", nil, "generate", "password", "hash", "--algorithm", "argon2", "--password", candidate, "--memory", "1024", "--iterations", "1", "--parallelism", "1", "--db-path", dbPath)
		if err == nil || strings.Contains(out+diagnostic, strings.TrimSpace(candidate)) || strings.Contains(out, `password "`) {
			t.Fatal("executable ignored password policy boundary or disclosed plaintext")
		}
	}
	f := newCLIE2EPortal(t, "password", false)
	db, err = identity.NewDatabase(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateUserPassword(&requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1, Password: match[1]}}); err != nil {
		t.Fatal("could not install CLI generated hash")
	}
	writeE2EConfig(t, home, f.config())
	if _, _, err := runCLIProcess(t, binary, home, "", nil, "connect"); err != nil {
		t.Fatal("executable login with generated Argon2 credential failed")
	}
	f.assertCredential(t, filepath.Join(home, ".config", "authdbctl", "token.jwt"))
	for _, args := range [][]string{{"--algorithm", "unknown"}, {"--algorithm", "argon2", "--cost", "10"}, {"--algorithm", "argon2", "--memory", "0"}, {"--algorithm", "argon2", "--parallelism", "256"}, {"--algorithm", "argon2", "--iterations", "11"}} {
		base := []string{"generate", "password", "hash", "--password", tests.TestPwd1}
		out, diagnostic, err := runCLIProcess(t, binary, home, "", nil, append(base, args...)...)
		if err == nil || strings.Contains(out+diagnostic, tests.TestPwd1) || strings.Contains(out, `password "`) {
			t.Fatal("invalid hash configuration did not fail cleanly")
		}
	}
}

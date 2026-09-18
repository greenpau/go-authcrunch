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

package tests

import (
	"fmt"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Cache only immutable imports for the two synthetic fixture passwords. Each
// database still creates independent user/password records, and every login
// performs real bcrypt verification at the normal cost.
var (
	testPwd1Hash = sync.OnceValues(func() (string, error) { return passwordImport(TestPwd1) })
	testPwd2Hash = sync.OnceValues(func() (string, error) { return passwordImport(TestPwd2) })
)

// TestPwd1Hash returns a reusable bcrypt import for provisioning TestPwd1.
// Login requests must continue to submit the plaintext TestPwd1.
func TestPwd1Hash(t testing.TB) string {
	t.Helper()
	return fixturePasswordImport(t, testPwd1Hash)
}

// TestPwd2Hash returns a reusable bcrypt import for provisioning TestPwd2.
// Login requests must continue to submit the plaintext TestPwd2.
func TestPwd2Hash(t testing.TB) string {
	t.Helper()
	return fixturePasswordImport(t, testPwd2Hash)
}

func fixturePasswordImport(t testing.TB, load func() (string, error)) string {
	t.Helper()
	value, err := load()
	if err != nil {
		t.Fatal("could not hash fixture password")
	}
	return value
}

func passwordImport(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("bcrypt:%d:%s", bcrypt.DefaultCost, hash), nil
}

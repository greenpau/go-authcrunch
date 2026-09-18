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
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestFixturePasswordImports(t *testing.T) {
	for _, tc := range []struct {
		name          string
		load          func(testing.TB) string
		password      string
		otherPassword string
	}{
		{"first", TestPwd1Hash, TestPwd1, TestPwd2},
		{"second", TestPwd2Hash, TestPwd2, TestPwd1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Concurrent first use must generate and publish one immutable import.
			var values [16]string
			var workers sync.WaitGroup
			for i := range values {
				workers.Go(func() { values[i] = tc.load(t) })
			}
			workers.Wait()
			for _, value := range values {
				if value != values[0] || value == "" {
					t.Fatal("fixture hash was not reused across concurrent callers")
				}
			}
			parts := strings.SplitN(values[0], ":", 3)
			if len(parts) != 3 || parts[0] != "bcrypt" || parts[1] != strconv.Itoa(bcrypt.DefaultCost) {
				t.Fatal("invalid password import format")
			}
			hash := []byte(parts[2])
			if cost, err := bcrypt.Cost(hash); err != nil || cost != bcrypt.DefaultCost {
				t.Fatal("fixture hash does not retain the default bcrypt cost")
			}
			if err := bcrypt.CompareHashAndPassword(hash, []byte(tc.password)); err != nil {
				t.Fatal("fixture hash rejects its plaintext password")
			}
			if err := bcrypt.CompareHashAndPassword(hash, []byte(tc.otherPassword)); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				t.Fatal("fixture hash accepts the other identity's password")
			}
		})
	}
}

func TestPasswordImportRejectsInvalidInput(t *testing.T) {
	if value, err := passwordImport(strings.Repeat("x", 73)); value != "" || !errors.Is(err, bcrypt.ErrPasswordTooLong) {
		t.Fatal("failed password generation returned an import or lost its error")
	}
}

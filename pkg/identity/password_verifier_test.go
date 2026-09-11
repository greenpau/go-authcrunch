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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/bcrypt"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func verifierTestPassword(t *testing.T, candidate string, cost int) *Password {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(candidate), cost)
	if err != nil {
		t.Fatal(err)
	}
	return &Password{Hash: string(hash), Cost: cost}
}

func TestPasswordVerifierWorkSchedule(t *testing.T) {
	// Instrument the bcrypt boundary to check work factors and comparison counts
	// deterministically, including cost 14, without flaky timing assertions.
	hash := func(cost int, suffix string) string {
		return fmt.Sprintf("$2a$%02d$%s%s", cost, dummyPasswordHash[7:59], suffix)
	}
	first := &Password{Hash: hash(10, "A"), Cost: 31}
	second := &Password{Hash: hash(10, "B")}
	ten := &User{Passwords: []*Password{first, second}}
	fourteen := &User{Passwords: []*Password{{Hash: hash(14, "A")}}}
	disabled := &User{Disabled: true, Passwords: []*Password{{Hash: hash(20, "A")}}}
	inactive := &User{Passwords: []*Password{
		nil, {Hash: hash(21, "A"), Disabled: true}, {Hash: hash(22, "A"), Expired: true},
	}}
	malformed := &User{Passwords: []*Password{{Hash: "not a bcrypt hash"}}}
	// Another account at cost 10 must not add work beyond the largest count
	// belonging to a single account.
	single := &User{Passwords: []*Password{first}}
	users := []*User{ten, single, fourteen, disabled, inactive, malformed, nil}

	for _, tc := range []struct {
		name      string
		user      *User
		candidate string
		match     string
		wantErr   error
	}{
		{name: "missing ordinary", candidate: "wrong-password", wantErr: errors.ErrUserPasswordInvalid},
		{name: "missing import representation", candidate: "bcrypt:10:not-a-hash", wantErr: errors.ErrUserPasswordInvalid},
		{name: "missing malformed import", candidate: "bcrypt:", wantErr: errors.ErrUserPasswordInvalid},
		{name: "missing whitespace", candidate: "   ", wantErr: errors.ErrUserPasswordInvalid},
		{name: "missing overlength", candidate: strings.Repeat("x", 73), wantErr: errors.ErrUserPasswordInvalid},
		{name: "cost 10 wrong password", user: ten, candidate: "wrong-password", wantErr: errors.ErrUserPasswordInvalid},
		{name: "cost 14 wrong password", user: fourteen, candidate: "wrong-password", wantErr: errors.ErrUserPasswordInvalid},
		{name: "first password matches", user: ten, candidate: "correct-password", match: first.Hash},
		{name: "second password matches", user: ten, candidate: "correct-password", match: second.Hash},
		{name: "cost 14 matches", user: fourteen, candidate: "correct-password", match: fourteen.Passwords[0].Hash},
		{name: "disabled user", user: disabled, candidate: "wrong-password", wantErr: errors.ErrUserPasswordInvalid},
		{name: "no passwords", user: &User{}, candidate: "wrong-password", wantErr: errors.ErrUserPasswordNotFound},
		{name: "no active passwords", user: inactive, candidate: "wrong-password", wantErr: errors.ErrUserPasswordInvalid},
		{name: "malformed stored hash", user: malformed, candidate: "wrong-password", wantErr: errors.ErrUserPasswordInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newPasswordVerifier(users)
			var costs []int
			v.compare = func(hash, candidate []byte) error {
				cost, err := bcrypt.Cost(hash)
				if err != nil {
					t.Fatal("comparison received an invalid bcrypt representation")
				}
				costs = append(costs, cost)
				if string(candidate) != tc.candidate {
					t.Fatal("candidate was parsed or changed before comparison")
				}
				if string(hash) == tc.match {
					return nil
				}
				return bcrypt.ErrMismatchedHashAndPassword
			}
			if got := v.verify(tc.user, tc.candidate); got != tc.wantErr {
				t.Fatalf("verification result: got %v, want %v", got, tc.wantErr)
			}
			if diff := cmp.Diff([]int{10, 10, 14}, costs); diff != "" {
				t.Fatalf("identity changed bcrypt work (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPasswordVerifierRejectsDummyMatch(t *testing.T) {
	for _, user := range []*User{nil, {}, {Disabled: true}, {Passwords: []*Password{{Hash: "invalid"}}}} {
		v := newPasswordVerifier([]*User{user})
		var costs []int
		v.compare = func(hash, _ []byte) error {
			cost, err := bcrypt.Cost(hash)
			if err != nil {
				t.Fatal(err)
			}
			costs = append(costs, cost)
			return nil // Even a successful dummy comparison cannot authenticate.
		}
		if err := v.verify(user, "candidate"); err == nil {
			t.Fatal("dummy comparison authenticated an identity")
		}
		if diff := cmp.Diff([]int{bcrypt.DefaultCost}, costs); diff != "" {
			t.Fatalf("empty-store fallback work (-want +got):\n%s", diff)
		}
	}
	// Exercise the actual known dummy credential as well as the instrumented
	// boundary: knowing its plaintext must never create an authenticated user.
	candidate := "AuthCrunch dummy credential; never an account"
	if err := bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(candidate)); err != nil {
		t.Fatal("dummy fixture no longer matches its synthetic plaintext")
	}
	if err := newPasswordVerifier(nil).verify(nil, candidate); err == nil {
		t.Fatal("known dummy plaintext authenticated a missing identity")
	}
}

func TestPasswordVerifierRealBcrypt(t *testing.T) {
	// Low costs keep the functional tests fast. Work-factor selection, including
	// production cost 14, is independently asserted above.
	first := verifierTestPassword(t, "first-password", bcrypt.MinCost)
	second := verifierTestPassword(t, "bcrypt:literal-password", bcrypt.MinCost+1)
	user := &User{Passwords: []*Password{first, second}}
	for _, tc := range []struct {
		name      string
		candidate string
		wantMatch bool
	}{
		{name: "first matches", candidate: "first-password", wantMatch: true},
		{name: "literal import prefix matches", candidate: "bcrypt:literal-password", wantMatch: true},
		{name: "ordinary wrong", candidate: "wrong-password"},
		{name: "import prefix wrong", candidate: "bcrypt:10:not-a-hash"},
		{name: "malformed import wrong", candidate: "bcrypt:"},
		{name: "whitespace wrong", candidate: "   "},
		{name: "overlength wrong", candidate: strings.Repeat("x", 73)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, target := range []*User{user, nil} {
				v := newPasswordVerifier([]*User{user})
				var completed []int
				v.compare = func(hash, candidate []byte) error {
					err := bcrypt.CompareHashAndPassword(hash, candidate)
					if err == nil || err == bcrypt.ErrMismatchedHashAndPassword {
						cost, _ := bcrypt.Cost(hash)
						completed = append(completed, cost)
					}
					return err
				}
				err := v.verify(target, tc.candidate)
				if got, want := err == nil, tc.wantMatch && target != nil; got != want {
					t.Fatalf("authenticated: got %v, want %v", got, want)
				}
				if diff := cmp.Diff([]int{bcrypt.MinCost, bcrypt.MinCost + 1}, completed); diff != "" {
					t.Fatalf("completed bcrypt work (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestPasswordVerifierMalformedSalt(t *testing.T) {
	password := verifierTestPassword(t, "correct-password", bcrypt.MinCost)
	password.Hash = password.Hash[:7] + "!" + password.Hash[8:]
	user := &User{Passwords: []*Password{password}}
	v := newPasswordVerifier([]*User{user})
	var attempted, completed int
	v.compare = func(hash, candidate []byte) error {
		attempted++
		err := bcrypt.CompareHashAndPassword(hash, candidate)
		if err == nil || err == bcrypt.ErrMismatchedHashAndPassword {
			completed++
		}
		return err
	}
	if err := v.verify(user, "correct-password"); err == nil {
		t.Fatal("malformed stored hash authenticated")
	}
	if attempted != 2 || completed != 1 {
		t.Fatalf("malformed salt skipped scheduled work: attempted %d, completed %d", attempted, completed)
	}
}

func TestPasswordVerifierCurrentRecords(t *testing.T) {
	user := &User{Passwords: []*Password{{Hash: dummyPasswordHash}}}
	check := func(want map[int]int) {
		t.Helper()
		v := newPasswordVerifier([]*User{user})
		got := make(map[int]int)
		for cost, count := range v.checks {
			if count != 0 {
				got[cost] = count
			}
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("current work schedule (-want +got):\n%s", diff)
		}
	}
	check(map[int]int{10: 1})
	user.Passwords[0].Hash = "$2a$14$" + dummyPasswordHash[7:]
	check(map[int]int{14: 1})
	user.Passwords = append(user.Passwords, &Password{Hash: user.Passwords[0].Hash})
	check(map[int]int{14: 2})
	user.Passwords[0].Expired = true
	check(map[int]int{14: 1})
	user.Disabled = true
	check(map[int]int{bcrypt.DefaultCost: 1})
}

func TestDatabasePasswordVerification(t *testing.T) {
	db, err := NewDatabase(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	password := verifierTestPassword(t, "correct-password", 8)
	if err := db.AddUser(&requests.Request{User: requests.User{
		Username: "timinguser", Email: "timinguser@example.test",
		Password: "bcrypt:8:" + password.Hash,
	}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		username  string
		candidate string
		wantMatch bool
	}{
		{name: "username", username: "timinguser", candidate: "correct-password", wantMatch: true},
		{name: "email", username: "timinguser@example.test", candidate: "correct-password", wantMatch: true},
		{name: "uppercase", username: "TIMINGUSER", candidate: "correct-password", wantMatch: true},
		{name: "unknown", username: "missinguser", candidate: "correct-password"},
		{name: "wrong password", username: "timinguser", candidate: "wrong-password"},
		{name: "unknown import", username: "missinguser", candidate: "bcrypt:10:not-a-hash"},
		{name: "known import", username: "timinguser", candidate: "bcrypt:10:not-a-hash"},
		{name: "unknown whitespace", username: "missinguser", candidate: "   "},
		{name: "known whitespace", username: "timinguser", candidate: "   "},
		{name: "unknown overlength", username: "missinguser", candidate: strings.Repeat("x", 73)},
		{name: "known overlength", username: "timinguser", candidate: strings.Repeat("x", 73)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &requests.Request{User: requests.User{Username: tc.username, Password: tc.candidate}}
			// Failed attempts must not retain evidence from an earlier request.
			r.Authentication.Method = "pwd"
			err := db.AuthenticateUser(r)
			if got := err == nil; got != tc.wantMatch {
				t.Fatalf("authenticated: got %v, want %v", got, tc.wantMatch)
			}
			if tc.wantMatch {
				if r.Response.Code != 200 || r.Authentication.Method != "pwd" || r.Authentication.AuthenticatedAt == 0 {
					t.Fatal("successful password authentication lost its evidence")
				}
			} else {
				if r.Response.Code != 400 || r.Authentication != (requests.AuthenticationEvidence{}) {
					t.Fatal("failed password authentication retained success or evidence")
				}
			}
		})
	}
}

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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestDatabaseMFAEnrollment(t *testing.T) {
	for _, existing := range []string{"none", "disabled", "enabled"} {
		t.Run(existing, func(t *testing.T) {
			db, authenticated := refreshTestDatabase(t)
			request := func(label string) *requests.Request {
				return &requests.Request{User: authenticated.User, MfaToken: requests.MfaToken{
					Type: "totp", Secret: "synthetic-enrollment-" + label, Comment: label,
					Period: 30, Digits: 6, Algorithm: "sha1", SkipVerification: true,
				}}
			}
			if existing != "none" {
				r := request("original")
				r.MfaToken.Disabled = existing == "disabled"
				if err := db.AddMfaToken(r); err != nil {
					t.Fatal(err)
				}
			}
			// The no-factor decision and mutation must be one transaction: two
			// pending login sandboxes cannot both enroll their first factor.
			var accepted atomic.Int32
			var wg sync.WaitGroup
			for i := range 8 {
				wg.Go(func() {
					if err := db.EnrollMfaToken(request(fmt.Sprint(i))); err == nil {
						accepted.Add(1)
					}
				})
			}
			wg.Wait()
			want := int32(1)
			if existing == "enabled" {
				want = 0
			}
			if got := accepted.Load(); got != want {
				t.Fatalf("accepted enrollments %d, want %d", got, want)
			}
			loaded, err := NewDatabase(db.GetPath())
			if err != nil {
				t.Fatal(err)
			}
			r := request("lookup")
			if err := loaded.GetMfaTokens(r); err != nil {
				t.Fatal(err)
			}
			if r.Response.Payload.(*MfaTokenBundle).Size() != 1 {
				t.Fatal("enrollment did not preserve exactly one enabled factor")
			}
		})
	}
}

func TestDatabaseMFAEnrollmentAcrossInstances(t *testing.T) {
	db, authenticated := refreshTestDatabase(t)
	stale, err := NewDatabase(db.GetPath())
	if err != nil {
		t.Fatal(err)
	}
	request := func(label string) *requests.Request {
		return &requests.Request{User: authenticated.User, MfaToken: requests.MfaToken{
			Type: "totp", Secret: "synthetic-enrollment-" + label, Comment: label,
			Period: 30, Digits: 6, Algorithm: "sha1", SkipVerification: true,
		}}
	}
	if err := db.EnrollMfaToken(request("first")); err != nil {
		t.Fatal(err)
	}
	if err := stale.EnrollMfaToken(request("replacement")); err == nil {
		t.Fatal("stale database instance replaced the first enrolled factor")
	}
	loaded, err := NewDatabase(db.GetPath())
	if err != nil {
		t.Fatal(err)
	}
	r := request("lookup")
	if err := loaded.GetMfaTokens(r); err != nil {
		t.Fatal(err)
	}
	tokens := r.Response.Payload.(*MfaTokenBundle).Get()
	if len(tokens) != 1 || tokens[0].Comment != "first" {
		t.Fatal("first enrolled factor was not preserved")
	}
}

func TestDatabaseMFAEnrollmentCommitFailureRollsBack(t *testing.T) {
	db, authenticated := refreshTestDatabase(t)
	user, err := db.validateUserIdentity(authenticated.User.Username, authenticated.User.Email)
	if err != nil {
		t.Fatal(err)
	}
	previousTokenCount := len(user.MfaTokens)
	previousCredentialVersion := user.CredentialVersion
	previousUserRevision := user.Revision
	previousUserLastModified := user.LastModified
	previousDatabaseRevision := db.Revision
	previousDatabaseLastModified := db.LastModified

	r := &requests.Request{User: authenticated.User, MfaToken: requests.MfaToken{
		Type: "totp", Secret: "synthetic-failed-enrollment", Comment: "failed enrollment",
		Period: 30, Digits: 6, Algorithm: "sha1", SkipVerification: true,
	}}
	commitErr := errors.New("synthetic commit failure")
	if err := db.addMfaTokenUnlocked(r, true, func() error {
		db.Revision++
		db.LastModified = time.Now().UTC().Add(time.Hour)
		return commitErr
	}); err == nil {
		t.Fatal("enrollment succeeded despite commit failure")
	}
	if len(user.MfaTokens) != previousTokenCount || user.CredentialVersion != previousCredentialVersion || user.Revision != previousUserRevision || !user.LastModified.Equal(previousUserLastModified) {
		t.Fatal("commit failure left an unpersisted MFA credential in the live identity")
	}
	if db.Revision != previousDatabaseRevision || !db.LastModified.Equal(previousDatabaseLastModified) {
		t.Fatal("commit failure changed live database metadata")
	}
	if err := db.EnrollMfaToken(r); err != nil {
		t.Fatalf("retry after commit failure: %v", err)
	}
}

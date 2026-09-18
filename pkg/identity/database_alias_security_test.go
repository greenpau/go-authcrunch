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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestDatabaseAliasDoesNotAuthenticateRevokedCredential(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		stale, authenticated := newMFABindingTestDatabase(t, false)
		current := mustLoadMFABindingDatabase(t, stale.GetPath())
		if err := current.ChangeUserPassword(&requests.Request{User: requests.User{
			Username: authenticated.User.Username, Email: authenticated.User.Email,
			OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
		}}); err != nil {
			t.Fatal(err)
		}
		oldPassword := &requests.Request{User: requests.User{
			Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd1,
		}}
		if err := stale.AuthenticateUser(oldPassword); err == nil {
			t.Fatal("stale database alias authenticated a revoked password")
		}
		newPassword := &requests.Request{User: requests.User{
			Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd2,
		}}
		if err := stale.AuthenticateUser(newPassword); err != nil {
			t.Fatalf("stale database alias did not refresh the current password: %v", err)
		}
	})

	t.Run("refresh evidence", func(t *testing.T) {
		stale, authenticated := newMFABindingTestDatabase(t, false)
		current := mustLoadMFABindingDatabase(t, stale.GetPath())
		if err := current.RevokeUserSessions(t.Context(), authenticated.Authentication.UserID); err != nil {
			t.Fatal(err)
		}
		called := false
		err := stale.WithRefreshIdentity(context.Background(), authenticated.Authentication, func(RefreshIdentity) error {
			called = true
			return nil
		})
		if !errors.Is(err, ErrRefreshIdentityDenied) || called {
			t.Fatal("stale database alias accepted revoked refresh evidence", err)
		}
	})
}

func TestDatabaseAliasCommitDoesNotReviveCredential(t *testing.T) {
	stale, authenticated := newMFABindingTestDatabase(t, false)
	current := mustLoadMFABindingDatabase(t, stale.GetPath())
	if err := current.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email,
		OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal(err)
	}
	err := stale.OverwriteUserRoles(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email,
		Roles: []string{"authp/user", "authp/admin"},
	}})
	if err == nil {
		t.Fatal("stale database alias committed over a newer credential")
	}

	loaded := mustLoadMFABindingDatabase(t, stale.GetPath())
	if err := loaded.AuthenticateUser(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd1,
	}}); err == nil {
		t.Fatal("stale commit revived the old password")
	}
	if err := loaded.AuthenticateUser(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatalf("current password was lost: %v", err)
	}
}

func TestDatabaseAliasTrustedMFAConflictKeepsAdoptedRevision(t *testing.T) {
	stale, authenticated := newMFABindingTestDatabase(t, false)
	current := mustLoadMFABindingDatabase(t, stale.GetPath())
	if err := current.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email,
		OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal(err)
	}
	r := mfaBindingTestRequest(authenticated, "trusted-conflict")
	r.Authentication = requests.AuthenticationEvidence{}
	if err := stale.AddMfaToken(r); err == nil {
		t.Fatal("stale trusted MFA mutation unexpectedly succeeded")
	}
	if stale.Revision != current.Revision {
		t.Fatalf("conflict rollback reverted adopted revision: got %d, want %d", stale.Revision, current.Revision)
	}
	if len(stale.Users[0].MfaTokens) != 0 {
		t.Fatal("conflicting MFA mutation entered the live snapshot")
	}
}

func TestDatabaseAliasLockoutRejectsTOTPConsumption(t *testing.T) {
	stale, path, request := newTOTPReplayDatabase(t)
	current := mustLoadMFABindingDatabase(t, path)
	for range 10 {
		if err := current.IncrementMfaFailedAttempts(request); err != nil {
			t.Fatal(err)
		}
	}
	ts := time.Unix(1800000000, 0).UTC()
	request.MfaToken.Passcode = totpReplayCode(t, uint64(ts.Unix()/30))
	if err := stale.consumeMfaTOTPWithTime(request, ts); err == nil {
		t.Fatal("stale database alias bypassed the persisted MFA lockout")
	}
}

func TestDatabaseAliasesAtomicallyCountMFAFailures(t *testing.T) {
	first, path, request := newTOTPReplayDatabase(t)
	second := mustLoadMFABindingDatabase(t, path)
	for i := range 10 {
		current := first
		if i%2 == 1 {
			current = second
		}
		if err := current.IncrementMfaFailedAttempts(request); err != nil {
			t.Fatalf("increment %d failed: %v", i+1, err)
		}
	}
	loaded := mustLoadMFABindingDatabase(t, path)
	if err := loaded.CheckMfaLockout(request); err == nil {
		t.Fatal("ten failures split across aliases did not lock the identity")
	}
}

func TestDatabaseAliasTOTPDoesNotMaskCredentialRevocation(t *testing.T) {
	stale, path, request := newTOTPReplayDatabase(t)
	current := mustLoadMFABindingDatabase(t, path)
	if err := current.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: request.User.Username, Email: request.User.Email,
		OldPassword: "correct horse battery staple", Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1800000000, 0).UTC()
	request.MfaToken.Passcode = totpReplayCode(t, uint64(ts.Unix()/30))
	if err := stale.consumeMfaTOTPWithTime(request, ts); err == nil {
		t.Fatal("TOTP continuation accepted after the identity credential changed")
	}
	if stale.Revision != current.Revision {
		t.Fatal("TOTP rejection did not adopt the current persisted revision")
	}
	if err := stale.AuthenticateUser(&requests.Request{User: requests.User{
		Username: request.User.Username, Email: request.User.Email, Password: "correct horse battery staple",
	}}); err == nil {
		t.Fatal("TOTP synchronization retained the revoked password")
	}
	if err := stale.AuthenticateUser(&requests.Request{User: requests.User{
		Username: request.User.Username, Email: request.User.Email, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal("TOTP synchronization lost the current password", err)
	}
}

func TestDatabaseTOTPContinuationRejectsChangedIdentity(t *testing.T) {
	db, _, request := newTOTPReplayDatabase(t)
	authenticated := &requests.Request{User: requests.User{
		Username: request.User.Username, Email: request.User.Email,
		Password: "correct horse battery staple",
	}}
	if err := db.AuthenticateUser(authenticated); err != nil {
		t.Fatal(err)
	}
	proof := authenticated.Authentication
	if err := db.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: request.User.Username, Email: request.User.Email,
		OldPassword: "correct horse battery staple", Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1800000000, 0).UTC()
	request.Authentication = proof
	request.MfaToken.Passcode = totpReplayCode(t, uint64(ts.Unix()/30))
	if err := db.consumeMfaTOTPWithTime(request, ts); err == nil {
		t.Fatal("TOTP completed a password checkpoint revoked in the same database instance")
	}
}

func TestDatabaseStaleContinuationCannotLockCurrentIdentity(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, true)
	proof := authenticated.Authentication
	if err := db.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email,
		OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal(err)
	}
	stale := identityRequest(t, authenticated)
	stale.Authentication = proof
	for range 20 {
		if err := db.IncrementMfaFailedAttempts(stale); !errors.Is(err, ErrIdentityRequestDenied) {
			t.Fatal("stale continuation increment was not rejected", err)
		}
	}
	if db.Users[0].MfaFailedAttempts != 0 || db.Users[0].Lockout != nil && db.Users[0].Lockout.IsLocked() {
		t.Fatal("stale continuation locked the current identity")
	}
}

func TestDatabaseWebAuthnContinuationRejectsChangedIdentity(t *testing.T) {
	const (
		rpID      = "login.example.test"
		origin    = "https://login.example.test"
		challenge = "pending-login-challenge"
	)
	db, authenticated := newMFABindingTestDatabase(t, true)
	registered, key, credentialID := newWebAuthnOriginTestUser(t, rpID)
	db.Users[0].MfaTokens = registered.MfaTokens
	proof := authenticated.Authentication
	assertion := webAuthnOriginTestAssertion(t, key, credentialID, rpID, challenge, origin)
	valid := &requests.Request{
		User:           requests.User{Username: authenticated.User.Username, Email: authenticated.User.Email},
		Authentication: proof,
		WebAuthn: requests.WebAuthn{
			Request: assertion, Challenge: challenge, ExpectedOrigin: origin,
		},
	}
	if err := db.AuthenticateUser(valid); err != nil {
		t.Fatalf("current WebAuthn continuation rejected: %v", err)
	}
	if err := db.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email,
		OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatal(err)
	}
	valid.Authentication = proof
	valid.WebAuthn.Request = assertion
	if err := db.AuthenticateUser(valid); err == nil {
		t.Fatal("WebAuthn completed a password checkpoint revoked in the same database instance")
	}
}

func TestDatabaseCopyLeavesSourceWritable(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, false)
	revision := db.Revision
	if err := db.Copy(t.TempDir() + "/backup.json"); err != nil {
		t.Fatal(err)
	}
	if db.Revision != revision {
		t.Fatalf("copy changed live source revision: got %d, want %d", db.Revision, revision)
	}
	if err := db.ChangeUserPassword(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email,
		OldPassword: tests.TestPwd1, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatalf("source mutation after copy failed: %v", err)
	}
	loaded := mustLoadMFABindingDatabase(t, db.GetPath())
	if err := loaded.AuthenticateUser(&requests.Request{User: requests.User{
		Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd2,
	}}); err != nil {
		t.Fatalf("source did not retain mutation after copy: %v", err)
	}
}

func TestDatabaseAliasCannotRevokeDuringRefreshIdentityUse(t *testing.T) {
	stale, authenticated := newMFABindingTestDatabase(t, false)
	current := mustLoadMFABindingDatabase(t, stale.GetPath())
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- stale.WithRefreshIdentity(t.Context(), authenticated.Authentication, func(RefreshIdentity) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	revokeResult := make(chan error, 1)
	go func() {
		revokeResult <- current.RevokeUserSessions(t.Context(), authenticated.Authentication.UserID)
	}()
	select {
	case err := <-revokeResult:
		close(release)
		<-result
		if err == nil {
			t.Fatal("cross-instance revocation committed during refresh identity use")
		}
	case <-time.After(100 * time.Millisecond):
		close(release)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		if err := <-revokeResult; err != nil {
			t.Fatal(err)
		}
	}
}

func TestDatabaseAliasCannotResetPasswordDuringAuthentication(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, false)
	slow, err := NewPasswordWithOptions(tests.TestPwd1, "generic", "bcrypt", map[string]any{"cost": 12})
	if err != nil {
		t.Fatal(err)
	}
	db.Users[0].Passwords = []*Password{slow}
	if err := db.Save(); err != nil {
		t.Fatal(err)
	}
	stale := mustLoadMFABindingDatabase(t, db.GetPath())
	current := mustLoadMFABindingDatabase(t, db.GetPath())
	authResult := make(chan error, 1)
	go func() {
		authResult <- stale.AuthenticateUser(&requests.Request{User: requests.User{
			Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd1,
		}})
	}()
	time.Sleep(25 * time.Millisecond)
	resetResult := make(chan error, 1)
	go func() {
		resetResult <- current.ResetUserPassword(&requests.Request{User: requests.User{
			Username: authenticated.User.Username, Email: authenticated.User.Email, Password: tests.TestPwd2,
		}})
	}()
	select {
	case err := <-resetResult:
		if err != nil {
			t.Fatal(err)
		}
		if err := <-authResult; err == nil {
			t.Fatal("password reset committed while the revoked password was being authenticated")
		}
	case err := <-authResult:
		if err != nil {
			t.Fatal("password authentication failed before the concurrent reset committed", err)
		}
		if err := <-resetResult; err != nil {
			t.Fatal(err)
		}
	}
}

func TestDatabaseAliasCannotDeleteAPIKeyDuringLookup(t *testing.T) {
	db, authenticated := newMFABindingTestDatabase(t, false)
	secret := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"
	add := &requests.Request{
		User: requests.User{Username: authenticated.User.Username, Email: authenticated.User.Email},
		Key:  requests.Key{Usage: "api", Payload: secret, Comment: "lookup race"},
	}
	if err := db.AddAPIKey(add); err != nil {
		t.Fatal(err)
	}
	slow, err := NewPasswordWithOptions(secret, "generic", "bcrypt", map[string]any{"cost": 12})
	if err != nil {
		t.Fatal(err)
	}
	db.Users[0].APIKeys[0].Payload = slow.Hash
	if err := db.Save(); err != nil {
		t.Fatal(err)
	}
	stale := mustLoadMFABindingDatabase(t, db.GetPath())
	current := mustLoadMFABindingDatabase(t, db.GetPath())
	lookupResult := make(chan error, 1)
	go func() {
		lookupResult <- stale.LookupAPIKey(&requests.Request{Key: requests.Key{Payload: secret}})
	}()
	time.Sleep(25 * time.Millisecond)
	deleteResult := make(chan error, 1)
	go func() {
		key := current.Users[0].APIKeys[0]
		deleteResult <- current.DeleteAPIKey(&requests.Request{
			User: requests.User{Username: authenticated.User.Username, Email: authenticated.User.Email},
			Key:  requests.Key{ID: key.ID, Prefix: key.Prefix, Usage: key.Usage},
		})
	}()
	select {
	case err := <-deleteResult:
		if err != nil {
			t.Fatal(err)
		}
		if err := <-lookupResult; err == nil {
			t.Fatal("API key deletion committed while the revoked key was being authenticated")
		}
	case err := <-lookupResult:
		if err != nil {
			t.Fatal("API key lookup failed before the concurrent deletion committed", err)
		}
		if err := <-deleteResult; err != nil {
			t.Fatal(err)
		}
	}
}

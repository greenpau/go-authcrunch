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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const totpReplayTestSecret = "0123456789abcdef0123456789abcdef"

func newTOTPReplayDatabase(t *testing.T) (*Database, string, *requests.Request) {
	t.Helper()
	path := t.TempDir() + "/users.json"
	db, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{
		Username: "alice", Email: "alice@example.test", Password: "correct horse battery staple",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddMfaToken(&requests.Request{
		User: requests.User{Username: "alice", Email: "alice@example.test"},
		MfaToken: requests.MfaToken{
			Type: "totp", Comment: "replay test", Secret: totpReplayTestSecret,
			Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true,
		},
	}); err != nil {
		t.Fatal(err)
	}
	return db, path, &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}}
}

func totpReplayCode(t *testing.T, counter uint64) string {
	t.Helper()
	code, err := generateMfaCode(totpReplayTestSecret, "sha1", 6, counter)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestDatabaseConsumeMfaTOTPRejectsReplay(t *testing.T) {
	db, path, req := newTOTPReplayDatabase(t)
	ts := time.Unix(1800000000, 0).UTC()
	counter := uint64(ts.Unix() / 30)
	req.MfaToken.Passcode = totpReplayCode(t, counter)

	// Stateless validation remains safe for enrollment and diagnostics.
	token := db.Users[0].MfaTokens[0]
	if err := token.ValidateCodeWithTime(req.MfaToken.Passcode, ts); err != nil {
		t.Fatal(err)
	}
	if err := token.ValidateCodeWithTime(req.MfaToken.Passcode, ts); err != nil || token.LastTOTPCounter != nil {
		t.Fatal("stateless validation consumed the TOTP step")
	}

	if err := db.consumeMfaTOTPWithTime(req, ts); err != nil {
		t.Fatal(err)
	}
	get := &requests.Request{User: req.User}
	if err := db.GetMfaTokens(get); err != nil {
		t.Fatal(err)
	}
	copy := get.Response.Payload.(*MfaTokenBundle).Get()[0]
	if copy.LastTOTPCounter == nil {
		t.Fatal("consumed counter was not returned")
	}
	*copy.LastTOTPCounter = 0
	if db.Users[0].MfaTokens[0].LastTOTPCounter == nil || *db.Users[0].MfaTokens[0].LastTOTPCounter != counter {
		t.Fatal("returned token could mutate the stored replay counter")
	}
	if err := db.consumeMfaTOTPWithTime(req, ts); err == nil {
		t.Fatal("accepted the same TOTP step twice")
	}

	// A separately loaded database observes the persisted high-water mark.
	reloaded, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.consumeMfaTOTPWithTime(req, ts); err == nil {
		t.Fatal("database reload accepted a consumed TOTP step")
	}

	// Accepting a newer step also closes older steps in the skew window.
	req.MfaToken.Passcode = totpReplayCode(t, counter+1)
	if err := reloaded.consumeMfaTOTPWithTime(req, ts.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	req.MfaToken.Passcode = totpReplayCode(t, counter)
	if err := reloaded.consumeMfaTOTPWithTime(req, ts.Add(30*time.Second)); err == nil {
		t.Fatal("accepted an older TOTP step after a newer step")
	}
}

func TestDatabaseConsumeMfaTOTPConcurrentAliases(t *testing.T) {
	db, path, req := newTOTPReplayDatabase(t)
	alias, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	staleWriter, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	databases := []*Database{db, alias}
	symlinkPath := t.TempDir() + "/users-symlink.json"
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Logf("symlink alias unavailable: %v", err)
	} else {
		symlinkAlias, err := NewDatabase(symlinkPath)
		if err != nil {
			t.Fatal(err)
		}
		databases = append(databases, symlinkAlias)
	}
	ts := time.Unix(1800000000, 0).UTC()
	req.MfaToken.Passcode = totpReplayCode(t, uint64(ts.Unix()/30))

	const attempts = 24
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			candidate := *req
			results <- databases[i%len(databases)].consumeMfaTOTPWithTime(&candidate, ts)
		}(i)
	}
	wg.Wait()
	close(results)
	var accepted int
	for err := range results {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent database aliases accepted one step %d times", accepted)
	}

	// A later commit from the stale alias must preserve the high-water mark.
	if err := staleWriter.AddUser(&requests.Request{User: requests.User{
		Username: "bob", Email: "bob@example.test", Password: "another correct horse battery staple",
	}}); err == nil {
		t.Fatal("stale alias mutation did not report its revision conflict")
	}
	if err := staleWriter.AddUser(&requests.Request{User: requests.User{
		Username: "bob", Email: "bob@example.test", Password: "another correct horse battery staple",
	}}); err != nil {
		t.Fatal("mutation retry after adopting replay state failed", err)
	}
	reloaded, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.consumeMfaTOTPWithTime(req, ts); err == nil {
		t.Fatal("stale database commit erased the consumed TOTP step")
	}
}

func TestDatabaseConsumeMfaTOTPStorageFailure(t *testing.T) {
	db, path, req := newTOTPReplayDatabase(t)
	ts := time.Unix(1800000000, 0).UTC()
	req.MfaToken.Passcode = totpReplayCode(t, uint64(ts.Unix()/30))

	db.path = t.TempDir()
	if err := db.consumeMfaTOTPWithTime(req, ts); err == nil {
		t.Fatal("storage failure accepted a TOTP step")
	}
	db.path = path
	if err := db.consumeMfaTOTPWithTime(req, ts); err != nil {
		t.Fatal("storage failure consumed the TOTP step")
	}
}

func TestDatabaseCopyDoesNotImportTOTPReplayState(t *testing.T) {
	db, sourcePath, req := newTOTPReplayDatabase(t)
	ts := time.Unix(1800000000, 0).UTC()
	counter := uint64(ts.Unix() / 30)
	req.MfaToken.Passcode = totpReplayCode(t, counter)
	if err := db.consumeMfaTOTPWithTime(req, ts); err != nil {
		t.Fatal(err)
	}

	destinationPath := t.TempDir() + "/copy.json"
	if err := db.Copy(destinationPath); err != nil {
		t.Fatal(err)
	}
	destination, err := NewDatabase(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	higherCounter := counter + 100
	destination.Users[0].MfaTokens[0].LastTOTPCounter = &higherCounter
	if err := destination.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(destinationPath, 0640); err != nil {
		t.Fatal(err)
	}
	beforeCopy, err := os.Stat(destinationPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.Copy(destinationPath); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(destinationPath); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != beforeCopy.Mode().Perm() {
		t.Fatalf("copy changed database mode to %04o", got)
	}
	if got := *db.Users[0].MfaTokens[0].LastTOTPCounter; got != counter {
		t.Fatalf("copy imported destination replay counter %d", got)
	}
	for _, path := range []string{sourcePath, destinationPath} {
		loaded, err := NewDatabase(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := *loaded.Users[0].MfaTokens[0].LastTOTPCounter; got != counter {
			t.Fatalf("database %q has replay counter %d after copy", path, got)
		}
	}
}

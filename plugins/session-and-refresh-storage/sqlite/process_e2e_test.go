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

package sqlite_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	storage "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
)

// Acknowledged admission, rotation, and replay history survive abrupt process
// termination. The first child also initializes a previously absent database.
func TestE2ESQLiteAbruptRestart(t *testing.T) {
	const pathEnv = "AUTHCRUNCH_SQLITE_CRASH_PATH"
	binding := tokenrefresh.Binding{Portal: "crash", Origin: "https://login.example.test", BasePath: "/auth", Transport: tokenrefresh.BodyTransport}
	now := time.Now().Unix()
	first := tokenrefresh.Session{
		ID: "crash-family", Current: sha256.Sum256([]byte("crash-original")), Binding: binding,
		IdleExpiresAt: now + 300, AbsoluteExpiresAt: now + 600,
		Principal: tokenrefresh.Principal{Backend: "local", Realm: "local", UserID: "immutable-alice", Subject: "alice", AuthTime: now, Methods: []string{"pwd"}},
	}
	next := sha256.Sum256([]byte("crash-next"))
	if path := os.Getenv(pathEnv); path != "" {
		store, err := storage.New(t.Context(), storageConfig(t, path))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if os.Getenv("AUTHCRUNCH_SQLITE_CRASH_PHASE") == "create" {
			err = store.Create(t.Context(), first, now+60)
		} else {
			err = store.Rotate(t.Context(), first, next, now+120, now+60)
		}
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("SQLITE_COMMIT_ACKNOWLEDGED")
		// The parent kills this process while it still owns the open Store.
		if _, err := io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
			t.Fatal("crash barrier failed", err)
		}
		return
	}
	path := filepath.Join(privateDirectory(t), "crash.db")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"create", "rotate"} {
		func() {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestE2ESQLiteAbruptRestart$", "-test.count=1", "-test.timeout=20s")
			command.Env = append(os.Environ(), pathEnv+"="+path, "AUTHCRUNCH_SQLITE_CRASH_PHASE="+phase)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
			line, readErr := bufio.NewReader(stdout).ReadString('\n')
			if readErr != nil || line != "SQLITE_COMMIT_ACKNOWLEDGED\n" {
				_ = command.Process.Kill()
				_ = command.Wait()
				t.Fatalf("child did not acknowledge %s: %v\n%s", phase, readErr, stderr.String())
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err == nil {
				t.Fatal("child exited normally instead of crashing")
			}
		}()
		store, err := storage.New(t.Context(), storageConfig(t, path))
		if err != nil {
			t.Fatal("reopen after crash", err)
		}
		t.Cleanup(func() { _ = store.Close() })
		current := first.Current
		if phase == "rotate" {
			current = next
		}
		if _, err := store.Lookup(t.Context(), current, binding); err != nil {
			t.Fatal("crash lost acknowledged credential", err)
		}
		if phase == "rotate" {
			if _, err := store.Lookup(t.Context(), first.Current, binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
				t.Fatal("crash lost spent history", err)
			}
			if _, err := store.Lookup(t.Context(), next, binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
				t.Fatal("replay after crash did not revoke descendant", err)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestE2ESQLiteProcessStorage(t *testing.T) {
	const pathEnv = "AUTHCRUNCH_SQLITE_PROCESS_PATH"
	binding := tokenrefresh.Binding{Portal: "process", Origin: "https://login.example.test", BasePath: "/auth", Transport: tokenrefresh.BodyTransport}
	previous := tokenrefresh.Session{ID: "process-family", Current: sha256.Sum256([]byte("process-original")), Binding: binding}
	if path := os.Getenv(pathEnv); path != "" {
		store, err := storage.New(t.Context(), storageConfig(t, path))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		fmt.Println("SQLITE_STORAGE_READY")
		if _, err := io.ReadFull(os.Stdin, make([]byte, 1)); err != nil {
			t.Fatal("process barrier failed")
		}
		now := time.Now().Unix()
		next := sha256.Sum256([]byte("process-next-" + os.Getenv("AUTHCRUNCH_SQLITE_PROCESS_INDEX")))
		err = store.Rotate(t.Context(), previous, next, now+120, now+60)
		switch {
		case err == nil:
			fmt.Println("SQLITE_ROTATION_WIN")
		case errors.Is(err, tokenrefresh.ErrInvalid):
			fmt.Println("SQLITE_ROTATION_DENY")
		default:
			t.Fatal("process rotation failed", err)
		}
		return
	}
	path := filepath.Join(privateDirectory(t), "process.db")
	config := storageConfig(t, path)
	store, err := storage.New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().Unix()
	previous.Principal = tokenrefresh.Principal{Backend: "local", Realm: "local", UserID: "immutable-alice", Subject: "alice", BackendVersion: "epoch", CredentialVersion: 1, AuthTime: now, Methods: []string{"pwd"}, Challenges: []string{"password"}}
	previous.IdleExpiresAt, previous.AbsoluteExpiresAt = now+300, now+600
	if err := store.Create(t.Context(), previous, now+60); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var commands [2]*exec.Cmd
	var stderr [2]bytes.Buffer
	var readers [2]*bufio.Reader
	var barriers [2]io.WriteCloser
	for i := range commands {
		command := exec.CommandContext(ctx, executable, "-test.run=^TestE2ESQLiteProcessStorage$", "-test.count=1", "-test.timeout=20s")
		command.Env = append(os.Environ(), pathEnv+"="+path, fmt.Sprintf("AUTHCRUNCH_SQLITE_PROCESS_INDEX=%d", i))
		command.Stderr = &stderr[i]
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		barriers[i], err = command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands[i] = command
		// Reap even if a later child fails to start or the parent assertion fails.
		t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
		readers[i] = bufio.NewReader(stdout)
		line, readErr := readers[i].ReadString('\n')
		if readErr != nil || line != "SQLITE_STORAGE_READY\n" {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("SQLite child did not initialize: %v\n%s%s", readErr, line, stderr[i].String())
		}
	}
	// Open clients before racing rotation. SQLite connection setup can briefly
	// hold read locks; overlapping setup tests commit rejection, not rotation's
	// one-winner/replay contract. Both independent clients are now ready.
	for _, barrier := range barriers {
		if _, err := barrier.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if err := barrier.Close(); err != nil {
			t.Fatal(err)
		}
	}
	wins, denials := 0, 0
	for i, command := range commands {
		output, readErr := io.ReadAll(readers[i])
		if err := command.Wait(); err != nil {
			t.Fatalf("SQLite child failed: %v\n%s%s", err, output, stderr[i].String())
		}
		if readErr != nil {
			t.Fatal("read child result", readErr)
		}
		wins += bytes.Count(output, []byte("SQLITE_ROTATION_WIN"))
		denials += bytes.Count(output, []byte("SQLITE_ROTATION_DENY"))
	}
	if wins != 1 || denials != 1 {
		t.Fatalf("cross-process rotation: %d winners, %d denials", wins, denials)
	}
	reopened, err := storage.New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.ValidateSession(t.Context(), previous.ID, binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("cross-process replay did not durably revoke winner", err)
	}
	for i := range 2 {
		next := sha256.Sum256(fmt.Appendf(nil, "process-next-%d", i))
		if _, err := reopened.Lookup(t.Context(), next, binding); !errors.Is(err, tokenrefresh.ErrInvalid) {
			t.Fatal("descendant survived restart", err)
		}
	}
}

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

package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(&Config{Directory: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func TestStoreRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := openTestStore(t, dir)
	r, err := s.OpenRecord("session/policy", "binding")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("private synthetic session")
	if err = r.Save(data); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(filepath.Join(dir, r.name))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, data) {
		t.Fatal("plaintext state on disk")
	}
	got, err := r.Load()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("state did not round trip")
	}
	got[0] = 'x'
	got, _ = r.Load()
	if !bytes.Equal(got, data) {
		t.Fatal("snapshot aliases caller")
	}
	if _, err := Open(&Config{Directory: dir}); err == nil {
		t.Fatal("concurrent owner accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Load(); err == nil {
		t.Fatal("closed record accepted")
	}
	s = openTestStore(t, dir)
	r, err = s.OpenRecord("session/policy", "binding")
	if err != nil {
		t.Fatal(err)
	}
	got, err = r.Load()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("restart lost committed state")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, dir)
	r, err = s.OpenRecord("session/policy", "changed")
	if err != nil {
		t.Fatal(err)
	}
	got, _ = r.Load()
	if len(got) != 0 {
		t.Fatal("changed policy restored state")
	}
	_ = s.Close()
	s = openTestStore(t, dir)
	r, err = s.OpenRecord("session/policy", "binding")
	if err != nil {
		t.Fatal(err)
	}
	got, _ = r.Load()
	if len(got) != 0 {
		t.Fatal("configuration rollback resurrected state")
	}
}
func TestStoreRejectsUnsafeState(t *testing.T) {
	for _, scenario := range []string{"corruption", "missing key", "missing record", "missing catalog", "corrupt catalog", "permissions", "symlink", "interrupted"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s := openTestStore(t, dir)
			r, err := s.OpenRecord("sessions", "binding")
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Save([]byte("session")); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			switch scenario {
			case "corruption":
				if err = os.WriteFile(filepath.Join(dir, r.name), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing key":
				if err = os.Remove(filepath.Join(dir, "master.key")); err != nil {
					t.Fatal(err)
				}
			case "missing record":
				if err = os.Remove(filepath.Join(dir, r.name)); err != nil {
					t.Fatal(err)
				}
			case "missing catalog":
				if err = os.Remove(filepath.Join(dir, catalogName)); err != nil {
					t.Fatal(err)
				}
			case "corrupt catalog":
				if err = os.WriteFile(filepath.Join(dir, catalogName), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err = os.Chmod(filepath.Join(dir, "master.key"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err = os.Remove(filepath.Join(dir, r.name)); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink("master.key", filepath.Join(dir, r.name)); err != nil {
					t.Fatal(err)
				}
			case "interrupted":
				if err = os.WriteFile(filepath.Join(dir, r.name+".pending"), []byte{1}, 0600); err != nil {
					t.Fatal(err)
				}
			}
			s, err = Open(&Config{Directory: dir})
			if scenario == "missing key" || scenario == "permissions" || scenario == "missing catalog" || scenario == "corrupt catalog" {
				if err == nil {
					_ = s.Close()
					t.Fatal("unsafe storage accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r, err = s.OpenRecord("sessions", "binding")
			if scenario == "interrupted" {
				if err != nil {
					t.Fatal(err)
				}
				data, _ := r.Load()
				if len(data) != 0 {
					t.Fatal("ambiguous state restored")
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe record accepted")
			}
		})
	}
}
func TestStoreWriteFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := openTestStore(t, dir)
	r, err := s.OpenRecord("sessions", "binding")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(dir, r.name+".pending"), 0700); err != nil {
		t.Fatal(err)
	}
	if r.Save([]byte("new")) == nil || s.Err() == nil {
		t.Fatal("failed write did not poison store")
	}
	if _, err = r.Load(); err == nil {
		t.Fatal("failed store served cached state")
	}
}

func TestRecordCodec(t *testing.T) {
	storage := openTestStore(t, filepath.Join(t.TempDir(), "state"))
	record, err := storage.OpenRecord("private-proof", "v1")
	if err != nil {
		t.Fatal(err)
	}
	// JSON exclusions cannot be used for internal proof snapshots.
	type proof struct {
		Identity string `json:"-"`
		Version  uint64 `json:"-"`
	}
	var restored proof
	if found, err := record.Decode(&restored); err != nil || found {
		t.Fatal("empty record was not absent")
	}
	want := proof{Identity: "immutable", Version: 9}
	if err := record.Encode(want); err != nil {
		t.Fatal(err)
	}
	if found, err := record.Decode(&restored); err != nil || !found || restored != want {
		t.Fatal("private proof did not round trip")
	}
	if err := record.Encode(func() {}); err == nil {
		t.Fatal("unsupported snapshot encoded")
	}
	if err := storage.Err(); err != nil {
		t.Fatalf("pre-commit encoding failure poisoned storage: %v", err)
	}
	if err := record.Encode(want); err != nil {
		t.Fatalf("storage did not recover from pre-commit encoding failure: %v", err)
	}
	data, err := record.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Save(append(data, 0xff)); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Decode(&restored); err == nil {
		t.Fatal("trailing state bytes accepted")
	}
}

func TestStoreCompletesInterruptedFirstInitialization(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	storage := openTestStore(t, directory)
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, catalogName)); err != nil {
		t.Fatal(err)
	}

	storage = openTestStore(t, directory)
	record, err := storage.OpenRecord("sessions", "binding")
	if err != nil {
		t.Fatalf("first initialization did not resume after the master key commit: %v", err)
	}
	if err := record.Save([]byte("committed")); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	storage = openTestStore(t, directory)
	record, err = storage.OpenRecord("sessions", "binding")
	if err != nil {
		t.Fatal(err)
	}
	data, err := record.Load()
	if err != nil || string(data) != "committed" {
		t.Fatal("state committed after resumed initialization did not survive restart")
	}
}

func TestMissingDirectories(t *testing.T) {
	root := t.TempDir()
	want := []string{
		filepath.Join(root, "one", "two", "state"),
		filepath.Join(root, "one", "two"),
		filepath.Join(root, "one"),
	}
	got, err := missingDirectories(want[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("missing directory count: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("missing directory %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestStoreRecordLimitFailsClosed(t *testing.T) {
	storage := openTestStore(t, filepath.Join(t.TempDir(), "state"))
	record, err := storage.OpenRecord("sessions", "binding")
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Save(make([]byte, maxRecordPayloadSize+1)); !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrCapacity) {
		t.Fatal("oversized snapshot was not an unavailable commit")
	}
	if storage.Err() == nil {
		t.Fatal("size failure left composite authentication available")
	}
}

func TestPrepareEncodeCapacityIsNonMutating(t *testing.T) {
	storage := openTestStore(t, filepath.Join(t.TempDir(), "state"))
	record, err := storage.OpenRecord("sessions", "binding")
	if err != nil {
		t.Fatal(err)
	}
	type snapshot struct{ Data []byte }
	want := snapshot{Data: []byte("previous authority")}
	if err := record.Encode(want); err != nil {
		t.Fatal(err)
	}
	if _, err := record.PrepareEncode(snapshot{Data: make([]byte, maxRecordPayloadSize+1)}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversized candidate error: %v", err)
	}
	if err := storage.Err(); err != nil {
		t.Fatalf("capacity preflight poisoned storage: %v", err)
	}
	var got snapshot
	found, err := record.Decode(&got)
	if err != nil || !found || !bytes.Equal(got.Data, want.Data) {
		t.Fatal("capacity preflight changed the committed snapshot")
	}
	prepared, err := record.PrepareEncode(snapshot{Data: []byte("replacement")})
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Save(prepared); err != nil {
		t.Fatalf("record was not writable after capacity refusal: %v", err)
	}
}

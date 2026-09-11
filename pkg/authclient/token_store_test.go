// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package authclient

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestFileTokenStore(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "caddy-authenticator", "token.jwt")
	store, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("constructor created a directory")
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error: %v", err)
	}
	credentials := &Credentials{AccessToken: "first", AccessTokenName: "portal_token", RefreshToken: "old-refresh"}
	if err := store.Save(credentials); err != nil {
		t.Fatal(err)
	}
	if credentials.CreatedAt != "" {
		t.Fatal("Save mutated caller credentials")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AccessToken != "first" || loaded.RefreshToken != "old-refresh" || loaded.CreatedAt == "" {
		t.Fatal("credential round trip failed")
	}
	if runtime.GOOS != "windows" {
		for _, tc := range []struct {
			path string
			mode os.FileMode
		}{{path, 0600}, {filepath.Dir(path), 0700}} {
			info, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != tc.mode {
				t.Errorf("unexpected permission on %s: %o", tc.path, info.Mode().Perm())
			}
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Save(&Credentials{AccessToken: "replacement"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AccessToken != "replacement" || loaded.RefreshToken != "" {
		t.Fatal("replacement retained stale credentials")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("replacement did not restore private file permissions")
		}
	}
	other, err := NewFileTokenStore(filepath.Join(root, "authdbctl", "token.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Save(&Credentials{AccessToken: "other-app"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Load()
	if err != nil || loaded.AccessToken != "replacement" {
		t.Fatal("application stores are not isolated")
	}
	if err := store.Save(nil); err == nil {
		t.Fatal("saved nil credentials")
	}
	if err := store.Save(&Credentials{}); err == nil {
		t.Fatal("saved empty credentials")
	}
	loaded, err = store.Load()
	if err != nil || loaded.AccessToken != "replacement" {
		t.Fatal("failed save changed the token file")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "token.jwt" {
		t.Fatal("temporary token files left behind")
	}
}

func TestLegacyTokenFiles(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
		header     string
	}{
		{"legacy complete", `{"access_token":"test","access_token_name":"custom","refresh_token":"refresh","created_at":"2026-03-03T12:00:00Z"}`, true, "custom=test"},
		{"legacy without name", `{"access_token":"test"}`, true, "authp_access_token=test"},
		{"unknown fields", `{"access_token":"test","future":"ignored"}`, true, "authp_access_token=test"},
		{"malformed", "private", false, ""},
		{"wrong token type", `{"access_token":123}`, false, ""},
		{"wrong expiry type", `{"access_token":"test","access_expires_at":"private"}`, false, ""},
		{"empty object", `{}`, false, ""},
		{"null", `null`, false, ""},
		{"trailing JSON", `{"access_token":"test"} {}`, false, ""},
		{"invalid name", `{"access_token":"private","access_token_name":"bad name"}`, false, ""},
		{"invalid value", `{"access_token":"private\n"}`, false, ""},
		{"oversized", strings.Repeat("x", maxResponseSize+1), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token.jwt")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			store, err := NewFileTokenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := store.Load()
			if !tc.valid {
				if err == nil || credentials != nil || strings.Contains(err.Error(), "private") {
					t.Fatalf("expected safe parse failure, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if header, err := credentials.Authorization(); err != nil || header != tc.header {
				t.Fatal("legacy authorization header changed")
			}
		})
	}
	if _, err := NewFileTokenStore(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestTokenStoreSaveFailure(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "token.jwt")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&Credentials{AccessToken: "test"}); err == nil {
		t.Fatal("replaced a directory with credentials")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "token.jwt" {
		t.Fatal("failed save left credentials in temporary file")
	}
	store, err = NewFileTokenStore(filepath.Join(root, "regular-file", "token.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular-file"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&Credentials{AccessToken: "test"}); err == nil {
		t.Fatal("invalid parent path accepted")
	}
}

func TestTokenStoreConcurrentReaders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rename atomicity is not guaranteed on Windows")
	}
	store, err := NewFileTokenStore(filepath.Join(t.TempDir(), "token.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&Credentials{AccessToken: "first"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				credentials, err := store.Load()
				if err != nil {
					t.Error(err)
					return
				}
				if credentials.AccessToken != "first" && credentials.AccessToken != "second" {
					t.Error("reader observed incomplete credentials")
					return
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		if err := store.Save(&Credentials{AccessToken: "second"}); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
}

// failingTokenFile uses a real temporary file so failure tests can verify that
// partial credentials are removed and the original file remains untouched.
type failingTokenFile struct {
	*os.File
	operation string
	err       error
}

func (f *failingTokenFile) Write(data []byte) (int, error) {
	if f.operation == "write" {
		n, err := f.File.Write(data[:len(data)/2])
		if err != nil {
			return n, err
		}
		return n, f.err
	}
	return f.File.Write(data)
}

func (f *failingTokenFile) Sync() error {
	if f.operation == "sync" {
		return f.err
	}
	return f.File.Sync()
}

func (f *failingTokenFile) Close() error {
	err := f.File.Close()
	if f.operation == "close" {
		return f.err
	}
	return err
}

func TestTokenStoreSaveFailuresPreserveCredentials(t *testing.T) {
	for _, tc := range []struct{ operation, prefix string }{
		{"create", "create temporary token file"},
		{"write", "write token file"},
		{"sync", "sync token file"},
		{"close", "close token file"},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := filepath.Join(root, "token.jwt")
			store, err := NewFileTokenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Save(&Credentials{AccessToken: "original", RefreshToken: "original-refresh"}); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("simulated storage failure")
			createTemp := store.createTemp
			var temporary *os.File
			store.createTemp = func(dir, pattern string) (tokenFile, error) {
				if tc.operation == "create" {
					return nil, failure
				}
				f, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				temporary = f
				return &failingTokenFile{File: f, operation: tc.operation, err: failure}, nil
			}
			err = store.Save(&Credentials{AccessToken: "replacement"})
			if !errors.Is(err, failure) || !strings.HasPrefix(err.Error(), tc.prefix+":") {
				t.Fatalf("expected wrapped %s failure, got %v", tc.operation, err)
			}
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(current, original) {
				t.Fatal("failed save changed existing credentials")
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "token.jwt" {
				t.Fatal("failed save left a temporary credential file")
			}
			if temporary != nil {
				if _, err := temporary.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("temporary file was not closed: %v", err)
				}
			}
			// A failed operation must leave the store usable for a later save.
			store.createTemp = createTemp
			if err := store.Save(&Credentials{AccessToken: "replacement"}); err != nil {
				t.Fatal(err)
			}
			credentials, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if credentials.AccessToken != "replacement" || credentials.RefreshToken != "" {
				t.Fatal("store did not recover after failed save")
			}
		})
	}
}

func TestTokenStoreReadFailure(t *testing.T) {
	// Opening a directory succeeds, but reading it as a credential file fails.
	store, err := NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := store.Load()
	var pathErr *os.PathError
	if credentials != nil || !errors.As(err, &pathErr) || pathErr.Op != "read" || !strings.HasPrefix(err.Error(), "read token file:") {
		t.Fatalf("expected wrapped filesystem read failure, got %v", err)
	}
}

func TestTokenStoreRejectsOversizedSave(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new file"
		if existing {
			name = "existing file"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "private", "token.jwt")
			store, err := NewFileTokenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			var original []byte
			if existing {
				if err := store.Save(&Credentials{AccessToken: "original"}); err != nil {
					t.Fatal(err)
				}
				original, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			// JSON escaping expands the refresh token beyond the persisted limit,
			// although the unencoded field itself is smaller than that limit.
			credentials := &Credentials{AccessToken: "test", RefreshToken: strings.Repeat("\n", maxResponseSize/2)}
			err = store.Save(credentials)
			if err == nil || err.Error() != "token file exceeds size limit" {
				t.Fatalf("expected file size rejection, got %v", err)
			}
			if credentials.CreatedAt != "" {
				t.Fatal("rejected save mutated the caller's credentials")
			}
			if existing {
				current, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(current, original) {
					t.Fatal("oversized save changed existing credentials")
				}
				entries, err := os.ReadDir(filepath.Dir(path))
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 {
					t.Fatal("oversized save created a temporary file")
				}
			} else if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("oversized save created a directory")
			}
		})
	}
}

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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	maxRecordSize        = 128 << 20
	maxRecordPayloadSize = maxRecordSize / 2
)

// ErrUnavailable indicates that state cannot safely be read or committed.
// A failed write poisons this runtime; reopen it to recover durable state.
var ErrUnavailable = errors.New("persistent state unavailable")

// ErrCapacity indicates that a component snapshot exceeds the supported
// plaintext payload limit. Callers that prepare a candidate snapshot before
// mutating live state may reject it without disabling the store.
var ErrCapacity = errors.New("persistent state capacity exceeded")

// Store owns an exclusively locked directory and its encryption key. Records
// are authenticated and atomically replaced before a successful Save returns.
// A host must drain and close the old owner before opening a replacement.
// This is local persistence, not a distributed session service.
type Store struct {
	mu             sync.Mutex
	root           *os.Root
	lock           *os.File
	cipher         cipher.AEAD
	records        map[string]*Record
	catalog        map[string]bool
	failed, closed bool
}

// Record is an independently versioned component snapshot. Its name and binding
// must come from trusted runtime configuration, never an HTTP request. Callers
// serialize mutations with Save and publish credentials only after it succeeds.
type Record struct {
	store         *Store
	name, binding string
	data          []byte
}

type envelope struct {
	Version int
	Binding string
	Data    []byte
}

// Open creates or reopens owner-only storage. Missing keys beside existing
// records, corruption, unsafe permissions, and competing owners fail closed.
func Open(config *Config) (_ *Store, err error) {
	if config == nil {
		return nil, fmt.Errorf("state config is nil")
	}
	c := *config
	if err := c.Validate(); err != nil {
		return nil, err
	}
	createdDirectories, err := missingDirectories(c.Directory)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.Directory, 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := syncCreatedDirectories(createdDirectories); err != nil {
		return nil, fmt.Errorf("persist state directory: %w", err)
	}
	info, err := os.Lstat(c.Directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("state directory must be a private directory")
	}
	r, err := os.OpenRoot(c.Directory)
	if err != nil {
		return nil, err
	}
	s := &Store{root: r, records: make(map[string]*Record)}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	if err := s.checkFile("owner.lock"); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	s.lock, err = r.OpenFile("owner.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(s.lock); err != nil {
		return nil, fmt.Errorf("state directory already in use: %w", err)
	}
	key, err := s.readFile("master.key")
	if os.IsNotExist(err) {
		dir, openErr := r.Open(".")
		if openErr != nil {
			return nil, openErr
		}
		entries, readErr := dir.ReadDir(-1)
		_ = dir.Close()
		if readErr != nil {
			return nil, readErr
		}
		for _, entry := range entries {
			if entry.Name() != "owner.lock" {
				return nil, fmt.Errorf("state encryption key missing from nonempty directory")
			}
		}
		key = make([]byte, 32)
		rand.Read(key)
		if err = s.writeFile("master.key", key); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid state encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	s.cipher, err = cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	if err = s.loadCatalog(); err != nil {
		return nil, err
	}
	return s, nil
}

// missingDirectories returns absent path elements from leaf to root. Syncing
// each containing directory in this order makes MkdirAll durable through the
// nearest ancestor that existed before initialization.
func missingDirectories(path string) ([]string, error) {
	var missing []string
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		_, err := os.Lstat(current)
		if err == nil {
			return missing, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect state directory: %w", err)
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return nil, fmt.Errorf("inspect state directory: no existing ancestor")
		}
	}
}

func syncCreatedDirectories(created []string) error {
	for _, path := range created {
		parent, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// Binding returns a deterministic digest without exposing configuration secrets.
func Binding(config any) (string, error) {
	b, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode state binding")
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// OpenRecord restores one component. A changed binding replaces its old state,
// so changing configuration away and back cannot resurrect older sessions.
func (s *Store) OpenRecord(name, binding string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return nil, ErrUnavailable
	}
	if name == "" || binding == "" {
		return nil, fmt.Errorf("state name and binding are required")
	}
	h := sha256.Sum256([]byte(name))
	filename := hex.EncodeToString(h[:]) + ".state"
	if existing := s.records[filename]; existing != nil {
		if existing.binding != binding {
			return nil, fmt.Errorf("conflicting state binding")
		}
		return existing, nil
	}
	r := &Record{store: s, name: filename, binding: binding}
	b, err := s.readFile(filename)
	if os.IsNotExist(err) && s.catalog[filename] {
		return nil, fmt.Errorf("committed state record is missing")
	}
	needsWrite := os.IsNotExist(err)
	if err == nil {
		plain, decryptErr := s.cipher.Open(nil, nil, b, []byte(filename))
		if decryptErr != nil {
			return nil, fmt.Errorf("state authentication failed")
		}
		var e envelope
		if json.Unmarshal(plain, &e) != nil || e.Version != 1 {
			return nil, fmt.Errorf("unsupported or malformed state record")
		}
		if e.Binding == binding {
			r.data = e.Data
		} else {
			needsWrite = true
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// An interrupted commit is ambiguous. Retire its session snapshot rather
	// than risk restoring a credential revoked by the interrupted operation.
	if _, err := s.root.Lstat(filename + ".pending"); err == nil {
		r.data = nil
		needsWrite = true
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if needsWrite {
		if err := r.saveLocked(r.data); err != nil {
			return nil, err
		}
	}
	if !s.catalog[filename] {
		s.catalog[filename] = true
		if err := s.saveCatalog(); err != nil {
			return nil, err
		}
	}
	s.records[filename] = r
	return r, nil
}

// Load returns an independent copy of the last committed snapshot.
func (r *Record) Load() ([]byte, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	if r.store.closed || r.store.failed {
		return nil, ErrUnavailable
	}
	return bytes.Clone(r.data), nil
}

// Save synchronously commits a complete snapshot. Failed or interrupted writes
// cannot produce a successful authentication or logout acknowledgement.
func (r *Record) Save(data []byte) error {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	if r.store.closed || r.store.failed {
		return ErrUnavailable
	}
	if bytes.Equal(data, r.data) {
		return nil
	}
	return r.saveLocked(data)
}

func (r *Record) saveLocked(data []byte) error {
	s := r.store
	if len(data) > maxRecordPayloadSize {
		s.failed = true
		return fmt.Errorf("state record too large: %w: %w", ErrCapacity, ErrUnavailable)
	}
	plain, err := json.Marshal(envelope{Version: 1, Binding: r.binding, Data: data})
	if err != nil {
		return err
	}
	encrypted := s.cipher.Seal(nil, nil, plain, []byte(r.name))
	if err = s.writeFile(r.name+".pending", []byte{1}); err == nil {
		err = s.writeFile(r.name, encrypted)
	}
	if err == nil {
		err = s.root.Remove(r.name + ".pending")
	}
	if err == nil {
		err = syncDirectory(s.root)
	}
	if err != nil {
		s.failed = true
		return fmt.Errorf("commit state: %w", ErrUnavailable)
	}
	r.data = bytes.Clone(data)
	return nil
}

// Err checks whether this store still permits security decisions.
func (s *Store) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.failed {
		return ErrUnavailable
	}
	return nil
}

// Close releases ownership after the host has drained all users. It does not
// delete state and does not need to flush: successful mutations are durable.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.lock != nil {
		err = s.lock.Close()
	}
	if s.root != nil {
		err = errors.Join(err, s.root.Close())
	}
	if s.failed {
		err = errors.Join(err, ErrUnavailable)
	}
	return err
}

func (s *Store) checkFile(name string) error {
	info, err := s.root.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxRecordSize {
		return fmt.Errorf("unsafe state file")
	}
	return nil
}

func (s *Store) readFile(name string) ([]byte, error) {
	if err := s.checkFile(name); err != nil {
		return nil, err
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRecordSize+1))
	if len(b) > maxRecordSize {
		return nil, fmt.Errorf("state record too large")
	}
	return b, err
}

func (s *Store) writeFile(name string, data []byte) error {
	if err := s.checkFile(name); err != nil && !os.IsNotExist(err) {
		return err
	}
	var random [16]byte
	rand.Read(random[:])
	tmp := ".tmp-" + hex.EncodeToString(random[:])
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = s.root.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := s.root.Rename(tmp, name); err != nil {
		return err
	}
	return syncDirectory(s.root)
}

// Err checks availability without copying the snapshot.
func (r *Record) Err() error { return r.store.Err() }

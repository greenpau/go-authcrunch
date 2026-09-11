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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileTokenStore persists credentials at an application-selected path. It does
// not discover configuration, expand '~', or choose an application directory.
// Applications must select a private directory and a distinct path per portal
// and identity; legacy token files contain no binding to a portal or user.
type FileTokenStore struct {
	path       string
	createTemp func(dir, pattern string) (tokenFile, error)
}

// tokenFile is the file lifecycle required for atomic credential replacement.
// Keep the factory per store so failures can be exercised without global hooks.
type tokenFile interface {
	io.WriteCloser
	Name() string
	Sync() error
}

// NewFileTokenStore constructs a store without reading or creating any files.
func NewFileTokenStore(path string) (*FileTokenStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("token file path is required")
	}
	return &FileTokenStore{
		path: path,
		createTemp: func(dir, pattern string) (tokenFile, error) {
			return os.CreateTemp(dir, pattern)
		},
	}, nil
}

// Load reads a legacy-compatible JSON token file. A missing file remains
// detectable with errors.Is(err, os.ErrNotExist); malformed files are errors.
func (s *FileTokenStore) Load() (*Credentials, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("open token file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("token file exceeds size limit")
	}
	var credentials Credentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("invalid token file JSON")
	}
	if err := credentials.Validate(); err != nil {
		return nil, fmt.Errorf("invalid token file credentials: %w", err)
	}
	return &credentials, nil
}

// Save writes a complete replacement using a private temporary file and rename.
// On platforms with atomic rename, readers cannot observe partial JSON. New
// directories use mode 0700 and token files use 0600; existing directory
// permissions are retained (Windows permissions follow the filesystem's ACLs).
// Concurrent saves use last-writer-wins semantics, not refresh-token coordination.
func (s *FileTokenStore) Save(credentials *Credentials) error {
	if credentials == nil {
		return fmt.Errorf("credentials are required")
	}
	if err := credentials.Validate(); err != nil {
		return err
	}
	stored := *credentials
	if stored.CreatedAt == "" {
		stored.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// Credentials contains only strings and integers, with no custom marshaler.
	data, _ := json.Marshal(stored)
	if len(data)+1 > maxResponseSize {
		return fmt.Errorf("token file exceeds size limit")
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	f, err := s.createTemp(dir, ".auth-token-*")
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync token file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close token file: %w", err)
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return fmt.Errorf("replace token file: %w", err)
	}
	return nil
}

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
	"path/filepath"

	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func withDatabaseFileLock(path string, fn func() error) error {
	lockPath, err := canonicalDatabasePath(path)
	if err != nil {
		return errors.ErrDatabaseCommit.WithArgs(path, err)
	}
	file, err := os.OpenFile(lockPath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return errors.ErrDatabaseCommit.WithArgs(path, err)
	}
	defer file.Close()
	if err := lockDatabaseFile(file); err != nil {
		return errors.ErrDatabaseCommit.WithArgs(path, err)
	}
	defer unlockDatabaseFile(file)
	return fn()
}

func canonicalDatabasePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absPath)
	if err == nil {
		return resolved, nil
	}
	if os.IsNotExist(err) {
		resolvedDir, dirErr := filepath.EvalSymlinks(filepath.Dir(absPath))
		if dirErr == nil {
			return filepath.Join(resolvedDir, filepath.Base(absPath)), nil
		}
		return filepath.Clean(absPath), nil
	}
	return "", err
}

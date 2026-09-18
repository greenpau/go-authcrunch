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
	"io"
	"os"
	"path/filepath"
)

func writeDatabaseFileAtomically(path string, data []byte) (err error) {
	target, err := canonicalDatabasePath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(target)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	mode := os.FileMode(0600)
	if info, statErr := os.Stat(target); statErr == nil {
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	n, err := temp.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceDatabaseFile(tempPath, target); err != nil {
		return err
	}
	committed = true
	return syncDatabaseDirectory(dir)
}

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
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

const catalogName = "catalog.state"

type catalogSnapshot struct {
	Version int
	Records []string
}

// An authenticated inventory distinguishes first use from loss of an individual
// key/session record. A missing committed key must never silently rotate.
func (s *Store) loadCatalog() error {
	s.catalog = make(map[string]bool)
	encrypted, err := s.readFile(catalogName)
	if os.IsNotExist(err) {
		directory, err := s.root.Open(".")
		if err != nil {
			return err
		}
		entries, err := directory.ReadDir(-1)
		_ = directory.Close()
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != "owner.lock" && entry.Name() != "master.key" {
				return fmt.Errorf("state catalog missing from nonempty directory")
			}
		}
		return s.saveCatalog()
	}
	if err != nil {
		return err
	}
	plain, err := s.cipher.Open(nil, nil, encrypted, []byte(catalogName))
	if err != nil {
		return fmt.Errorf("state catalog authentication failed")
	}
	var snapshot catalogSnapshot
	if json.Unmarshal(plain, &snapshot) != nil || snapshot.Version != 1 {
		return fmt.Errorf("invalid state catalog")
	}
	for _, name := range snapshot.Records {
		if len(name) != 70 || s.catalog[name] {
			return fmt.Errorf("invalid state catalog record")
		}
		s.catalog[name] = true
	}
	return nil
}

func (s *Store) saveCatalog() error {
	snapshot := catalogSnapshot{Version: 1}
	for name := range s.catalog {
		snapshot.Records = append(snapshot.Records, name)
	}
	sort.Strings(snapshot.Records)
	plain, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	encrypted := s.cipher.Seal(nil, nil, plain, []byte(catalogName))
	if err := s.writeFile(catalogName, encrypted); err != nil {
		s.failed = true
		return fmt.Errorf("commit state catalog: %w", ErrUnavailable)
	}
	return nil
}

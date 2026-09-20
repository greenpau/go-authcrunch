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
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	for _, c := range []*Config{nil, {}, {Directory: "relative"}, {Directory: string(filepath.Separator)}, {Directory: "/invalid\npath"}} {
		if err := c.Validate(); err == nil {
			t.Fatal("unsafe directory accepted")
		}
	}
	directory := filepath.Join(t.TempDir(), "not-created")
	c := &Config{Directory: directory + string(filepath.Separator) + "."}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Directory != directory {
		t.Fatal("directory was not normalized")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("validation created storage")
	}
}

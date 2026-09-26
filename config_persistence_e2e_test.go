// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authcrunch_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
)

func TestE2EConfigPersistenceNarrowsPermissionsAndRoundTripsSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.json")
	if err := os.WriteFile(path, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}

	const secret = "configuration-secret"
	cfg := &authcrunch.Config{Credentials: &credentials.Config{Generic: []*credentials.GenericCredential{{
		Name: "smtp", Username: "mailer", Password: secret,
	}}}}
	if err := cfg.DumpToJSONFile(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("persisted configuration mode = %04o, want 0600", got)
	}

	var restored authcrunch.Config
	if err := restored.LoadFromJSONFile(path); err != nil {
		t.Fatal(err)
	}
	if restored.Credentials == nil || len(restored.Credentials.Generic) != 1 || restored.Credentials.Generic[0].Password != secret {
		t.Fatal("secret-bearing configuration did not round trip through the public persistence API")
	}
}

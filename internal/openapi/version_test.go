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

package openapi

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckVersion(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"info":{"version":"1.4.1"}}`)
	for _, version := range []string{"1.4.1", "1.4.1\n"} {
		put(t, dir, "VERSION", version)
		if err := CheckVersion(dir, data); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"v1.4.1", "2.4.1", "1.04.1", "1.4.01", "1.4.1-rc1", "1.4.1+build", "1.4.1\r\n", "1.4.1\n\n", "1.18446744073709551615.1", "1.18446744073709551616.1", ""} {
		put(t, dir, "VERSION", version)
		if err := CheckVersion(dir, data); err == nil {
			t.Errorf("accepted invalid VERSION %q", version)
		}
	}
	put(t, dir, "VERSION", "1.4.2")
	before := bytes.Clone(data)
	if err := CheckVersion(dir, data); err == nil || !strings.Contains(err.Error(), "make version-sync") {
		t.Fatalf("missing actionable drift error: %v", err)
	}
	if !bytes.Equal(data, before) {
		t.Fatal("version check modified the bundle")
	}
	for _, invalid := range []string{`{`, `{}`, `{"info":{"version":1}}`} {
		if err := CheckVersion(dir, []byte(invalid)); err == nil {
			t.Errorf("accepted invalid document %s", invalid)
		}
	}
	if err := os.Remove(filepath.Join(dir, "VERSION")); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion(dir, data); err == nil {
		t.Fatal("accepted missing VERSION")
	}
}

func TestBundleRejectsSymlinkContentRoot(t *testing.T) {
	dir := fixture(t)
	link := filepath.Join(t.TempDir(), "content")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Bundle(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("accepted content symlink: %v", err)
	}
}

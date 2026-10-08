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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestWriteArtifact(t *testing.T) {
	directory := t.TempDir()
	data := []byte(`{"openapi":"3.1.1","paths":{"/":{"get":{"responses":{"200":{"description":"OK"}}}}},"x-data":{"$ref":"https://example.test/literal","large":9007199254740993,"maximum":18446744073709551615,"fraction":1.25,"empty":null,"boolean":true,"strings":["200","true","on","yes","off","12:34","2026-10-08","null","a\nb"],"empty_object":{},"empty_array":[],"unicode":"before\u0085after\u2028line\u2029end\r\n","key\u0085name":"value"}}`)
	// JSON permits literal Unicode line breaks inside strings and keys. YAML
	// must preserve them, together with the already escaped CR/LF above.
	data = []byte(strings.NewReplacer(`\u0085`, "\u0085", `\u2028`, "\u2028", `\u2029`, "\u2029").Replace(string(data)))
	if err := WriteArtifact(directory, data); err != nil {
		t.Fatal(err)
	}
	actualJSON, err := os.ReadFile(filepath.Join(directory, "openapi.json"))
	if err != nil || !bytes.Equal(actualJSON, data) {
		t.Fatalf("JSON bundle changed: %v", err)
	}
	actualYAML, err := os.ReadFile(filepath.Join(directory, "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(actualYAML, []byte("\"openapi\": \"3.1.1\"\n")) || json.Valid(actualYAML) {
		t.Fatal("expected readable block YAML")
	}
	// YAML 1.1 consumers implicitly type these strings unless they are quoted.
	for _, literal := range []string{`"on"`, `"yes"`, `"off"`, `"12:34"`, `"2026-10-08"`} {
		if !bytes.Contains(actualYAML, []byte(literal)) {
			t.Fatalf("missing quoted string for YAML 1.1 compatibility: %s", literal)
		}
	}
	var value any
	if err := yaml.Unmarshal(actualYAML, &value); err != nil {
		t.Fatal(err)
	}
	converted, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(data []byte) any {
		t.Helper()
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if diff := cmp.Diff(decode(data), decode(converted)); diff != "" {
		t.Fatalf("YAML changed JSON values (-want +got):\n%s", diff)
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 2 {
		t.Fatalf("expected exactly two artifact files: %v", err)
	}
	// Identical regeneration preserves both files and their modification times.
	old := time.Unix(1234567890, 0)
	for _, file := range files {
		if err := os.Chtimes(filepath.Join(directory, file.Name()), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteArtifact(directory, data); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifact(directory, []byte("not JSON")); err == nil {
		t.Fatal("invalid input was exported")
	}
	for name, expected := range map[string][]byte{"openapi.json": actualJSON, "openapi.yaml": actualYAML} {
		file := filepath.Join(directory, name)
		actual, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("existing artifact changed: %s (%v)", name, err)
		}
		info, err := os.Stat(file)
		if err != nil || !info.ModTime().Equal(old) {
			t.Fatalf("unchanged artifact rewritten: %s (%v)", name, err)
		}
	}
}

func TestWriteArtifactRejectsSymlinks(t *testing.T) {
	for _, name := range []string{"directory", "openapi.json", "openapi.yaml"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "private/openapi.json", "keep")
			directory := filepath.Join(root, "artifact")
			target := filepath.Join(root, "private/openapi.json")
			link := filepath.Join(directory, name)
			if name == "directory" {
				target = filepath.Dir(target)
				link = directory
			} else if err := os.Mkdir(directory, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			if err := WriteArtifact(directory, []byte(`{"openapi":"3.1.1"}`)); err == nil {
				t.Fatal("artifact followed a symlink")
			}
			data, err := os.ReadFile(filepath.Join(root, "private/openapi.json"))
			if err != nil || string(data) != "keep" {
				t.Fatalf("artifact modified symlink target: %v", err)
			}
		})
	}
}

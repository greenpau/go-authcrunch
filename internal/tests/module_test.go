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

package tests

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExternalModuleFixtureErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing string
		want    string
	}{
		{"missing module", "go.mod", "read external module fixture"},
		{"missing checksums", "go.sum", "read external module fixture"},
		{"missing consumer", "consumer_test.go", "read external module fixture"},
		{"invalid destination", "destination", "write external module fixture"},
		{"invalid module", "syntax", "prepare external module"},
		{"cancelled", "context", "context canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, dir := t.TempDir(), t.TempDir()
			for name, content := range map[string]string{
				"go.mod": "module " + authcrunchModule + "\n\ngo 1.26.0\n",
				"go.sum": "", "consumer_test.go": "package consumer_test\n",
			} {
				if name != tc.missing {
					writeModuleFixture(t, filepath.Join(root, name), []byte(content))
				}
			}
			if tc.missing == "destination" {
				dir = filepath.Join(dir, "absent")
			}
			if tc.missing == "syntax" {
				writeModuleFixture(t, filepath.Join(root, "go.mod"), []byte("invalid directive\n"))
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if tc.missing == "context" {
				cancel()
			}
			output, err := runExternalModule(ctx, root, dir, "example.test/consumer", filepath.Join(root, "consumer_test.go"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v\n%s", tc.want, err, output)
			}
		})
	}
}

// Build a tiny real module graph in an empty private cache. The legacy module
// names an unavailable test-only dependency, like xml-roundtrip-validator's old
// testify requirement. A developer's warm cache must not hide the regression.
func TestE2EExternalModulePrunedDependencies(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	base := t.TempDir()
	root := filepath.Join(base, "checkout with spaces")
	proxy := filepath.Join(base, "proxy")
	cache := filepath.Join(base, "cache")
	const legacy = "example.test/legacy"
	const version = "v1.0.0"
	legacyMod := "module " + legacy + "\n\ngo 1.16\n\nrequire example.test/unavailable v1.0.0\n"
	files := map[string]string{
		"go.mod":    legacyMod,
		"legacy.go": "package legacy\n\nfunc Value() string { return \"public API\" }\n",
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	for name, data := range files {
		entry, err := zw.Create(legacy + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for suffix, data := range map[string][]byte{
		".mod": []byte(legacyMod), ".zip": archive.Bytes(),
		".info": []byte(`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`),
	} {
		writeModuleFixture(t, filepath.Join(proxy, legacy, "@v", version+suffix), data)
	}
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GONOPROXY", "none")
	t.Setenv("GOPROXY", (&url.URL{Scheme: "file", Path: filepath.ToSlash(proxy)}).String())
	// Seed only the selected module, without visiting its old transitive graph.
	bootstrap := filepath.Join(base, "bootstrap")
	writeModuleFixture(t, filepath.Join(bootstrap, "go.mod"), []byte("module example.test/bootstrap\n\ngo 1.26.0\n"))
	// Writable extraction lets t.TempDir clean up this private cache.
	download := exec.CommandContext(ctx, "go", "mod", "download", "-modcacherw", "-json", legacy+"@"+version)
	download.Dir = bootstrap
	output, err := download.CombinedOutput()
	if err != nil {
		t.Fatalf("seed private module cache: %v\n%s", err, output)
	}
	var hashes struct {
		Sum      string
		GoModSum string
	}
	if err := json.Unmarshal(output, &hashes); err != nil || hashes.Sum == "" || hashes.GoModSum == "" {
		t.Fatalf("invalid module hashes: %v\n%s", err, output)
	}
	mod := "module " + authcrunchModule + "\n\ngo 1.26.0\n\nrequire " + legacy + " " + version + "\n"
	sum := fmt.Sprintf("%s %s %s\n%s %s/go.mod %s\n", legacy, version, hashes.Sum, legacy, version, hashes.GoModSum)
	writeModuleFixture(t, filepath.Join(root, "go.mod"), []byte(mod))
	writeModuleFixture(t, filepath.Join(root, "go.sum"), []byte(sum))
	writeModuleFixture(t, filepath.Join(root, "api.go"), []byte("package authcrunch\n\nimport \""+legacy+"\"\n\nfunc Value() string { return legacy.Value() }\n"))
	writeModuleFixture(t, filepath.Join(root, "internal/secret/secret.go"), []byte("package secret\n\nconst Value = 1\n"))
	source := filepath.Join(base, "consumer_test.go")
	consumer := `package consumer_test
import (
    "testing"
    core "github.com/greenpau/go-authcrunch"
    "example.test/legacy"
)
func TestPublicAPI(t *testing.T) {
    if core.Value() != "public API" || core.Value() != legacy.Value() {
        t.Fatal("unexpected public API result")
    }
}
`
	writeModuleFixture(t, source, []byte(consumer))
	t.Setenv("GOPROXY", "off")
	// Demonstrate the former setup's failure before running the corrected helper.
	original := filepath.Join(base, "original")
	writeModuleFixture(t, filepath.Join(original, "go.mod"), fmt.Appendf(nil, "module example.test/consumer\n\ngo 1.26.0\n\nrequire %s v0.0.0\n\nreplace %s => %q\n", authcrunchModule, authcrunchModule, filepath.ToSlash(root)))
	writeModuleFixture(t, filepath.Join(original, "go.sum"), []byte(sum))
	writeModuleFixture(t, filepath.Join(original, "consumer_test.go"), []byte(consumer))
	old := exec.CommandContext(ctx, "go", "list", "-mod=mod", "-deps", "-test", ".")
	old.Dir = original
	output, err = old.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("example.test/unavailable")) || !bytes.Contains(output, []byte("GOPROXY=off")) {
		t.Fatalf("minimal module did not reproduce the missing-metadata failure: %v\n%s", err, output)
	}
	// The helper must ignore an ambient workspace, without mutating its parent.
	t.Setenv("GOWORK", filepath.Join(base, "nonexistent.go.work"))
	for _, tc := range []struct {
		name   string
		source string
		want   string
		fail   bool
	}{
		{"public API", consumer, "--- PASS: TestPublicAPI", false},
		{"test failure", strings.ReplaceAll(consumer, `"public API"`, `"wrong result"`), "unexpected public API result", true},
		{"internal boundary", "package consumer_test\n\nimport _ \"" + authcrunchModule + "/internal/secret\"\n", "use of internal package", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeModuleFixture(t, source, []byte(tc.source))
			output, err := runExternalModule(ctx, root, t.TempDir(), "example.test/consumer", source)
			if (err != nil) != tc.fail || !bytes.Contains(output, []byte(tc.want)) {
				t.Fatalf("unexpected consumer result: %v\n%s", err, output)
			}
		})
	}
	for name, want := range map[string]string{"go.mod": mod, "go.sum": sum} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(data) != want {
			t.Fatalf("checkout %s changed: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cache, "cache/download/example.test/unavailable")); !os.IsNotExist(err) {
		t.Fatalf("unavailable module unexpectedly accessed: %v", err)
	}
}

func writeModuleFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

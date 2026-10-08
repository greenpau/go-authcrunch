//go:build unix

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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the actual Make entry points in an isolated checkout. A dependency
// cache is a read-only input; every generated file stays inside this repository.
func TestE2EMakeOpenAPI(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "tmp"), 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(filepath.Join(repository, "tmp"), "_openapi-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, pattern := range []string{"*.go", "go.mod", "go.sum", "VERSION", "Makefile", ".github/workflows/test.yml", "internal/openapi/*", "cmd/openapi/*", "cmd/authdb/main.go", "cmd/authdbctl/main.go", "pkg", "assets/scripts/version.py", "assets/openapi/*", "assets/openapi/content"} {
		matches, err := filepath.Glob(filepath.Join(repository, pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			if strings.Contains(match, "assets/openapi/generated") {
				continue
			}
			if err := filepath.WalkDir(match, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				name, _ := filepath.Rel(repository, path)
				destination := filepath.Join(dir, name)
				if entry.IsDir() {
					return os.MkdirAll(destination, 0755)
				}
				if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
					return err
				}
				if strings.HasPrefix(name, "pkg/") && (!strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go")) {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				return os.WriteFile(destination, data, 0644)
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	// Extensible claims can contain JSON fields named like schema keywords.
	// Exercise preservation through the public Make target and HTTP server.
	claims := filepath.Join(dir, "assets/openapi/content/components/schemas/Claims.yaml")
	claimSource, err := os.ReadFile(claims)
	if err != nil {
		t.Fatal(err)
	}
	claimSource = append(claimSource, []byte("  metadata: {$ref: 'https://example.test/data', $id: literal}\n")...)
	if err := os.WriteFile(claims, claimSource, 0644); err != nil {
		t.Fatal(err)
	}

	// Paths, Responses and Components permit arbitrary extension payloads.
	for _, extension := range []struct{ file, before, after string }{
		{"openapi.yaml", "paths:\n", "paths:\n  x-review: {$ref: 'https://example.test/path-data'}\n"},
		{"openapi.yaml", "components:\n", "components:\n  x-review:\n    record: {$ref: 'https://example.test/component-data'}\n"},
		{"paths/root.yaml", "  responses:\n", "  responses:\n    x-review: {$ref: 'https://example.test/response-data'}\n"},
	} {
		file := filepath.Join(dir, "assets/openapi/content", extension.file)
		before, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(before, []byte(extension.before)) {
			t.Fatalf("extension fixture marker missing in %s", extension.file)
		}
		after := bytes.Replace(before, []byte(extension.before), []byte(extension.after), 1)
		if err := os.WriteFile(file, after, 0644); err != nil {
			t.Fatal(err)
		}
	}
	runMake := func(wantSuccess bool, target string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "make", target)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		if (err == nil) != wantSuccess {
			t.Fatalf("make %s: %v\n%s", target, err, output)
		}
		return output
	}
	runMake(false, "openapi-check")
	runMake(true, "openapi")
	runMake(true, "openapi-check")
	destination := filepath.Join(dir, "assets/openapi/generated/openapi.json")
	original, _ := os.ReadFile(destination)
	var doc map[string]any
	if json.Unmarshal(original, &doc) != nil || doc["openapi"] != "3.1.1" {
		t.Fatal("make did not publish OpenAPI")
	}
	if !bytes.Contains(original, []byte(`"$ref": "https://example.test/data"`)) {
		t.Fatal("generation changed literal claim example data")
	}
	for _, marker := range []string{"path-data", "response-data", "component-data"} {
		if !bytes.Contains(original, []byte(`"$ref": "https://example.test/`+marker+`"`)) {
			t.Fatalf("generation changed literal extension %s", marker)
		}
	}
	artifactTarget, artifactPath := artifactWorkflow(t, dir)
	artifactDirectory := filepath.Join(dir, artifactPath)
	runMake(true, artifactTarget)
	artifactBefore := checkArtifact(t, artifactDirectory, original)
	checkArtifactPreserved := func() {
		t.Helper()
		for file, expected := range artifactBefore {
			actual, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatalf("failed export changed %s: %v", file, err)
			}
		}
	}
	// Human navigation labels must remain unambiguous in every public export.
	// A rejected label edit must retain the last valid reference and artifact.
	loginSource := filepath.Join(dir, "assets/openapi/content/paths/login.yaml")
	loginBefore, err := os.ReadFile(loginSource)
	if err != nil {
		t.Fatal(err)
	}
	label := []byte("  summary: Authenticate with a challenge or API key\n")
	if !bytes.Contains(loginBefore, label) {
		t.Fatal("login summary fixture is missing")
	}
	duplicate := bytes.Replace(loginBefore, label, []byte("  summary: Open the login page\n"), 1)
	if err := os.WriteFile(loginSource, duplicate, 0644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"openapi", "openapi-check", "serve-openapi", artifactTarget} {
		if output := runMake(false, target); !bytes.Contains(output, []byte("duplicate operation summary")) {
			t.Fatalf("%s accepted ambiguous operation labels: %s", target, output)
		}
	}
	if actual, err := os.ReadFile(destination); err != nil || !bytes.Equal(actual, original) {
		t.Fatal("duplicate label replaced the reference")
	}
	checkArtifactPreserved()
	if err := os.WriteFile(loginSource, loginBefore, 0644); err != nil {
		t.Fatal(err)
	}
	// Every entry point rejects stale versions without rewriting YAML or JSON.
	versionFile := filepath.Join(dir, "VERSION")
	versionBefore, _ := os.ReadFile(versionFile)
	source := filepath.Join(dir, "assets/openapi/content/openapi.yaml")
	valid, _ := os.ReadFile(source)
	if err := os.WriteFile(versionFile, []byte("1.999.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"openapi", "openapi-check", "serve-openapi", artifactTarget} {
		if output := runMake(false, target); !bytes.Contains(output, []byte("make version-sync")) {
			t.Fatalf("%s did not report version drift: %s", target, output)
		}
	}
	for file, expected := range map[string][]byte{source: valid, destination: original} {
		actual, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("version drift changed %s: %v", file, err)
		}
	}
	checkArtifactPreserved()
	runMake(true, "version-sync")
	runMake(true, "openapi")
	runMake(true, "openapi-check")
	updated, _ := os.ReadFile(destination)
	if json.Unmarshal(updated, &doc) != nil || doc["info"].(map[string]any)["version"] != "1.999.0" {
		t.Fatal("generation did not follow version-sync")
	}
	runMake(true, artifactTarget)
	checkArtifact(t, artifactDirectory, updated)
	if err := os.WriteFile(versionFile, versionBefore, 0644); err != nil {
		t.Fatal(err)
	}
	runMake(true, "version-sync")
	runMake(true, "openapi")
	runMake(true, artifactTarget)
	checkArtifact(t, artifactDirectory, original)
	// Source drift must fail before touching an otherwise valid bundle.
	for _, relative := range []string{"pkg/authn/serve_http.go", "pkg/redirects/redirect_match.go", "pkg/util/addr/utils.go", "pkg/util/redirect.go", "pkg/util/sanitizer.go", "pkg/waf/malformed_input_check.go"} {
		trackedSource := filepath.Join(dir, relative)
		originalSource, err := os.ReadFile(trackedSource)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(trackedSource, append(bytes.Clone(originalSource), '\n'), 0644); err != nil {
			t.Fatal(err)
		}
		output := runMake(false, "openapi")
		if !bytes.Contains(output, []byte("source review required")) || !bytes.Contains(output, []byte(relative)) {
			t.Fatal("source review failure did not identify the changed contract input")
		}
		if actual, err := os.ReadFile(destination); err != nil || !bytes.Equal(actual, original) {
			t.Fatal("source drift replaced the valid bundle")
		}
		if output := runMake(false, artifactTarget); !bytes.Contains(output, []byte("source review required")) {
			t.Fatal("artifact bypassed source review")
		}
		checkArtifactPreserved()
		if err := os.WriteFile(trackedSource, originalSource, 0644); err != nil {
			t.Fatal(err)
		}
	}
	// A second source-review document must not be silently ignored.
	review := filepath.Join(dir, "assets/openapi/reviewed-sources.yaml")
	reviewBefore, _ := os.ReadFile(review)
	if err := os.WriteFile(review, append(bytes.Clone(reviewBefore), []byte("\n---\n{}\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	if output := runMake(false, "openapi"); !bytes.Contains(output, []byte("exactly one YAML document")) {
		t.Fatal("accepted an ambiguous source review record")
	}
	if actual, err := os.ReadFile(destination); err != nil || !bytes.Equal(actual, original) {
		t.Fatal("invalid review record changed the bundle")
	}
	if err := os.WriteFile(review, reviewBefore, 0644); err != nil {
		t.Fatal(err)
	}
	// A valid OpenAPI operation-level server can still break the shared mount.
	// Reject it through the public generation target before replacing the bundle.
	callback := filepath.Join(dir, "assets/openapi/content/paths/oauth2_authorization-code-callback.yaml")
	callbackBefore, _ := os.ReadFile(callback)
	if err := os.WriteFile(callback, append(bytes.Clone(callbackBefore), []byte("  servers:\n  - url: https://example.test/oauth2\n")...), 0644); err != nil {
		t.Fatal(err)
	}
	if output := runMake(false, "openapi"); !bytes.Contains(output, []byte("inherit the document server")) {
		t.Fatal("generation accepted a server that bypasses the shared mount")
	}
	if actual, err := os.ReadFile(destination); err != nil || !bytes.Equal(actual, original) {
		t.Fatal("server override changed the valid bundle")
	}
	if err := os.WriteFile(callback, callbackBefore, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runMake(false, "openapi-check")
	runMake(true, "openapi")
	// Invalid YAML must neither replace nor truncate the prior output.
	if err := os.WriteFile(source, []byte("openapi: [unterminated"), 0644); err != nil {
		t.Fatal(err)
	}
	runMake(false, "openapi")
	runMake(false, artifactTarget)
	checkArtifactPreserved()
	unchanged, _ := os.ReadFile(destination)
	if !bytes.Equal(unchanged, original) {
		t.Fatal("failed generation replaced valid JSON")
	}
	if err := os.WriteFile(source, valid, 0644); err != nil {
		t.Fatal(err)
	}
	// A real HTTP server, launched through make, serves the generated result.
	cmd := exec.CommandContext(ctx, "make", "serve-openapi", "OPENAPI_ADDR=127.0.0.1:0")
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	// The CLI prints one ready line only after successful generation and bind.
	ready := make(chan string, 1)
	go func() {
		var line strings.Builder
		one := make([]byte, 1)
		for {
			if _, err := stdout.Read(one); err != nil {
				ready <- ""
				return
			}
			if one[0] == '\n' {
				ready <- line.String()
				return
			}
			line.WriteByte(one[0])
		}
	}()
	select {
	case line := <-ready:
		start := strings.Index(line, "http://")
		if start < 0 {
			t.Fatalf("no server address in %q", line)
		}
		address := strings.Fields(line[start:])[0]
		client := &http.Client{Timeout: 5 * time.Second}
		// Reject aliases introduced after generation, including a parent
		// directory alias whose final file is regular and remains inside root.
		private := filepath.Join(dir, "assets/openapi/private")
		if err := os.Mkdir(private, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(private, "secret.yaml"), []byte("private"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../private", filepath.Join(dir, "assets/openapi/content/alias")); err != nil {
			t.Fatal(err)
		}
		resp, err := client.Get(address + "content/alias/secret.yaml")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatal("documentation server exposed a private alias")
		}
		for _, name := range []string{"", "scalar.js", "generated/openapi.json", "content/openapi.yaml"} {
			resp, err := client.Get(address + name)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || len(data) == 0 {
				t.Fatalf("served %s incorrectly", name)
			}
			if name == "generated/openapi.json" && !bytes.Equal(data, original) {
				t.Fatal("served a different bundle")
			}
		}
	case <-ctx.Done():
		t.Fatal("documentation server did not start")
	}
}

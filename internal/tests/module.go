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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const authcrunchModule = "github.com/greenpau/go-authcrunch"

// RunExternalModule runs portable consumer tests in a separate temporary module.
// Sources must use public APIs and end in _test.go. Only the in-module driver
// may import this helper. Dependencies retain the checkout's pinned versions;
// the child cannot download modules or inherit a workspace's replacements.
func RunExternalModule(t *testing.T, root, module string, sources ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	output, err := runExternalModule(ctx, root, t.TempDir(), module, sources...)
	if err != nil {
		t.Fatalf("external module journey failed: %v\n%s", err, output)
	}
	t.Logf("external module journey:\n%s", output)
}

func runExternalModule(ctx context.Context, root, dir, module string, sources ...string) ([]byte, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	// A minimal consumer go.mod can force Go to load the unpruned dependency
	// graph, including historical test-only modules absent from a fresh CI
	// cache. Seed all root requirements, not just go.sum (which is checksums,
	// not a dependency graph), and keep the child graph read-only during tests.
	files := append([]string{filepath.Join(root, "go.mod"), filepath.Join(root, "go.sum")}, sources...)
	for _, source := range files {
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("read external module fixture: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(source)), data, 0600); err != nil {
			return nil, fmt.Errorf("write external module fixture: %w", err)
		}
	}
	env := append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GONOPROXY=none", "GOSUMDB=off", "GOTOOLCHAIN=local")
	edit := exec.CommandContext(ctx, "go", "mod", "edit", "-module="+module,
		"-require="+authcrunchModule+"@v0.0.0", "-replace="+authcrunchModule+"="+root)
	edit.Dir, edit.Env = dir, env
	if output, err := edit.CombinedOutput(); err != nil {
		return output, fmt.Errorf("prepare external module: %w", err)
	}
	cmd := exec.CommandContext(ctx, "go", "test", "-mod=readonly", "-race", "-count=1", "-p=1", "-parallel=2", "-timeout=150s", "-v", ".")
	cmd.Dir, cmd.Env = dir, env
	return cmd.CombinedOutput()
}

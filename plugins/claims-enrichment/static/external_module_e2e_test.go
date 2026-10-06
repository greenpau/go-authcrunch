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

package static_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestE2EClaimsEnrichmentExternalModule(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	module := fmt.Sprintf("module example.test/enrichment-consumer\n\ngo 1.26.0\n\nrequire github.com/greenpau/go-authcrunch v0.0.0\n\nreplace github.com/greenpau/go-authcrunch => %q\n", filepath.ToSlash(root))
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(module), 0600); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{filepath.Join(root, "go.sum"), "go.sum"}, {"consumer_e2e_test.go", "consumer_test.go"}} {
		data, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pair[1]), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-mod=mod", "-race", "-count=1", "-p=1", "-parallel=2", "-timeout=150s", "-v", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("external module journey failed: %v\n%s", err, output)
	}
	t.Log("external module completed real TLS login, plugin enrichment and gatekeeper authorization")
}

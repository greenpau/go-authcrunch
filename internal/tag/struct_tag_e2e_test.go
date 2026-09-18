// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package tag

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2EStructTagCompliance(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}

	for _, tc := range []struct {
		name        string
		extraFiles  []string
		wantMissing string
	}{
		{name: "registered source structs"},
		{
			name: "ignore generated and non-package directories",
			extraFiles: []string{
				".coverage/codeql/fixture/claims.go",
				".git/fixture/claims.go",
				"_scratch/claims.go",
				"testdata/fixture/claims.go",
				"vendor/example.com/fixture/claims.go",
				"pkg/model/.coverage/claims.go",
				"pkg/model/_scratch/claims.go",
				"pkg/model/testdata/claims.go",
				"pkg/model/vendor/fixture/claims.go",
			},
		},
		{
			name:        "reject unregistered root struct",
			extraFiles:  []string{"claims.go"},
			wantMissing: "fixture.Claims",
		},
		{
			name:        "reject unregistered nested struct",
			extraFiles:  []string{"pkg/unregistered/claims.go"},
			wantMissing: "fixture.Claims",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				"go.mod":             "module example.com/fixture\n\ngo 1.26.0\n",
				"config.go":          "package fixture\n\ntype Config struct{}\n",
				"pkg/model/model.go": "package model\n\ntype Record struct{}\n",
				"internal/tag/tag_test.go": `package tag

import (
	"example.com/fixture"
	"example.com/fixture/pkg/model"
)

var entries = []any{&fixture.Config{}, &model.Record{}}
`,
			}
			for _, path := range tc.extraFiles {
				files[path] = "package fixture\n\ntype Claims struct{ ID string }\n"
			}
			for path, content := range files {
				path = filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatalf("create fixture directory: %v", err)
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestStructTagCompliance$", "-test.v")
			cmd.Dir = filepath.Join(root, "internal", "tag")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("struct compliance check timed out: %v\n%s", ctx.Err(), output)
			}
			if tc.wantMissing == "" {
				if err != nil {
					t.Fatalf("struct compliance check failed: %v\n%s", err, output)
				}
				if !strings.Contains(string(output), "--- PASS: TestStructTagCompliance") {
					t.Fatalf("struct compliance check did not run: %s", output)
				}
				return
			}
			if err == nil || !strings.Contains(string(output), "Found struct "+tc.wantMissing) {
				t.Fatalf("expected missing registration for %s, got %v\n%s", tc.wantMissing, err, output)
			}
		})
	}
}

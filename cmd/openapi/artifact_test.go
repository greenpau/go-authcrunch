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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/internal/openapi"
)

func TestOpenAPIArtifactWorkflow(t *testing.T) {
	artifactWorkflow(t, filepath.Join("..", ".."))
}

// Read the workflow's actual build command and upload directory so the executable
// fixture verifies the files Actions will publish, not a parallel packaging path.
func artifactWorkflow(t *testing.T, repository string) (string, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repository, ".github/workflows/test.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	quality := workflow["jobs"].(map[string]any)["quality"].(map[string]any)
	if quality["needs"] != "selection" || quality["if"] != "${{ needs.selection.outputs.run_tests == 'true' }}" {
		t.Fatal("artifact must follow ordinary validation selection")
	}
	var target, directory string
	qualityIndex, buildIndex, uploadIndex := -1, -1, -1
	for i, value := range quality["steps"].([]any) {
		step := value.(map[string]any)
		if step["id"] == "tests" {
			qualityIndex = i
		}
		if step["id"] == "openapi" {
			buildIndex = i
			command := strings.Fields(step["run"].(string))
			if len(command) != 2 || command[0] != "make" || step["if"] != nil || step["continue-on-error"] != nil {
				t.Fatal("artifact generation must use Make and propagate failures")
			}
			target = command[1]
		}
		with, _ := step["with"].(map[string]any)
		name, _ := with["name"].(string)
		if !strings.HasPrefix(name, "go-authcrunch_openapi_") {
			continue
		}
		if uploadIndex != -1 || name != "go-authcrunch_openapi_${{ needs.selection.outputs.artifact_id }}" {
			t.Fatal("expected one separate OpenAPI artifact with the shared identity")
		}
		uploadIndex = i
		uses, _ := step["uses"].(string)
		pin, found := strings.CutPrefix(uses, "actions/upload-artifact@")
		if !found || len(pin) != 40 || step["if"] != nil || step["continue-on-error"] != nil {
			t.Fatal("upload must be pinned and require successful preceding steps")
		}
		if with["if-no-files-found"] != "error" || with["overwrite"] != true || with["retention-days"] != 14 {
			t.Fatal("artifact must fail when absent and support retained reruns")
		}
		directory, _ = with["path"].(string)
		if !filepath.IsLocal(directory) || !strings.HasPrefix(directory, "assets/openapi/generated/") {
			t.Fatal("artifact output must stay in the ignored generated directory")
		}
	}
	if qualityIndex < 0 || buildIndex <= qualityIndex || uploadIndex <= buildIndex {
		t.Fatal("artifact must be generated and uploaded after quality checks pass")
	}
	return target, directory
}

func checkArtifact(t *testing.T, directory string, expected []byte) map[string][]byte {
	t.Helper()
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 2 {
		t.Fatalf("artifact must contain exactly two specifications: %v", err)
	}
	contents := map[string][]byte{}
	for _, name := range []string{"openapi.json", "openapi.yaml"} {
		file := filepath.Join(directory, name)
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		contents[file] = data
	}
	if !bytes.Equal(contents[filepath.Join(directory, "openapi.json")], expected) {
		t.Fatal("artifact JSON does not match the current validated reference")
	}
	var yamlDoc map[string]any
	if err := yaml.Unmarshal(contents[filepath.Join(directory, "openapi.yaml")], &yamlDoc); err != nil {
		t.Fatal(err)
	}
	// Compile the exported YAML independently, with external loading disabled.
	if err := openapi.Validate(yamlDoc); err != nil {
		t.Fatal(err)
	}
	if err := openapi.ValidateStandard(yamlDoc); err != nil {
		t.Fatal(err)
	}
	converted, err := json.Marshal(yamlDoc)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(converted, &got); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("artifact YAML differs from JSON (-want +got):\n%s", diff)
	}
	return contents
}

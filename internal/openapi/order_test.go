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

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestBundlePreservesWorkflowOrder(t *testing.T) {
	for _, mode := range []string{"inline", "file", "reference-chain-with-siblings"} {
		t.Run(mode, func(t *testing.T) {
			directory := fixture(t)
			root := strings.Replace(fixtureRoot, "/nodes/{id}", "/z-nodes/{id}", 1)
			second := strings.Replace(fixturePath, "getNode", "getNext", 1)
			second = strings.Replace(second, "summary: Get node", "summary: Get next node", 1)
			root = strings.Replace(root, "components:\n", "  /a-nodes/{id}:\n"+indentYAML(second, "    ")+"components:\n", 1)
			post := strings.Replace(strings.Replace(fixturePath, "get:\n", "post:\n", 1), "getNode", "postNode", 1)
			post = strings.Replace(post, "summary: Get node", "summary: Submit node", 1)
			switch mode {
			case "inline":
				// Inline operations resolve their schema relative to the document root.
				inline := strings.ReplaceAll(post+fixturePath, "../schemas/", "schemas/")
				root = strings.Replace(root, "    $ref: paths/node.yaml\n", indentYAML(inline, "    "), 1)
				if err := os.Remove(filepath.Join(directory, "paths/node.yaml")); err != nil {
					t.Fatal(err)
				}
			case "file":
				put(t, directory, "paths/node.yaml", post+fixturePath)
			default:
				put(t, directory, "paths/node.yaml", post+"$ref: methods.yaml#/a~1b/~0/0\nx-note: {$ref: 'https://example.test/literal'}\n")
				put(t, directory, "paths/methods.yaml", "a/b:\n  '~':\n    - $ref: final.yaml\n")
				put(t, directory, "paths/final.yaml", fixturePath)
			}
			// The second path is always inline, so adjust only that relative reference.
			root = strings.ReplaceAll(root, "../schemas/", "schemas/")
			put(t, directory, "openapi.yaml", root)
			data, err := Bundle(directory)
			if err != nil {
				t.Fatal(err)
			}
			var document yaml.Node
			if err := yaml.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			paths := yamlField(document.Content[0], "paths")
			if diff := cmp.Diff([]string{"/z-nodes/{id}", "/a-nodes/{id}"}, yamlKeys(paths)); diff != "" {
				t.Fatal(diff)
			}
			first := yamlField(paths, "/z-nodes/{id}")
			keys := yamlKeys(first)
			if len(keys) < 2 || keys[0] != "post" || keys[1] != "get" {
				t.Fatalf("operation order changed: %v", keys)
			}
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if err := Validate(doc); err != nil {
				t.Fatal(err)
			}
			if mode == "reference-chain-with-siblings" && !bytes.Contains(data, []byte(`"$ref": "https://example.test/literal"`)) {
				t.Fatal("literal extension was changed")
			}
			again, err := Bundle(directory)
			if err != nil || !bytes.Equal(data, again) {
				t.Fatalf("order is nondeterministic: %v", err)
			}
			output := t.TempDir()
			if err := WriteArtifact(output, data); err != nil {
				t.Fatal(err)
			}
			exported, err := os.ReadFile(filepath.Join(output, "openapi.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var artifact yaml.Node
			if err := yaml.Unmarshal(exported, &artifact); err != nil {
				t.Fatal(err)
			}
			exportedPaths := yamlField(artifact.Content[0], "paths")
			if diff := cmp.Diff(yamlKeys(paths), yamlKeys(exportedPaths)); diff != "" {
				t.Fatal(diff)
			}
			if diff := cmp.Diff(keys, yamlKeys(yamlField(exportedPaths, "/z-nodes/{id}"))); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func indentYAML(value, prefix string) string {
	return prefix + strings.ReplaceAll(strings.TrimSuffix(value, "\n"), "\n", "\n"+prefix) + "\n"
}

func yamlField(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return &yaml.Node{}
}

func yamlKeys(node *yaml.Node) []string {
	var keys []string
	for i := 0; i < len(node.Content); i += 2 {
		keys = append(keys, node.Content[i].Value)
	}
	return keys
}

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
	"strings"
	"testing"
)

func TestOperationSummaries(t *testing.T) {
	for _, tc := range []struct {
		name, summary, want string
	}{
		{"distinct purpose", "Submit a node", ""},
		{"method qualifier", "Get node (POST)", ""},
		{"exact duplicate", "Get node", "duplicate operation summary"},
		{"case duplicate", "GET NODE", "duplicate operation summary"},
		{"whitespace duplicate", "  Get   node  ", "duplicate operation summary"},
		{"unicode whitespace duplicate", "Get\u00a0node", "duplicate operation summary"},
		{"empty", "", "nonempty summary"},
		{"blank", " \t\u00a0", "nonempty summary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := fixture(t)
			post := strings.NewReplacer("get:\n", "post:\n", "operationId: getNode", "operationId: postNode", "summary: Get node", "summary: '"+tc.summary+"'").Replace(fixturePath)
			put(t, directory, "paths/node.yaml", fixturePath+post)
			_, err := Bundle(directory)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
	for _, differentTag := range []bool{false, true} {
		t.Run(map[bool]string{false: "duplicate across paths", true: "duplicate across categories"}[differentTag], func(t *testing.T) {
			directory := fixture(t)
			root := strings.Replace(fixtureRoot, "components:\n", "  /other/{id}:\n    $ref: paths/other.yaml\ncomponents:\n", 1)
			other := strings.Replace(fixturePath, "operationId: getNode", "operationId: getOther", 1)
			if differentTag {
				root = strings.Replace(root, "description: Test operations}]", "description: Test operations}, {name: Other, description: Other operations}]", 1)
				other = strings.Replace(other, "tags: [Test]", "tags: [Other]", 1)
			}
			put(t, directory, "openapi.yaml", root)
			put(t, directory, "paths/other.yaml", other)
			_, err := Bundle(directory)
			if err == nil || !strings.Contains(err.Error(), "duplicate operation summary") {
				t.Fatalf("duplicate label accepted: %v", err)
			}
			for _, id := range []string{"getNode", "getOther"} {
				if !strings.Contains(err.Error(), id) {
					t.Fatalf("error must identify both operations: %v", err)
				}
			}
		})
	}
}

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
)

const fixtureRoot = `openapi: 3.1.1
info: {title: Fixture, version: "1", description: Fixture API}
tags: [{name: Test, description: Test operations}]
paths:
  /nodes/{id}:
    $ref: paths/node.yaml
components:
  schemas:
    Node:
      $ref: schemas/node.yaml
`

const fixturePath = `get:
  operationId: getNode
  summary: Get node
  description: Read a recursive node.
  tags: [Test]
  security: []
  parameters:
    - {name: id, in: path, required: true, schema: {type: string}}
  responses:
    '200':
      description: The node.
      content:
        application/json:
          schema:
            $ref: ../schemas/node.yaml
`

const fixtureSchema = `type: object
properties:
  name: {type: string}
  children:
    type: array
    items:
      $ref: node.yaml
`

func put(t *testing.T, root, name, content string) {
	t.Helper()
	file := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	put(t, dir, "openapi.yaml", fixtureRoot)
	put(t, dir, "paths/node.yaml", fixturePath)
	put(t, dir, "schemas/node.yaml", fixtureSchema)
	return dir
}

func TestBundleRecursiveComponents(t *testing.T) {
	directory := fixture(t)
	first, err := Bundle(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Bundle(directory)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("generation was not deterministic: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatal(err)
	}
	for _, pointerPath := range []string{
		"/paths/~1nodes~1{id}/get/responses/200/content/application~1json/schema/$ref",
		"/components/schemas/Node/properties/children/items/$ref",
	} {
		ref, err := pointer(doc, pointerPath)
		if err != nil || ref != "#/components/schemas/Node" {
			t.Fatalf("reference was not made local: %v, %v", ref, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(directory, "schemas/node.yaml"))
	if err != nil || string(data) != fixtureSchema {
		t.Fatal("generation modified authored YAML")
	}
}

func TestBundleRejectsInvalidSources(t *testing.T) {
	for _, tc := range []struct{ name, file, content, want string }{
		{"duplicate", "schemas/node.yaml", "type: object\ntype: string\n", "duplicate"},
		{"numeric-status", "paths/node.yaml", strings.Replace(fixturePath, "'200'", "200", 1), "non-string"},
		{"multi-document", "schemas/node.yaml", "type: object\n---\ntype: string\n", "exactly one"},
		{"alias", "schemas/node.yaml", "type: object\nproperties: &fields {}\n", "anchors"},
		{"remote", "schemas/node.yaml", "$ref: https://example.com/schema.yaml\n", "local YAML"},
		{"missing", "schemas/node.yaml", "$ref: missing.yaml\n", "reference"},
		{"pointer", "schemas/node.yaml", "$ref: ../openapi.yaml#/missing\n", "unresolved"},
		{"resource-id", "schemas/node.yaml", "$id: https://example.com/\ntype: object\n", "unsupported"},
		{"unknown-tag", "paths/node.yaml", strings.Replace(fixturePath, "tags: [Test]", "tags: [Missing]", 1), "undeclared tag"},
		{"path-param", "paths/node.yaml", strings.Replace(fixturePath, "required: true", "required: false", 1), "path parameter"},
		{"auth-boundary", "paths/node.yaml", strings.Replace(fixturePath, "  security: []\n", "", 1), "credential boundary"},
		{"path-server-override", "paths/node.yaml", "servers: [{url: 'https://example.test/oauth2'}]\n" + fixturePath, "inherit the document server"},
		{"operation-server-override", "paths/node.yaml", strings.Replace(fixturePath, "get:\n", "get:\n  servers: [{url: 'https://example.test/oauth2'}]\n", 1), "inherit the document server"},
		{"orphan", "schemas/forgotten.yaml", "type: object\n", "unreferenced"},
		{"cycle", "paths/node.yaml", "$ref: node.yaml\n", "cyclic"},
		{"ref-type", "schemas/node.yaml", "$ref: 1\n", "invalid $ref"},
		{"operation-id", "paths/node.yaml", strings.Replace(fixturePath, "  operationId: getNode\n", "", 1), "operationId"},
		{"oas-structure", "paths/node.yaml", strings.Replace(fixturePath, "  operationId: getNode", "  invalidKeyword: true\n  operationId: getNode", 1), "OpenAPI structure"},
		{"payload-type", "schemas/node.yaml", "type: imaginary\n", "schema"},
		{"payload-minimum", "schemas/node.yaml", "type: integer\nminimum: wrong\n", "schema"},
		{"example", "paths/node.yaml", strings.Replace(fixturePath, "          schema:", "          example: {children: false}\n          schema:", 1), "example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := fixture(t)
			put(t, directory, tc.file, tc.content)
			_, err := Bundle(directory)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestSchemaPropertyNamesAreNotOpenAPIKeywords(t *testing.T) {
	directory := fixture(t)
	put(t, directory, "schemas/node.yaml", "type: object\nproperties:\n  schema: {type: string}\n  examples: {type: string}\n")
	if _, err := Bundle(directory); err != nil {
		t.Fatal(err)
	}
}

func TestBundlePreservesLiteralReferenceData(t *testing.T) {
	const literal = `{"$ref":"https://example.test/data", "$id":"literal", "schema":{"type":"not-a-schema"}}`
	for _, tc := range []struct{ name, schema, path string }{
		{"media-example", "type: object\n", strings.Replace(fixturePath, "          schema:", "          example: "+literal+"\n          schema:", 1)},
		{"named-example", "type: object\n", strings.Replace(fixturePath, "          schema:", "          examples:\n            sample:\n              value: "+literal+"\n          schema:", 1)},
		{"schema-annotations", "type: object\nexample: " + literal + "\nexamples: [" + literal + "]\ndefault: " + literal + "\nconst: " + literal + "\nenum: [" + literal + "]\n", fixturePath},
		{"extension", "type: object\nx-data: " + literal + "\n", fixturePath},
		{"property-names", "type: object\nproperties:\n  $ref: {type: string}\n  $id: {type: string}\n  x-record: {$ref: '#/properties/child'}\n  child: {type: integer}\n", fixturePath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := fixture(t)
			put(t, directory, "schemas/node.yaml", tc.schema)
			put(t, directory, "paths/node.yaml", tc.path)
			data, err := Bundle(directory)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "property-names" {
				var doc map[string]any
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				child, err := pointer(doc, "/components/schemas/Node/properties/x-record/type")
				if err != nil || child != "integer" {
					t.Fatal("schema beneath an extension-like property name was not resolved")
				}
			} else if !bytes.Contains(data, []byte(`"$ref": "https://example.test/data"`)) {
				t.Fatal("literal reference data was changed")
			}
		})
	}
}

func TestBundleRejectsEscapingReferences(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{true: "symlink", false: "parent"}[symlink], func(t *testing.T) {
			parent := t.TempDir()
			put(t, parent, "outside.yaml", "type: string\n")
			directory := filepath.Join(parent, "content")
			put(t, directory, "openapi.yaml", fixtureRoot)
			put(t, directory, "paths/node.yaml", fixturePath)
			if symlink {
				if err := os.MkdirAll(filepath.Join(directory, "schemas"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(parent, "outside.yaml"), filepath.Join(directory, "schemas/node.yaml")); err != nil {
					t.Fatal(err)
				}
			} else {
				put(t, directory, "schemas/node.yaml", "$ref: ../../outside.yaml\n")
			}
			if _, err := Bundle(directory); err == nil || !strings.Contains(err.Error(), "escapes") {
				t.Fatalf("reference escaped content: %v", err)
			}
		})
	}
}

func TestJSONPointer(t *testing.T) {
	doc := map[string]any{"a/b": map[string]any{"~": []any{"value"}}}
	actual, err := pointer(doc, "/a~1b/~0/0")
	if err != nil || actual != "value" {
		t.Fatal(actual, err)
	}
	for _, fragment := range []string{"anchor", "/a~1b/~0/01", "/a~1b/~0/-1", "/a~2b", "/missing"} {
		if _, err := pointer(doc, fragment); err == nil {
			t.Errorf("accepted invalid pointer %s", fragment)
		}
	}
}

func TestWritePreservesCurrentAndUnrelatedFiles(t *testing.T) {
	directory := t.TempDir()
	data := []byte("{\"openapi\":\"3.1.1\"}\n")
	put(t, directory, "notes.txt", "keep")
	if err := Write(directory, data); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "openapi.json")
	before, _ := os.Stat(file)
	if err := Write(directory, data); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(file)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged bundle was rewritten")
	}
	if err := Write(directory, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 2 {
		t.Fatal("temporary output was retained or unrelated file removed")
	}
}

func TestWriteRejectsSymlinkDestinations(t *testing.T) {
	for _, directoryLink := range []bool{false, true} {
		t.Run(map[bool]string{true: "directory", false: "file"}[directoryLink], func(t *testing.T) {
			root := t.TempDir()
			put(t, root, "private/openapi.json", "keep")
			generated := filepath.Join(root, "generated")
			if directoryLink {
				if err := os.Symlink(filepath.Join(root, "private"), generated); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(generated, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "private/openapi.json"), filepath.Join(generated, "openapi.json")); err != nil {
					t.Fatal(err)
				}
			}
			if err := Write(generated, []byte("{}")); err == nil {
				t.Fatal("generation followed a symlink")
			}
			data, err := os.ReadFile(filepath.Join(root, "private/openapi.json"))
			if err != nil || string(data) != "keep" {
				t.Fatal("generation modified a symlink destination")
			}
		})
	}

}

func TestSourceReviewDetectsAllChanges(t *testing.T) {
	before := &ReviewedSources{Module: "v1", Files: map[string]string{"changed.go": "old", "removed.go": "old"}}
	after := &ReviewedSources{Module: "v2", Files: map[string]string{"changed.go": "new", "added.go": "new"}}
	err := compareSources(before, after)
	for _, want := range []string{"v1 -> v2", "changed.go", "removed.go (removed)", "added.go"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("source drift omitted %s: %v", want, err)
		}
	}
	if err := compareSources(before, before); err != nil {
		t.Fatal(err)
	}
}

func TestSourceReviewRejectsAmbiguousRecords(t *testing.T) {
	valid := "module: v1.0.0\nfiles:\n  handler.go: abc123\n"
	if _, err := readReviewedSources([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{valid + "---\n" + valid, valid + "---\n", valid + "---\n[", valid + "extra: ignored\n", valid + "module: v2\n", ""} {
		if _, err := readReviewedSources([]byte(input)); err == nil {
			t.Errorf("accepted ambiguous review record %q", input)
		}
	}
}

func TestRepositoryContract(t *testing.T) {
	repository := filepath.Join("..", "..")
	if err := CheckSources(t.Context(), repository); err != nil {
		t.Fatal(err)
	}
	data, err := Bundle(filepath.Join(repository, "assets/openapi/content"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion(repository, data); err != nil {
		t.Fatal(err)
	}
	checkOrigin := func(servers any) {
		t.Helper()
		for _, server := range array(servers) {
			origin := object(object(object(server)["variables"])["origin"])["default"]
			if origin != "https://auth.myfiosgateway.com:8443" {
				t.Errorf("unexpected default origin: %v", origin)
			}
		}
	}
	checkOrigin(doc["servers"])
	servers := array(doc["servers"])
	if len(servers) != 1 || object(servers[0])["url"] != "{origin}{portalBasePath}" {
		t.Fatal("every operation must share the origin and portal mount")
	}
	variables := object(object(servers[0])["variables"])
	if object(variables["portalBasePath"])["default"] != "/auth" || len(variables) != 2 {
		t.Fatal("unexpected reference mount variables")
	}
	// Resolve the entire document at default, nested and root mounts. The OAuth
	// regression asserts its suffixes explicitly so losing /oauth2 cannot pass.
	for _, mount := range []string{"/auth", "/team/auth", ""} {
		base := strings.NewReplacer("{origin}", "https://login.example.test:8443", "{portalBasePath}", mount).Replace(object(servers[0])["url"].(string))
		for path, item := range object(doc["paths"]) {
			if strings.HasPrefix(path, "/auth/") || strings.Contains(base+path, "8443//") {
				t.Errorf("duplicated mount in URL %s", base+path)
			}
			for method, value := range object(item) {
				if !methods[method] {
					continue
				}
				switch object(value)["operationId"] {
				case "directOAuthCallback":
					if base+path != "https://login.example.test:8443"+mount+"/oauth2/authorization-code-callback" {
						t.Errorf("wrong direct OAuth callback URL: %s", base+path)
					}
				case "directOAuthLogout":
					if base+path != "https://login.example.test:8443"+mount+"/oauth2/logout" {
						t.Errorf("wrong direct OAuth logout URL: %s", base+path)
					}
				}
			}
		}
	}
	if object(doc["paths"])["/authorization-code-callback"] != nil || object(object(doc["paths"])["/logout"])["post"] != nil {
		t.Fatal("direct OAuth routes must not overlap the portal logout or omit /oauth2")
	}
	sources, err := Sources(t.Context(), repository)
	if err != nil {
		t.Fatal(err)
	}
	for path, item := range object(doc["paths"]) {
		for method, op := range object(item) {
			if !methods[method] {
				continue
			}
			checkOrigin(object(op)["servers"])
			provenance := array(object(op)["x-source-files"])
			if len(provenance) == 0 {
				t.Errorf("%s %s lacks source evidence", method, path)
			}
			for _, source := range provenance {
				name, _ := source.(string)
				if sources.Files[name] == "" {
					t.Errorf("%s %s has unreviewed source %s", method, path, name)
				}
			}
		}
	}
	// Ensure form and JSON protocols remain separately documented at login.
	content, err := pointer(doc, "/paths/~1login/post/requestBody/content")
	if err != nil {
		t.Fatal(err)
	}
	var media []string
	for _, name := range []string{"application/json", "application/x-www-form-urlencoded"} {
		if object(content)[name] != nil {
			media = append(media, name)
		}
	}
	if diff := cmp.Diff([]string{"application/json", "application/x-www-form-urlencoded"}, media); diff != "" {
		t.Fatal(diff)
	}
}

func TestBundlePreservesObjectExtensions(t *testing.T) {
	const literal = `{"$ref":"https://example.test/data", "$id":"literal", "schema":{"type":"not-a-schema"}}`
	for _, tc := range []struct {
		name, root, path, pointer, want, wantError string
	}{
		{
			name: "paths",
			root: strings.Replace(fixtureRoot, "paths:\n", "paths:\n  x-data: "+literal+"\n", 1),
			path: fixturePath, pointer: "/paths/x-data/$ref", want: "https://example.test/data",
		},
		{
			name: "responses", root: fixtureRoot,
			path:    strings.Replace(fixturePath, "  responses:\n", "  responses:\n    x-data: "+literal+"\n", 1),
			pointer: "/paths/~1nodes~1{id}/get/responses/x-data/$ref", want: "https://example.test/data",
		},
		{
			name: "components",
			root: strings.Replace(fixtureRoot, "components:\n", "components:\n  x-data:\n    record: "+literal+"\n", 1),
			path: fixturePath, pointer: "/components/x-data/record/$ref", want: "https://example.test/data",
		},
		{
			name: "extension-like-component-name",
			root: strings.Replace(fixtureRoot, "    Node:\n", "    x-Node:\n", 1),
			path: fixturePath, pointer: "/paths/~1nodes~1{id}/get/responses/200/content/application~1json/schema/$ref", want: "#/components/schemas/x-Node",
		},
		{
			name: "only-path-extensions",
			root: strings.Replace(fixtureRoot, "  /nodes/{id}:\n    $ref: paths/node.yaml\n", "  x-data: "+literal+"\n", 1),
			path: fixturePath, wantError: "paths must not be empty",
		},
		{
			name: "only-response-extensions", root: fixtureRoot,
			path:      strings.Split(fixturePath, "  responses:\n")[0] + "  responses:\n    x-data: " + literal + "\n",
			wantError: "has no responses",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := fixture(t)
			put(t, directory, "openapi.yaml", tc.root)
			put(t, directory, "paths/node.yaml", tc.path)
			data, err := Bundle(directory)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("expected %q error, got %v", tc.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			value, err := pointer(doc, tc.pointer)
			if err != nil || value != tc.want {
				t.Fatalf("unexpected value at %s: %v (%v)", tc.pointer, value, err)
			}
		})
	}
}

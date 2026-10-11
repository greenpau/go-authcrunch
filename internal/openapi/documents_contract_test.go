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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strings"
	"testing"
)

func TestRepositoryDocumentsCiphertextEncoding(t *testing.T) {
	compiler, err := SchemaCompiler(repositoryDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		model, field string
		maximum      int
	}{
		{"DocumentsChunk", "ciphertext", 1048592},
		{"DocumentsChunkPutRequest", "ciphertext", 1048592},
		{"DocumentsFile", "metadata", 32768},
		{"DocumentsManifest", "metadata", 32768},
	} {
		t.Run(tc.model, func(t *testing.T) {
			schema, err := SchemaAt(compiler, "/components/schemas/"+tc.model+"/properties/"+tc.field)
			if err != nil {
				t.Fatal(err)
			}
			for _, size := range []int{15, 16, 17, 18, 19, 20, 21, tc.maximum, tc.maximum + 1} {
				encoded := base64.RawURLEncoding.EncodeToString(make([]byte, size))
				if valid := schema.Validate(encoded) == nil; valid != (size >= 16 && size <= tc.maximum) {
					t.Errorf("ciphertext length %d: accepted=%t", size, valid)
				}
			}
			for _, invalid := range []string{
				strings.Repeat("A", 21) + "B", // Nonzero unused bits after 16 bytes.
				strings.Repeat("A", 22) + "B", // Nonzero unused bits after 17 bytes.
				strings.Repeat("A", 25),       // A base64 string cannot have this length.
				strings.Repeat("A", 22) + "=", strings.Repeat("A", 21) + "+",
			} {
				if schema.Validate(invalid) == nil {
					t.Errorf("noncanonical ciphertext accepted: %q", invalid)
				}
			}
		})
	}
}

func TestRepositoryDocumentsPublicPointEncoding(t *testing.T) {
	doc := repositoryDocument(t)
	compiler, err := SchemaCompiler(doc)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../pkg/authn/documents/testdata/protocol.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Registration struct {
			PublicKey string `json:"public_key"`
		}
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	point, err := base64.RawURLEncoding.DecodeString(vector.Registration.PublicKey)
	if err != nil || len(point) != 65 || point[0] != 4 {
		t.Fatal("invalid public-point fixture")
	}
	for _, tc := range []struct{ model, field string }{
		{"DocumentsKey", "public_key"}, {"DocumentsPublicKey", "public_key"}, {"DocumentsEnvelope", "ephemeral_key"},
	} {
		t.Run(tc.model, func(t *testing.T) {
			schema, err := SchemaAt(compiler, "/components/schemas/"+tc.model+"/properties/"+tc.field)
			if err != nil {
				t.Fatal(err)
			}
			for prefix := range 256 {
				point[0] = byte(prefix)
				value := base64.RawURLEncoding.EncodeToString(point)
				if valid := schema.Validate(value) == nil; valid != (prefix == 4) {
					t.Errorf("public point prefix 0x%02x: accepted=%t, want %t", prefix, valid, prefix == 4)
				}
			}
		})
	}
}

var documentsContractEndpoints = map[string]struct {
	method, path string
	body         bool
	parameters   []string
}{
	"bootstrap":     {"get", "/api/documents/bootstrap", false, []string{}},
	"key.fetch":     {"get", "/api/documents/keys/fetch", false, []string{}},
	"key.register":  {"put", "/api/documents/keys/register", true, []string{}},
	"file.allocate": {"post", "/api/documents/files/allocate", true, []string{}},
	"file.manifest": {"put", "/api/documents/file/{id}/manifest", true, []string{"id"}},
	"chunk.put":     {"put", "/api/documents/file/{id}/chunk/{idx}/put", true, []string{"id", "idx"}},
	"file.commit":   {"post", "/api/documents/file/{id}/commit", false, []string{"id"}},
	"file.list":     {"get", "/api/documents/files", false, []string{"after"}},
	"file.fetch":    {"get", "/api/documents/file/{id}/fetch", false, []string{"id"}},
	"chunk.fetch":   {"get", "/api/documents/file/{id}/chunk/{idx}/fetch", false, []string{"id", "idx"}},
	"key.lookup":    {"get", "/api/documents/key/{user_id}/lookup", false, []string{"user_id"}},
	"share.put":     {"put", "/api/documents/file/{id}/share/{user_id}/put", true, []string{"id", "user_id"}},
	"share.list":    {"get", "/api/documents/file/{id}/share/list", false, []string{"id"}},
	"share.delete":  {"delete", "/api/documents/file/{id}/share/{user_id}/delete", false, []string{"id", "user_id"}},
	"file.delete":   {"delete", "/api/documents/file/{id}/delete", false, []string{"id"}},
	"key.reset":     {"post", "/api/documents/keys/reset", true, []string{}},
}

func TestRepositoryDocumentsMessages(t *testing.T) {
	doc := repositoryDocument(t)
	paths := doc["paths"].(map[string]any)
	if paths["/api/documents"] != nil {
		t.Fatal("Documents retains the obsolete dispatcher endpoint")
	}
	count := 0
	for path := range paths {
		if strings.HasPrefix(path, "/api/documents/") {
			count++
		}
	}
	if count != len(documentsContractEndpoints) {
		t.Fatal("unexpected Documents path count")
	}
	for name, endpoint := range documentsContractEndpoints {
		methods, ok := paths[endpoint.path].(map[string]any)
		if !ok || len(methods) != 1 || methods[endpoint.method] == nil {
			t.Fatal("incorrect Documents method/path", name)
		}
		op := methods[endpoint.method].(map[string]any)
		if (op["requestBody"] != nil) != endpoint.body {
			t.Fatal("unexpected request body", name)
		}
		params, _ := op["parameters"].([]any)
		if len(params) != len(endpoint.parameters) {
			t.Fatal("incorrect parameter count", name)
		}
		for i, parameter := range params {
			p := parameter.(map[string]any)
			in, required := "path", true
			if endpoint.parameters[i] == "after" {
				in, required = "query", false
			}
			if p["name"] != endpoint.parameters[i] || p["in"] != in || p["required"] != required {
				t.Fatal("incorrect resource parameter", name)
			}
		}
	}
	c, err := SchemaCompiler(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../pkg/authn/documents/testdata/protocol.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]any
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	file := vector["file"].(map[string]any)
	key := vector["registration"].(map[string]any)
	for _, tc := range []struct {
		operation string
		payload   any
		valid     bool
	}{
		{"key.reset", map[string]any{"user_id": key["user_id"], "key_id": key["key_id"]}, true},
		{"key.register", map[string]any{"key": key}, true},
		{"file.allocate", map[string]any{"size": 32, "chunks": 1}, true},
		{"file.manifest", map[string]any{"manifest": map[string]any{"metadata": file["metadata"], "envelope": file["envelope"]}}, true},
		{"chunk.put", map[string]any{"ciphertext": vector["ciphertext"]}, true},
		{"share.put", map[string]any{"envelope": file["envelope"]}, true},
		{"key.reset", map[string]any{}, false},
		{"key.reset", map[string]any{"user_id": key["user_id"]}, false},
		{"key.reset", map[string]any{"user_id": "00000000-0000-0000-0000-000000000000", "key_id": key["key_id"]}, false},
		{"file.allocate", nil, false},
		{"file.allocate", map[string]any{"operation": "file.allocate", "payload": map[string]any{"size": 32, "chunks": 1}}, false},
		{"file.allocate", map[string]any{"size": 32, "chunks": 1, "owner": key["user_id"]}, false},
		{"chunk.put", map[string]any{"id": file["id"], "ciphertext": vector["ciphertext"]}, false},
		{"chunk.put", map[string]any{"idx": 0, "ciphertext": vector["ciphertext"]}, false},
		{"chunk.put", map[string]any{"ciphertext": "padded=="}, false},
		{"share.put", map[string]any{"user_id": key["user_id"], "envelope": file["envelope"]}, false},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			endpoint := documentsContractEndpoints[tc.operation]
			path := endpoint.path
			schema, err := SchemaAt(c, "/paths/"+strings.ReplaceAll(path, "/", "~1")+"/"+endpoint.method+"/requestBody/content/application~1json/schema")
			if err != nil {
				t.Fatal(err)
			}
			err = schema.Validate(tc.payload)
			if (err == nil) != tc.valid {
				t.Fatalf("message contract: valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestRepositoryDocumentsMessageExamples(t *testing.T) {
	doc := repositoryDocument(t)
	c, err := SchemaCompiler(doc)
	if err != nil {
		t.Fatal(err)
	}
	for name, endpoint := range documentsContractEndpoints {
		path := endpoint.path
		t.Run(name, func(t *testing.T) {
			op := doc["paths"].(map[string]any)[path].(map[string]any)[endpoint.method].(map[string]any)
			pointer := "/paths/" + strings.ReplaceAll(path, "/", "~1") + "/" + endpoint.method + "/"
			responses := op["responses"].(map[string]any)
			response := responses["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
			params, _ := op["parameters"].([]any)
			for i, raw := range params {
				parameter := raw.(map[string]any)
				schema, err := SchemaAt(c, pointer+fmt.Sprintf("parameters/%d/schema", i))
				if err != nil {
					t.Fatal(err)
				}
				if parameter["description"] == nil || schema.Validate(parameter["examples"].(map[string]any)[name].(map[string]any)["value"]) != nil {
					t.Fatal("parameter needs a description and valid example")
				}
				if schema.Validate("") == nil || schema.Validate(nil) == nil {
					t.Fatal("resource parameter accepts empty or null")
				}
				if parameter["name"] == "idx" {
					for _, bad := range []any{-1, 4096, 0.5} {
						if schema.Validate(bad) == nil {
							t.Fatal("invalid chunk index accepted")
						}
					}
				}
			}
			sides := []struct {
				pointer string
				media   map[string]any
			}{{"responses/200/content/application~1json/schema", response}}
			if endpoint.body {
				request := op["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
				sides = append(sides, struct {
					pointer string
					media   map[string]any
				}{"requestBody/content/application~1json/schema", request})
			}
			for _, side := range sides {
				schema, err := SchemaAt(c, pointer+side.pointer)
				if err != nil {
					t.Fatal(err)
				}
				examples := side.media["examples"].(map[string]any)
				if len(examples) != 1 {
					t.Fatal("operation must have its own single message example")
				}
				example, ok := examples[name].(map[string]any)
				if !ok {
					t.Fatal("missing named message example")
				}
				value := example["value"].(map[string]any)
				if err := schema.Validate(value); err != nil {
					t.Fatalf("invalid message example: %v", err)
				}
				other := maps.Clone(value)
				if side.pointer == "requestBody/content/application~1json/schema" {
					if _, exists := value["operation"]; exists {
						t.Fatal("request retains operation wrapper")
					}
					if _, exists := value["payload"]; exists {
						t.Fatal("request retains payload wrapper")
					}
					for _, field := range []string{"operation", "payload"} {
						other[field] = map[string]any{}
						if schema.Validate(other) == nil {
							t.Fatal("schema accepts an obsolete request wrapper")
						}
						delete(other, field)
					}
				} else {
					if len(value) == 0 || value["operation"] != nil || value["result"] != nil {
						t.Fatal("response must contain concrete direct fields")
					}
					if schema.Validate(map[string]any{"operation": name, "result": value}) == nil {
						t.Fatal("response accepts obsolete wrappers")
					}
					for _, field := range []string{"operation", "result"} {
						other[field] = name
						if schema.Validate(other) == nil {
							t.Fatal("response accepts wrapper field")
						}
						delete(other, field)
					}
					if value["success"] != nil {
						if value["success"] != true || len(value) != 1 {
							t.Fatal("invalid confirmation example")
						}
						for _, invalid := range []any{map[string]any{}, map[string]any{"success": false}, map[string]any{"success": "true"}} {
							if schema.Validate(invalid) == nil {
								t.Fatal("confirmation must require literal boolean true")
							}
						}
					}
				}
			}
			for status, raw := range responses {
				if status == "200" {
					continue
				}
				response := raw.(map[string]any)
				ref, ok := response["$ref"].(string)
				if !ok || !strings.HasPrefix(ref, "#/components/responses/Documents") {
					t.Fatal("Documents errors must use the shared response contract")
				}
				response = doc["components"].(map[string]any)["responses"].(map[string]any)[strings.TrimPrefix(ref, "#/components/responses/")].(map[string]any)
				media := response["content"].(map[string]any)["application/json"].(map[string]any)
				schema, err := SchemaAt(c, strings.TrimPrefix(ref, "#")+"/content/application~1json/schema")
				if err != nil {
					t.Fatal(err)
				}
				if err := schema.Validate(media["example"]); err != nil {
					t.Fatalf("invalid error example: %v", err)
				}
			}
		})
	}
}

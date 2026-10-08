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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegularAsset(t *testing.T) {
	directory := t.TempDir()
	put(t, directory, "content/openapi.yaml", "public")
	if err := os.Symlink("openapi.yaml", filepath.Join(directory, "content/alias.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("content", filepath.Join(directory, "alias")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, want := range map[string]bool{
		"content/openapi.yaml":            true,
		"content":                         false,
		"missing.yaml":                    false,
		"content/alias.yaml":              false,
		"alias/openapi.yaml":              false,
		"content/openapi.yaml/child.yaml": false,
	} {
		if regularAsset(root, name) != want {
			t.Errorf("regularAsset(%q) != %v", name, want)
		}
	}
}

func TestE2EReferenceServer(t *testing.T) {
	directory := t.TempDir()
	put(t, directory, "index.html", "<title>API</title>")
	put(t, directory, "scalar.js", "window.loaded = true;")
	put(t, directory, "content/openapi.yaml", fixtureRoot)
	put(t, directory, "content/paths/node.yaml", fixturePath)
	put(t, directory, "content/schemas/node.yaml", fixtureSchema)
	bundle, err := Bundle(filepath.Join(directory, "content"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(directory, "generated"), bundle); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "private.yaml")
	if err := os.WriteFile(outside, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "content/private.yaml")); err != nil {
		t.Fatal(err)
	}
	put(t, directory, "private/secret.yaml", "must not be served")
	if err := os.Symlink("../private/secret.yaml", filepath.Join(directory, "content/alias.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../private", filepath.Join(directory, "content/alias")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	server := httptest.NewServer(Handler(root))
	defer server.Close()
	for _, tc := range []struct {
		method, path, media string
		status              int
	}{
		{"GET", "/", "text/html", 200},
		{"GET", "/scalar.js?v=123", "text/javascript", 200},
		{"GET", "/generated/openapi.json?v=123", "application/json", 200},
		{"HEAD", "/generated/openapi.json", "application/json", 200},
		{"GET", "/content/openapi.yaml", "application/yaml", 200},
		{"GET", "/content/", "", 404},
		{"GET", "/generated/", "", 404},
		{"GET", "/go.mod", "", 404},
		{"GET", "/reviewed-sources.yaml", "", 404},
		{"GET", "/content/private.yaml", "", 404},
		{"GET", "/content/alias.yaml", "", 404},
		{"GET", "/content/alias/secret.yaml", "", 404},
		{"GET", "/content/%61lias.yaml", "", 404},
		{"GET", "/content/../../go.mod", "", 404},
		{"POST", "/", "", 405},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(t.Context(), tc.method, server.URL+tc.path, nil)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			data, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status || !strings.HasPrefix(resp.Header.Get("Content-Type"), tc.media) {
				t.Fatalf("status/media %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
			}
			if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing response policy")
			}
			if tc.method == "HEAD" && len(data) != 0 {
				t.Fatal("HEAD returned a body")
			}
			if tc.method == "GET" && tc.status == 200 && tc.media == "application/json" && string(data) != string(bundle) {
				t.Fatal("served JSON differs from YAML bundle")
			}
			if tc.status == 405 && resp.Header.Get("Allow") != "GET, HEAD" {
				t.Fatal("missing method contract")
			}
		})
	}
}

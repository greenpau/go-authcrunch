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
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Write publishes an already validated bundle with an atomic rename. A matching
// bundle is not rewritten, and failed generation never removes a prior bundle.
func Write(directory string, data []byte) error {
	return writeBundleFile(directory, "openapi.json", data)
}

func writeBundleFile(directory, name string, data []byte) error {
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	stat, err := os.Lstat(directory)
	if err != nil || !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("generated directory must be a real directory: %s", directory)
	}
	destination := filepath.Join(directory, name)
	if stat, err := os.Lstat(destination); err == nil && !stat.Mode().IsRegular() {
		return fmt.Errorf("generated file must be a regular file: %s", destination)
	}
	if previous, err := os.ReadFile(destination); err == nil && bytes.Equal(previous, data) {
		return nil
	}
	file, err := os.CreateTemp(directory, ".openapi-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(0644); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), destination)
}

// Handler serves only reference assets, with no directory listings. Symlinks
// cannot turn allowed asset paths into aliases for private documentation files.
// The documentation tree must remain under the local operator's control.
func Handler(root *os.Root) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if path.Clean(name) != name || (name != "index.html" && name != "scalar.js" && name != "generated/openapi.json" && !(strings.HasPrefix(name, "content/") && strings.HasSuffix(name, ".yaml"))) {
			http.NotFound(w, r)
			return
		}
		if !regularAsset(root, name) {
			http.NotFound(w, r)
			return
		}
		file, err := root.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		switch path.Ext(name) {
		case ".html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case ".js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case ".json":
			w.Header().Set("Content-Type", "application/json")
		case ".yaml":
			w.Header().Set("Content-Type", "application/yaml")
		}
		http.ServeContent(w, r, name, info.ModTime(), file)
	})
}

func regularAsset(root *os.Root, name string) bool {
	parts := strings.Split(name, "/")
	for i := range parts {
		info, err := root.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if i == len(parts)-1 {
			return info.Mode().IsRegular()
		}
		if !info.IsDir() {
			return false
		}
	}
	return false
}

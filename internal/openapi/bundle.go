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

// Package openapi builds the repository's YAML API reference without fetching
// remote references or modifying its source documents.
package openapi

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type bundler struct {
	root       string
	documents  map[string]any
	components map[string]string
	keyOrder   map[string][]string
}

// Bundle resolves a modular YAML document to a self-contained JSON document.
// Named components retain local references, including recursive schemas.
func Bundle(directory string) ([]byte, error) {
	entry, err := os.Lstat(filepath.Clean(directory))
	if err != nil {
		return nil, err
	}
	if entry.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("OpenAPI content directory must not be a symlink")
	}
	root, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	b := &bundler{root: root, documents: map[string]any{}, components: map[string]string{}, keyOrder: map[string][]string{}}
	entryFile := filepath.Join(root, "openapi.yaml")
	raw, err := b.read(entryFile)
	if err != nil {
		return nil, err
	}
	doc, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("openapi.yaml must contain an object")
	}
	for kind, entries := range object(doc["components"]) {
		if componentsKind.child(kind) == literalKind {
			continue
		}
		for name, value := range object(entries) {
			canonical := "#/components/" + escape(kind) + "/" + escape(name)
			b.components[entryFile+canonical] = canonical
			ref, ok := object(value)["$ref"].(string)
			if !ok {
				continue
			}
			file, fragment, err := b.target(entryFile, ref)
			if err != nil {
				return nil, err
			}
			key := file + "#" + fragment
			if _, duplicate := b.components[key]; duplicate {
				return nil, fmt.Errorf("component source is registered twice: %s", ref)
			}
			b.components[key] = canonical
		}
	}
	result, err := b.expand(raw, entryFile, "", documentKind, map[string]bool{})
	if err != nil {
		return nil, err
	}
	doc = object(result)
	if err := Validate(doc); err != nil {
		return nil, err
	}
	if err := ValidateStandard(doc); err != nil {
		return nil, err
	}
	// A forgotten source file is usually a path/component missing from the root.
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks are not allowed in OpenAPI content: %s", path)
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			if _, read := b.documents[path]; !read {
				return fmt.Errorf("unreferenced YAML source: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	data, err := b.marshalDocument(doc, entryFile)
	return append(data, '\n'), err
}

func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func escape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func (b *bundler) target(from, ref string) (string, string, error) {
	u, err := url.Parse(ref)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(ref, "\\") {
		return "", "", fmt.Errorf("only local YAML references are allowed: %q", ref)
	}
	file := from
	if u.Path != "" {
		if filepath.IsAbs(u.Path) || filepath.Ext(u.Path) != ".yaml" {
			return "", "", fmt.Errorf("expected a relative .yaml reference: %q", ref)
		}
		file = filepath.Join(filepath.Dir(from), filepath.FromSlash(u.Path))
	}
	physical, err := filepath.EvalSymlinks(file)
	if err != nil {
		return "", "", fmt.Errorf("reference %q from %s: %w", ref, from, err)
	}
	relative, err := filepath.Rel(b.root, physical)
	if err != nil || !filepath.IsLocal(relative) || physical != file {
		return "", "", fmt.Errorf("reference escapes content or uses a symlink: %q", ref)
	}
	return physical, u.Fragment, nil
}

func (b *bundler) read(file string) (any, error) {
	if doc, ok := b.documents[file]; ok {
		return doc, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%s: expected exactly one YAML document", file)
	}
	if err := checkYAML(&node); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var doc any
	if err := node.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	b.documents[file] = doc
	b.rememberOrder(file, "", &node)
	return doc, nil
}

func checkYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("line %d: use $ref instead of YAML anchors/aliases", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag != "!!str" || seen[key.Value] {
				return fmt.Errorf("line %d: duplicate or non-string key %q (quote status codes)", key.Line, key.Value)
			}
			seen[key.Value] = true
		}
	}
	if n.Kind == yaml.ScalarNode {
		switch n.Tag {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
		default:
			return fmt.Errorf("line %d: unsupported YAML tag %s", n.Line, n.Tag)
		}
	}
	for _, child := range n.Content {
		if err := checkYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func pointer(doc any, fragment string) (any, error) {
	if fragment == "" {
		return doc, nil
	}
	if !strings.HasPrefix(fragment, "/") {
		return nil, fmt.Errorf("expected JSON Pointer, got #%s", fragment)
	}
	for part := range strings.SplitSeq(fragment[1:], "/") {
		for i := 0; i < len(part); i++ {
			if part[i] == '~' && (i+1 == len(part) || (part[i+1] != '0' && part[i+1] != '1')) {
				return nil, fmt.Errorf("invalid JSON Pointer escape in #%s", fragment)
			}
			if part[i] == '~' {
				i++
			}
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch v := doc.(type) {
		case map[string]any:
			var found bool
			doc, found = v[part]
			if !found {
				return nil, fmt.Errorf("unresolved JSON Pointer #%s", fragment)
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) || strconv.Itoa(i) != part {
				return nil, fmt.Errorf("invalid array pointer #%s", fragment)
			}
			doc = v[i]
		default:
			return nil, fmt.Errorf("unresolved JSON Pointer #%s", fragment)
		}
	}
	return doc, nil
}

func (b *bundler) expand(value any, from, location string, kind syntaxKind, active map[string]bool) (any, error) {
	if kind == literalKind {
		return value, nil
	}
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		if raw, exists := v["$ref"]; exists && kind.reference() {
			ref, ok := raw.(string)
			if !ok || ref == "" {
				return nil, fmt.Errorf("invalid $ref in %s", from)
			}
			file, fragment, err := b.target(from, ref)
			if err != nil {
				return nil, err
			}
			doc, err := b.read(file)
			if err != nil {
				return nil, err
			}
			target, err := pointer(doc, fragment)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			key := file + "#" + fragment
			if canonical := b.components[key]; canonical != "" && canonical != "#"+location {
				out["$ref"] = canonical
			} else {
				if active[key] {
					return nil, fmt.Errorf("cyclic non-component reference: %s", ref)
				}
				active[key] = true
				expanded, err := b.expand(target, file, location, kind, active)
				delete(active, key)
				if err != nil {
					return nil, err
				}
				var ok bool
				out, ok = expanded.(map[string]any)
				if !ok {
					if len(v) == 1 {
						return expanded, nil
					}
					return nil, fmt.Errorf("reference siblings require an object: %s", ref)
				}
			}
		}
		for key, child := range v {
			if key == "$ref" && kind.reference() {
				continue
			}
			// Anchors and resource IDs change JSON Schema reference resolution.
			// Keep the authored subset explicit instead of silently rebasing them.
			if kind == schemaKind && (key == "$id" || key == "$anchor" || key == "$dynamicRef" || key == "$dynamicAnchor") {
				return nil, fmt.Errorf("unsupported schema resource keyword %s in %s", key, from)
			}
			if _, overlap := out[key]; overlap {
				return nil, fmt.Errorf("ambiguous reference sibling %s in %s", key, from)
			}
			x, err := b.expand(child, from, location+"/"+escape(key), kind.child(key), active)
			if err != nil {
				return nil, err
			}
			out[key] = x
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			x, err := b.expand(child, from, location+"/"+strconv.Itoa(i), kind.child(""), active)
			if err != nil {
				return nil, err
			}
			out[i] = x
		}
		return out, nil
	default:
		return value, nil
	}
}

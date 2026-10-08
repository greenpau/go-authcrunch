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
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Remember source mapping order separately from the maps used for validation.
// Only paths and path-item fields use it during export; schemas and payloads
// retain the existing deterministic encoding.
func (b *bundler) rememberOrder(file, fragment string, node *yaml.Node) {
	switch node.Kind {
	case yaml.DocumentNode:
		b.rememberOrder(file, fragment, node.Content[0])
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			b.keyOrder[file+"#"+fragment] = append(b.keyOrder[file+"#"+fragment], key)
			b.rememberOrder(file, fragment+"/"+escape(key), node.Content[i+1])
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			b.rememberOrder(file, fragment+"/"+strconv.Itoa(i), child)
		}
	}
}

// References are already checked and expanded. Splice referenced fields at the
// authored $ref position, retaining the placement of non-overlapping siblings.
func (b *bundler) pathItemOrder(file, fragment string) ([]string, error) {
	value, err := pointer(b.documents[file], fragment)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, key := range b.keyOrder[file+"#"+fragment] {
		if key != "$ref" {
			keys = append(keys, key)
			continue
		}
		ref, _ := object(value)["$ref"].(string)
		target, part, err := b.target(file, ref)
		if err != nil {
			return nil, err
		}
		nested, err := b.pathItemOrder(target, part)
		if err != nil {
			return nil, err
		}
		keys = append(keys, nested...)
	}
	return keys, nil
}

type jsonField struct {
	name  string
	value any
}

type jsonFields []jsonField

func (fields jsonFields) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, field := range fields {
		if i > 0 {
			out.WriteByte(',')
		}
		key, err := json.Marshal(field.name)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(field.value)
		if err != nil {
			return nil, err
		}
		out.Write(key)
		out.WriteByte(':')
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func (b *bundler) marshalDocument(doc map[string]any, entryFile string) ([]byte, error) {
	paths := object(doc["paths"])
	ordered := make(jsonFields, 0, len(paths))
	for _, path := range b.keyOrder[entryFile+"#/paths"] {
		value := paths[path]
		// Path-map extensions are literal data, including fields named $ref.
		if !strings.HasPrefix(path, "x-") {
			keys, err := b.pathItemOrder(entryFile, "/paths/"+escape(path))
			if err != nil {
				return nil, err
			}
			item := object(value)
			fields := make(jsonFields, 0, len(item))
			for _, key := range keys {
				fields = append(fields, jsonField{key, item[key]})
			}
			value = fields
		}
		ordered = append(ordered, jsonField{path, value})
	}
	doc["paths"] = ordered
	return json.MarshalIndent(doc, "", "  ")
}

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
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// WriteArtifact exports an already validated bundle as standalone JSON and YAML.
// Each file is replaced atomically; callers publish only after both writes succeed.
func WriteArtifact(directory string, data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON bundle")
	}
	var document yaml.Node
	// JSON permits these literal characters inside strings, but YAML normalizes
	// them as line breaks. Escape them before passing JSON to the YAML parser.
	escaped := strings.NewReplacer("\u0085", `\u0085`, "\u2028", `\u2028`, "\u2029", `\u2029`).Replace(string(data))
	if err := yaml.Unmarshal([]byte(escaped), &document); err != nil {
		return err
	}
	// Change only JSON's flow collections to block YAML. Preserve string quotes
	// so YAML 1.1 consumers cannot turn "on" or "12:34" into booleans or numbers,
	// and line breaks cannot be folded. Scalar tags and exact numbers stay intact.
	// Authored YAML is never rewritten.
	var blockStyle func(*yaml.Node)
	blockStyle = func(node *yaml.Node) {
		if node.Kind == yaml.MappingNode || node.Kind == yaml.SequenceNode {
			node.Style = 0
		}
		for _, child := range node.Content {
			blockStyle(child)
		}
	}
	blockStyle(&document)
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	if err := Write(directory, data); err != nil {
		return err
	}
	return writeBundleFile(directory, "openapi.yaml", output.Bytes())
}

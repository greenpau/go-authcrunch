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
	_ "embed" // Embed the offline OpenAPI structural schema.
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed oas31-schema.yaml
var specificationSchema []byte

var compiledSpecification = sync.OnceValues(func() (*jsonschema.Schema, error) {
	var source map[string]any
	if err := yaml.Unmarshal(specificationSchema, &source); err != nil {
		return nil, err
	}
	doc, err := jsonValue(source)
	if err != nil {
		return nil, err
	}
	c := newSchemaCompiler()
	const location = "https://spec.openapis.org/oas/3.1/schema/2022-10-07"
	if err := c.AddResource(location, doc); err != nil {
		return nil, err
	}
	return c.Compile(location)
})

const documentLocation = "https://openapi.invalid/document"

type offlineLoader struct{}

func (offlineLoader) Load(location string) (any, error) {
	return nil, fmt.Errorf("external schema loading is disabled: %s", location)
}

func newSchemaCompiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(offlineLoader{})
	return c
}

func jsonValue(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(data))
}

// SchemaCompiler registers the bundled document for validating its payload
// schemas. It cannot fetch any external resource, including file URLs.
func SchemaCompiler(doc map[string]any) (*jsonschema.Compiler, error) {
	value, err := jsonValue(doc)
	if err != nil {
		return nil, err
	}
	c := newSchemaCompiler()
	if err := c.AddResource(documentLocation, value); err != nil {
		return nil, err
	}
	return c, nil
}

// SchemaAt compiles a JSON Pointer into a registered specification. It is also
// used by native HTTP contract tests, so tests consume the authored schemas.
func SchemaAt(c *jsonschema.Compiler, fragment string) (*jsonschema.Schema, error) {
	return c.Compile(documentLocation + "#" + fragment)
}

// ValidateStandard validates OpenAPI structure against the vendored official
// schema, compiles every payload schema and checks media-type examples.
func ValidateStandard(doc map[string]any) error {
	schema, err := compiledSpecification()
	if err != nil {
		return err
	}
	value, err := jsonValue(doc)
	if err != nil {
		return err
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("OpenAPI structure: %w", err)
	}
	c, err := SchemaCompiler(doc)
	if err != nil {
		return err
	}
	for name := range object(object(doc["components"])["schemas"]) {
		if _, err := SchemaAt(c, "/components/schemas/"+escape(name)); err != nil {
			return fmt.Errorf("schema %s: %w", name, err)
		}
	}
	return validateMediaSchemas(c, doc, doc, "", documentKind)
}

func validateMediaSchemas(c *jsonschema.Compiler, doc map[string]any, value any, location string, kind syntaxKind) error {
	if kind == literalKind || kind == schemaKind {
		return nil
	}
	switch v := value.(type) {
	case map[string]any:
		if _, exists := v["schema"]; exists && (kind == mediaKind || kind == parameterKind) {
			schema, err := SchemaAt(c, location+"/schema")
			if err != nil {
				return fmt.Errorf("schema at %s: %w", location, err)
			}
			samples := map[string]any{}
			if sample, exists := v["example"]; exists {
				samples["example"] = sample
			}
			for name, example := range object(v["examples"]) {
				example, err := dereference(doc, example)
				if err != nil {
					return err
				}
				if sample, exists := object(example)["value"]; exists {
					samples[name] = sample
				}
			}
			for name, sample := range samples {
				value, err := jsonValue(sample)
				if err != nil {
					return err
				}
				if err := schema.Validate(value); err != nil {
					return fmt.Errorf("example %s at %s: %w", name, location, err)
				}
			}
		}
		for key, child := range v {
			if err := validateMediaSchemas(c, doc, child, location+"/"+escape(key), kind.child(key)); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range v {
			if err := validateMediaSchemas(c, doc, child, location+"/"+strconv.Itoa(i), kind.child("")); err != nil {
				return err
			}
		}
	}
	return nil
}

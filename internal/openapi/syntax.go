// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package openapi

import "strings"

// syntaxKind distinguishes reference-bearing objects from payload data and
// maps whose keys are user-chosen names. In particular, a property named $ref
// and a $ref in an example are data, not instructions to the bundler.
type syntaxKind uint16

const (
	literalKind syntaxKind = iota
	documentKind
	componentsKind
	pathsKind
	responsesKind
	pathItemKind
	operationKind
	parameterKind
	responseKind
	requestBodyKind
	mediaKind
	encodingKind
	exampleKind
	linkKind
	securitySchemeKind
	callbackKind
	schemaKind
	collectionKind syntaxKind = 1 << 8
)

func (k syntaxKind) reference() bool {
	return k != literalKind && k != documentKind && k != componentsKind && k != pathsKind && k != responsesKind && k&collectionKind == 0
}

func (k syntaxKind) child(key string) syntaxKind {
	if k&collectionKind != 0 {
		return k &^ collectionKind
	}
	switch k {
	case documentKind:
		switch key {
		case "components":
			return componentsKind
		case "paths":
			return pathsKind
		case "webhooks":
			return pathItemKind | collectionKind
		}
	case pathsKind, responsesKind:
		if strings.HasPrefix(key, "x-") {
			return literalKind
		}
		if k == pathsKind {
			return pathItemKind
		}
		return responseKind
	case componentsKind:
		switch key {
		case "schemas":
			return schemaKind | collectionKind
		case "parameters", "headers":
			return parameterKind | collectionKind
		case "responses":
			return responseKind | collectionKind
		case "requestBodies":
			return requestBodyKind | collectionKind
		case "examples":
			return exampleKind | collectionKind
		case "links":
			return linkKind | collectionKind
		case "securitySchemes":
			return securitySchemeKind | collectionKind
		case "callbacks":
			return callbackKind | collectionKind
		case "pathItems":
			return pathItemKind | collectionKind
		}
	case pathItemKind:
		if methods[key] {
			return operationKind
		}
		if key == "parameters" {
			return parameterKind | collectionKind
		}
	case operationKind:
		switch key {
		case "parameters":
			return parameterKind | collectionKind
		case "responses":
			return responsesKind
		case "requestBody":
			return requestBodyKind
		case "callbacks":
			return callbackKind | collectionKind
		}
	case parameterKind, mediaKind:
		switch key {
		case "schema":
			return schemaKind
		case "content":
			return mediaKind | collectionKind
		case "examples":
			return exampleKind | collectionKind
		case "encoding":
			return encodingKind | collectionKind
		}
	case responseKind, requestBodyKind, encodingKind:
		switch key {
		case "content":
			return mediaKind | collectionKind
		case "headers":
			return parameterKind | collectionKind
		case "links":
			return linkKind | collectionKind
		}
	case callbackKind:
		// Callback keys are runtime expressions, not fixed object fields.
		if key != "$ref" && !strings.HasPrefix(key, "x-") {
			return pathItemKind
		}
	case schemaKind:
		switch key {
		case "$defs", "properties", "patternProperties", "dependentSchemas":
			return schemaKind | collectionKind
		case "allOf", "anyOf", "oneOf", "prefixItems":
			return schemaKind | collectionKind
		case "not", "if", "then", "else", "items", "contains", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "propertyNames", "contentSchema":
			return schemaKind
		}
	}
	// Examples, defaults, enum/const values, extensions and other annotations
	// are opaque even when their payload happens to look like a schema.
	return literalKind
}

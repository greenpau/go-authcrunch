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

package httpserver

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/greenpau/go-authcrunch"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

type initializationError struct{ cause error }

func (e *initializationError) Error() string {
	return "initialize AuthCrunch runtime: check security configuration and required resources (details withheld because they may contain credentials)"
}

func (e *initializationError) Unwrap() error { return e.cause }

// The legacy KMS decoder indexes the directive's first two tokens before its
// semantic checks. Reject incomplete records before invoking that decoder.
func validateCryptoStatements(statements []string) error {
	for i, statement := range statements {
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return fmt.Errorf("invalid crypto configuration statement %d", i+1)
		}
	}
	return nil
}

// Serialized collections represent concrete objects, but JSON also permits
// null entries. Several existing component validators dereference those entries.
// Inspect only the declared JSON model, leaving optional fields nil and opaque
// provider parameters to their owning validators. Do not include map keys or
// configuration values in errors. Tracking pointers also bounds shared graphs.
func validateConfigurationObjects(config *authcrunch.Config) error {
	seen := make(map[any]bool)
	var walk func(reflect.Value, string) error
	walk = func(value reflect.Value, location string) error {
		switch value.Kind() {
		case reflect.Pointer:
			if value.IsNil() || seen[value.Interface()] {
				return nil
			}
			seen[value.Interface()] = true
			return walk(value.Elem(), location)
		case reflect.Struct:
			for i := 0; i < value.NumField(); i++ {
				field := value.Type().Field(i)
				name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
				if !field.IsExported() || name == "" || name == "-" {
					continue
				}
				if err := walk(value.Field(i), location+"."+name); err != nil {
					return err
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < value.Len(); i++ {
				entry := value.Index(i)
				if entry.Kind() == reflect.Pointer && entry.IsNil() {
					return fmt.Errorf("%s[%d] must not be null", location, i)
				}
				if err := walk(entry, location); err != nil {
					return err
				}
			}
		case reflect.Map:
			for iter := value.MapRange(); iter.Next(); {
				entry := iter.Value()
				if entry.Kind() == reflect.Pointer && entry.IsNil() {
					return fmt.Errorf("%s contains a null object", location)
				}
				if err := walk(entry, location); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(reflect.ValueOf(config), "security")
}

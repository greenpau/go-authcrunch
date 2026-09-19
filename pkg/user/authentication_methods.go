// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package user

import (
	"fmt"
	"slices"
	"strings"
)

func (c *Claims) unpackAuthenticationMethods(value any, claims, data map[string]any) error {
	var methods []string
	switch v := value.(type) {
	case []string:
		methods = slices.Clone(v)
	case []any:
		for _, entry := range v {
			method, ok := entry.(string)
			if !ok {
				return fmt.Errorf("invalid authentication method reference")
			}
			methods = append(methods, method)
		}
	default:
		return fmt.Errorf("authentication method references must be a list")
	}
	for _, method := range methods {
		if strings.TrimSpace(method) == "" {
			return fmt.Errorf("empty authentication method reference")
		}
		if !slices.Contains(c.AuthenticationMethods, method) {
			c.AuthenticationMethods = append(c.AuthenticationMethods, method)
		}
	}
	if len(c.AuthenticationMethods) > 0 {
		claims["amr"] = slices.Clone(c.AuthenticationMethods)
		data["amr"] = slices.Clone(c.AuthenticationMethods)
	}
	return nil
}

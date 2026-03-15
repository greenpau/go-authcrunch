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

package ldap

import (
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// parseFirstDN returns the first RDN (e.g., "ou=mathematicians") from a full DN.
func parseFirstDN(dn string) (string, error) {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil {
		return "", err
	}

	if len(parsedDN.RDNs) == 0 || len(parsedDN.RDNs[0].Attributes) == 0 {
		return "", fmt.Errorf("invalid or empty DN structure")
	}

	primaryRDN := parsedDN.RDNs[0].Attributes[0]

	if primaryRDN.Value == "" {
		return "", fmt.Errorf("empty primary RDN")
	}

	return strings.ToLower(primaryRDN.Value), nil
}

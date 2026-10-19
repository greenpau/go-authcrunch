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

package parser_test

import (
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity/attachment/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func ExampleNewIdentityAttachmentConfigFromDirectives() {
	config, err := parser.NewIdentityAttachmentConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"attach", "to", "local", "identity", "store", "localdb"})})
	fmt.Println(config.LocalIdentityStore, err)
	// Output: localdb <nil>
}

func TestIdentityAttachmentConfig(t *testing.T) {
	good := cfgutil.EncodeArgs([]string{"attach", "to", "local", "identity", "store", "localdb"})
	for _, statements := range [][]string{{good}, nil} {
		if config, err := parser.NewIdentityAttachmentConfigFromDirectives(statements); err != nil || config == nil {
			t.Fatal(err)
		}
	}
	for _, statements := range [][]string{{good, good}, {good + "\nignored"}, {"attach"}, {cfgutil.EncodeArgs([]string{"attach", "to", "local", "identity", "store", ":memory:"})}, {cfgutil.EncodeArgs([]string{"attach", "to", "local", "identity", "store", ""})}} {
		if config, err := parser.NewIdentityAttachmentConfigFromDirectives(statements); err == nil || config != nil {
			t.Fatal("invalid attachment accepted")
		}
	}
}

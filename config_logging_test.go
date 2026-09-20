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

package authcrunch_test

import (
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/logging"
)

func TestConfigLoggingValidation(t *testing.T) {
	cfg := &authcrunch.Config{Logging: &logging.Config{Skip: []logging.SkipRule{{Match: "regex", Text: "["}}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "logging") {
		t.Fatal("root validation ignored logging")
	}
	if server, err := authcrunch.NewServer(cfg, zap.NewNop()); server != nil || err == nil || !strings.Contains(err.Error(), "logging") {
		t.Fatal("server accepted invalid logging")
	}
	encoded, err := json.Marshal(authcrunch.NewConfig())
	if err != nil || strings.Contains(string(encoded), "logging") {
		t.Fatal("default config opted into logging")
	}
}

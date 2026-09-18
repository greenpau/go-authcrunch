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

// Package parser decodes standalone HTTP server settings for reusable consumers.
package parser

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/httpserver"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// NewHTTPServerConfigFromDirectives accepts encoded block-body statements:
// listen <host:port>, tls certificate <file>, tls key <file>, insecure http
// enabled|disabled, timeout read header|read|write|idle|shutdown <duration>,
// max header bytes <number>, and repeatable portal <name> <path> routes.
// Encode each statement with cfgutil.EncodeArgs. Singleton settings cannot
// repeat. Empty input fails because transport and portal routes are required.
// Parsing has no file, network, or runtime provisioning side effects.
func NewHTTPServerConfigFromDirectives(statements []string) (*httpserver.Config, error) {
	cfg := &httpserver.Config{}
	seen := make(map[string]bool)
	for i, statement := range statements {
		fail := func() (*httpserver.Config, error) { return nil, fmt.Errorf("invalid HTTP server statement %d", i+1) }
		if strings.ContainsAny(statement, "\r\n") {
			return fail()
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return fail()
		}
		if slices.Contains(args, "") {
			return fail()
		}
		key := ""
		switch {
		case len(args) == 2 && args[0] == "listen":
			key = "listen"
			cfg.ListenAddress = args[1]
		case len(args) == 3 && args[0] == "tls" && args[1] == "certificate":
			key = "certificate"
			cfg.TLSCertificateFile = args[2]
		case len(args) == 3 && args[0] == "tls" && args[1] == "key":
			key = "key"
			cfg.TLSKeyFile = args[2]
		case len(args) == 3 && args[0] == "insecure" && args[1] == "http":
			key = "http"
			switch args[2] {
			case "enabled":
				cfg.InsecureHTTP = true
			case "disabled":
				cfg.InsecureHTTP = false
			default:
				return fail()
			}
		case len(args) == 4 && args[0] == "timeout" && args[1] == "read" && args[2] == "header":
			key = "read header"
			cfg.ReadHeaderTimeout = args[3]
		case len(args) == 3 && args[0] == "timeout":
			key = args[1]
			switch args[1] {
			case "read":
				cfg.ReadTimeout = args[2]
			case "write":
				cfg.WriteTimeout = args[2]
			case "idle":
				cfg.IdleTimeout = args[2]
			case "shutdown":
				cfg.ShutdownTimeout = args[2]
			default:
				return fail()
			}
		case len(args) == 4 && args[0] == "max" && args[1] == "header" && args[2] == "bytes":
			key = "max header bytes"
			cfg.MaxHeaderBytes, err = strconv.Atoi(args[3])
			if err != nil {
				return fail()
			}
		case len(args) == 3 && args[0] == "portal":
			cfg.Portals = append(cfg.Portals, httpserver.PortalRoute{Name: args[1], Path: args[2]})
		default:
			return fail()
		}
		if key != "" {
			if seen[key] {
				return fail()
			}
			seen[key] = true
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

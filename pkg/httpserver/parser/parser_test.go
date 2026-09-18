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
	"reflect"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/httpserver/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestHTTPServerDirectives(t *testing.T) {
	statements := []string{
		"listen [::1]:8443", cfgutil.EncodeArgs([]string{"tls", "certificate", "/private/cert, file.pem"}),
		cfgutil.EncodeArgs([]string{"tls", "key", "/private/key file.pem"}), "insecure http disabled",
		"timeout read header 5s", "timeout read 15s", "timeout write 45s", "timeout idle 90s", "timeout shutdown 20s",
		"max header bytes 4096", "portal primary /tenant/auth", "portal secondary /other",
	}
	original := append([]string(nil), statements...)
	cfg, err := parser.NewHTTPServerConfigFromDirectives(statements)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "[::1]:8443" || cfg.TLSCertificateFile != "/private/cert, file.pem" || cfg.TLSKeyFile != "/private/key file.pem" || cfg.InsecureHTTP || cfg.ReadHeaderTimeout != "5s" || cfg.ReadTimeout != "15s" || cfg.WriteTimeout != "45s" || cfg.IdleTimeout != "90s" || cfg.ShutdownTimeout != "20s" || cfg.MaxHeaderBytes != 4096 || len(cfg.Portals) != 2 {
		t.Fatal("directive values lost")
	}
	if !reflect.DeepEqual(statements, original) {
		t.Fatal("parser mutated statements")
	}
	other, err := parser.NewHTTPServerConfigFromDirectives(statements)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Portals[0].Name = "changed"
	if other.Portals[0].Name != "primary" {
		t.Fatal("parser calls share state")
	}
	base := []string{"insecure http enabled", "portal primary /auth"}
	for _, statement := range []string{
		"", "unknown SECRET", "listen", "listen :80 extra", "listen \"\"", "listen :80\nportal x /y", "listen :80\r", "\"broken",
		"insecure http true", "insecure http disabled", "insecure http enabled", "tls key file", "tls certificate file", "tls wrong SECRET",
		"timeout wrong 5s", "timeout read header", "timeout read 0s", "max header bytes SECRET", "max header bytes 999999999999999999999999",
		"portal primary /other", "portal secondary /auth/sub", "portal secondary", "portal secondary /login", "portal \"\" /other",
		cfgutil.EncodeArgs([]string{"portal", "secondary", "/other\x00"}),
	} {
		t.Run(statement, func(t *testing.T) {
			cfg, err := parser.NewHTTPServerConfigFromDirectives(append(append([]string(nil), base...), statement))
			if err == nil || cfg != nil {
				t.Fatal("invalid directive accepted")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("error disclosed statement data")
			}
		})
	}
	for _, repeated := range []string{"listen :8443", "timeout read header 5s", "timeout read 5s", "timeout write 5s", "timeout idle 5s", "timeout shutdown 5s", "max header bytes 4096"} {
		cfg, err := parser.NewHTTPServerConfigFromDirectives(append(append([]string(nil), base...), repeated, repeated))
		if err == nil || cfg != nil {
			t.Fatal("duplicate singleton accepted")
		}
	}
	for _, input := range [][]string{nil, {}, {"portal primary /auth"}, {"insecure http enabled"}} {
		cfg, err := parser.NewHTTPServerConfigFromDirectives(input)
		if err == nil || cfg != nil {
			t.Fatal("incomplete config accepted")
		}
	}
}

func ExampleNewHTTPServerConfigFromDirectives() {
	config, err := parser.NewHTTPServerConfigFromDirectives([]string{
		"listen 127.0.0.1:8443", "tls certificate server.pem", "tls key server-key.pem", "portal primary /auth",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(config.ListenAddress, config.Portals[0].Path, config.ShutdownTimeout)
	// Output: 127.0.0.1:8443 /auth 30s
}

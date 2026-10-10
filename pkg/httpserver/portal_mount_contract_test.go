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

package httpserver_test

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/httpserver"
	serverparser "github.com/greenpau/go-authcrunch/pkg/httpserver/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

type portalMountCase struct {
	path     string
	reserved bool
}

func portalMountCases(t *testing.T) []portalMountCase {
	t.Helper()
	data, err := os.ReadFile("../authn/testdata/reserved_route_words.json")
	if err != nil {
		t.Fatal(err)
	}
	var words map[string]struct {
		Mount string `json:"mount"`
	}
	if err := json.Unmarshal(data, &words); err != nil || len(words) == 0 {
		t.Fatal("reserved route catalogue must be a nonempty object")
	}
	var names []string
	for name := range words {
		names = append(names, name)
	}
	slices.Sort(names)
	cases := []portalMountCase{{"/", false}, {"/xauth", false}, {"/tenant/xauth", false}, {"/tenant/security", false}}
	for _, word := range names {
		rule := words[word].Mount
		if rule != "allow" && rule != "deny_segment" && rule != "deny_prefix" {
			t.Fatalf("reserved word %q needs an explicit mount rule", word)
		}
		cases = append(cases,
			portalMountCase{"/" + word, rule != "allow"},
			portalMountCase{"/tenant/" + word, rule != "allow"},
			portalMountCase{"/" + word + "/tenant", rule != "allow"},
			portalMountCase{"/tenant/" + word + "-service/console", rule == "deny_prefix"},
			portalMountCase{"/tenant/team-" + word, false},
			// Portal dispatch is case-sensitive; do not invent normalization.
			portalMountCase{"/tenant/" + strings.ToUpper(word), false},
		)
	}
	return cases
}

// The independent catalogue must agree with both public configuration entry
// points. New route reservations cannot silently leave mount validation behind.
func TestPortalReservedMountContract(t *testing.T) {
	for _, tc := range portalMountCases(t) {
		t.Run(tc.path, func(t *testing.T) {
			config := &httpserver.Config{InsecureHTTP: true, Portals: []httpserver.PortalRoute{{Name: "portal", Path: tc.path}}}
			err := config.Validate()
			if (err != nil) != tc.reserved || (err != nil && !strings.Contains(err.Error(), "uses a reserved endpoint")) {
				t.Fatalf("reserved=%v: typed configuration returned %v", tc.reserved, err)
			}
			parsed, err := serverparser.NewHTTPServerConfigFromDirectives([]string{"insecure http enabled", cfgutil.EncodeArgs([]string{"portal", "portal", tc.path})})
			if (err != nil) != tc.reserved {
				t.Fatalf("reserved=%v: directive parser returned %v", tc.reserved, err)
			}
			if tc.reserved {
				if parsed != nil {
					t.Fatal("rejected mount returned partial configuration")
				}
			} else if parsed == nil || len(parsed.Portals) != 1 || parsed.Portals[0].Path != tc.path {
				t.Fatal("accepted mount changed during parsing")
			}
		})
	}
}

// Exercise the host's public startup workflow too: raw/serialized configs can
// bypass the directive parser. Rejection must precede TLS/security provisioning
// and release the caller's real listener, without accepting any HTTP request.
func TestE2EHTTPServerReservedMounts(t *testing.T) {
	for _, tc := range portalMountCases(t) {
		if !tc.reserved {
			continue
		}
		t.Run(tc.path, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			config := &httpserver.Config{TLSCertificateFile: "unused.pem", TLSKeyFile: "unused.key", Portals: []httpserver.PortalRoute{{Name: "portal", Path: tc.path}}}
			if err := httpserver.Serve(t.Context(), listener, config, nil, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "uses a reserved endpoint") {
				t.Fatalf("startup did not reject the reserved mount before provisioning: %v", err)
			}
			if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("startup rejection did not close the listener: %v", err)
			}
		})
	}
}

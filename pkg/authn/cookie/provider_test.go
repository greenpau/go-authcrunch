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

package cookie

import (
	"strings"
	"testing"
)

func TestProviderLoginCookieNames(t *testing.T) {
	factory, err := NewFactory(&Config{CookieNamePrefix: "CUSTOM", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "APP_BINDING", "__Secure-APP_BINDING"} {
		if err := factory.ValidateProviderLoginCookieName(name, "/auth/provider/app"); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range factory.cookieNames() {
		if err := factory.ValidateProviderLoginCookieName(strings.ToLower(name), "/auth/provider/app"); err == nil {
			t.Fatal("lowercase portal cookie alias accepted")
		}
		if err := factory.ValidateProviderLoginCookieName(name, "/auth/provider/app"); err == nil {
			t.Fatal("portal cookie collision accepted")
		}
	}
	for _, name := range []string{"bad;name", "bad\r\n", "__Host-APP_BINDING"} {
		if err := factory.ValidateProviderLoginCookieName(name, "/auth/provider/app"); err == nil {
			t.Fatal("invalid provider binding name accepted")
		}
	}
}

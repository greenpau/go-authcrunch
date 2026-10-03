// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cookie_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

func TestCrossDeviceBrowserBindingCookie(t *testing.T) {
	c := cookie.NewConfig()
	c.CrossDeviceSessionIDCookieName = "CrossDevice_BROWSER"
	c.Insecure = true
	c.Domains = map[string]*cookie.DomainConfig{"example.test": {Domain: "example.test"}}
	f, err := cookie.NewFactory(c)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := http.ParseSetCookie(f.GetCrossDeviceSessionIDCookie("/", "binding"))
	if err != nil {
		t.Fatal(err)
	}
	if issued.Name != "CrossDevice_BROWSER" || issued.Domain != "" || issued.Path != "/" || issued.MaxAge != 300 || !issued.Secure || !issued.HttpOnly || issued.SameSite != http.SameSiteNoneMode {
		t.Fatalf("unsafe CrossDevice binding cookie: %#v", issued)
	}
	deleted, err := http.ParseSetCookie(f.GetDeleteCrossDeviceSessionIDCookie("/"))
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Domain != issued.Domain || deleted.Path != issued.Path || !deleted.Secure || !deleted.HttpOnly || deleted.SameSite != issued.SameSite || deleted.MaxAge >= 0 {
		t.Fatal("CrossDevice binding deletion changed cookie scope")
	}
	if _, err := cookie.NewFactory(&cookie.Config{CrossDeviceSessionIDCookieName: cookie.DefaultCookieNamePrefix + "_" + cookie.DefaultAccessTokenCookieName}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("CrossDevice binding name collision accepted")
	}
	host, err := cookie.NewFactory(&cookie.Config{CrossDeviceSessionIDCookieName: "__Host-CrossDevice"})
	if err != nil || !strings.HasPrefix(host.GetCrossDeviceSessionIDCookie("/", "binding"), "__Host-CrossDevice=") {
		t.Fatal("optional __Host- CrossDevice binding name rejected")
	}
}

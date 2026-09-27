// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"io"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/messaging"
)

const emailHTMLInjection = `<img src=x onerror=alert(1)>`

func TestRenderEmailHTMLEscapesUntrustedValues(t *testing.T) {
	content := `<p>{{.text}}</p><a href="{{.url}}">continue</a>`
	poisonedURL := `https://portal.example.test/register"><img src=x onerror=alert(1)>`
	got, err := renderEmailHTML(content, map[string]string{"text": emailHTMLInjection, "url": poisonedURL})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, emailHTMLInjection) || strings.Contains(got, `<img`) {
		t.Fatalf("rendered email contains active markup: %s", got)
	}
	if !strings.Contains(got, `&lt;img`) || !strings.Contains(got, `%22`) {
		t.Fatalf("rendered email did not contextually escape text and URL values: %s", got)
	}
}

func TestE2ERegistrationNotificationEscapesHTML(t *testing.T) {
	inbox := filepath.Join(t.TempDir(), "inbox")
	provider := &LocalUserRegistryProvider{
		EmailProviderName: "file-sink",
	}
	if err := provider.SetMessaging(&messaging.Config{FileProviders: []*messaging.FileProvider{{
		Name: "file-sink", RootDir: inbox, SenderEmail: "auth@example.test",
	}}}); err != nil {
		t.Fatal(err)
	}
	poisonedURL := `https://portal.example.test/register"><img src=x onerror=alert(1)>`
	if err := provider.Notify(map[string]string{
		"template":          "registration_confirmation",
		"session_id":        "session-id",
		"request_id":        "request-id",
		"timestamp":         "now",
		"registration_id":   "registration-id",
		"registration_code": "registration-code",
		"username":          "alice",
		"email":             "alice@example.test",
		"registration_url":  poisonedURL,
		"realm_name":        "local",
		"src_ip":            "192.0.2.10",
		"src_conn_ip":       "192.0.2.11",
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("notification files = %d, want 1", len(entries))
	}
	raw, err := os.ReadFile(filepath.Join(inbox, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(raw), "\r\n", 2)
	if len(parts) != 2 {
		t.Fatal("notification does not contain a header/body boundary")
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(parts[1])))
	if err != nil {
		t.Fatal(err)
	}
	body := string(decoded)
	if strings.Contains(body, emailHTMLInjection) || strings.Contains(body, `<img`) {
		t.Fatalf("delivered email contains active markup: %s", body)
	}
	if !strings.Contains(body, `%22`) || !strings.Contains(body, `%3cimg`) {
		t.Fatalf("delivered email did not preserve contextual escaping: %s", body)
	}
}

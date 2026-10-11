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

package authn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestE2EDocumentsBrowserEncryption(t *testing.T) {
	f := newDocumentsE2E(t, "/auth", true)
	tokens := map[string]string{"alice": f.login(t, "alice"), "bob": f.login(t, "bob"), "charlie": f.login(t, "charlie")}
	encoded, err := json.Marshal(tokens)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	profile := t.TempDir()
	sum := sha256.Sum256(f.server.Certificate().RawSubjectPublicKeyInfo)
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t), "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile, "--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:]), "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	driver := exec.CommandContext(ctx, "node", "ui/testdata/documents_browser_e2e.cjs", endpoint, f.server.URL, f.base)
	driver.Stdin = bytes.NewReader(encoded)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("Documents browser journey failed: %v\n%s", err, output)
	}
	var result struct {
		Passed bool
		Chunks int
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed || result.Chunks != 2 {
		t.Fatal("browser did not confirm encryption journey")
	}
	raw, err := os.ReadFile(f.database)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sensitive-budget-2026.txt", "Private file body invisible to TLS inspection"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext persisted in Documents database")
		}
	}
}

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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authnui "github.com/greenpau/go-authcrunch/pkg/authn/ui"
)

func TestE2EMFADOMRendering(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("Node.js is required for browser E2E")
	}
	assets := http.FileServer(http.Dir("ui/core"))
	portalUI := authnui.NewFactory()
	if err := portalUI.AddBuiltinTemplates(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sandbox":
			args := portalUI.GetArgs()
			args.Data["view"] = "mfa_app_register"
			args.Data["id"] = "fixture"
			args.Data["mfa_label"] = "AUTHP"
			args.Data["mfa_comment"] = "Browser Fixture"
			args.Data["mfa_email"] = "member@example.test"
			args.Data["mfa_secret"] = "FIXTURESECRET"
			args.Data["mfa_digits"] = "6"
			args.Data["mfa_period"] = "30"
			args.Data["code_uri"] = "otpauth://totp/fixture"
			args.Data["code_uri_encoded"] = "fixture"
			page, err := portalUI.Render("basic/sandbox", args)
			if err != nil {
				http.Error(w, "render failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(page.Bytes())
		case r.URL.Path == "/fixture":
			script := r.URL.Query().Get("script")
			if script != "mfa_add_app.js" && script != "sandbox_mfa_add_app.js" {
				http.Error(w, "unknown fixture", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<!doctype html><html><body>
<input id="label"><input id="email"><input id="secret" value="fixture secret">
<input id="digits"><input id="period"><input id="barcode_uri" value="/barcode">
<div id="mfa-no-camera-link">text<a href="#">manual</a></div>
<div id="mfa-qr-code-image">text<img alt="old"></div>
<ul class="tabs"><li class="tab"><a class="active" href="#panel%%5Bfixture%%5D%%5Cvalue">fixture</a></li></ul>
<div id="panel[fixture]\value"></div>
<script src="/assets/materialize-css/js/materialize.min.js"></script>
<script src="/assets/js/%s"></script></body></html>`, script)
		case strings.HasPrefix(r.URL.Path, "/assets/"):
			http.StripPrefix("/assets/", assets).ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/barcode/"):
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	profile := t.TempDir()
	chrome := exec.CommandContext(ctx, refreshBrowserExecutable(t),
		"--headless=new", "--disable-gpu", "--no-sandbox", "--ignore-certificate-errors",
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	driver := exec.CommandContext(ctx, "node", filepath.Join("ui", "testdata", "mfa_dom_browser_e2e.cjs"), endpoint, server.URL)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("MFA DOM browser regression failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), `"passed":true`) {
		t.Fatalf("browser did not confirm MFA DOM rendering: %s", output)
	}
}

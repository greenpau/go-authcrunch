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
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is an evidence-collector fixture, not a conformance run. Deliberately
// mixed outcomes must survive the public HTTP/export/file reporting workflow.
func TestE2EOIDCConformanceEvidenceCollector(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	statuses := []string{"PASSED", "WARNING", "SKIPPED", "REVIEW", "FAILED", "INTERRUPTED", ""}
	exports := map[string][]byte{}
	var instances []string
	for i, status := range statuses {
		id := fmt.Sprintf("fixture-%d", i)
		instances = append(instances, id)
		info := map[string]any{"testId": id, "testName": "fixture-module", "result": status, "status": "FINISHED"}
		if status == "" {
			delete(info, "result")
			info["status"] = "WAITING"
		}
		content, err := json.Marshal(map[string]any{"testInfo": info, "results": []any{map[string]any{"page_source": "<p>Fixture evidence only</p>"}}})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		writer := zip.NewWriter(&buf)
		for name, data := range map[string][]byte{id + ".json": content, id + ".sig": []byte(base64.URLEncoding.EncodeToString(signature))} {
			member, err := writer.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := member.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		exports[id] = buf.Bytes()
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data any
		switch r.URL.Path {
		case "/jwks":
			data = map[string]any{"keys": []any{map[string]any{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}}
		case "/api/plan":
			data = map[string]any{"data": []any{map[string]any{"_id": "fixture-plan"}}}
		case "/api/plan/fixture-plan":
			data = map[string]any{"planName": "fixture", "modules": []any{map[string]any{"testModule": "fixture-module", "instances": instances}, map[string]any{"testModule": "fixture-not-run"}}}
		default:
			id, ok := strings.CutPrefix(r.URL.Path, "/api/log/export/")
			if !ok || exports[id] == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(exports[id])
			return
		}
		_ = json.NewEncoder(w).Encode(data)
	}))
	defer server.Close()
	output := t.TempDir()
	foundationCollectEvidence(t, output, server.URL, server.Client(), 1)
	data, err := os.ReadFile(filepath.Join(output, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Outcomes map[string]int
		Modules  []map[string]any
		NotRun   []string `json:"not_run"`
		Exit     int      `json:"runner_exit_code"`
		Verified int      `json:"verified_signed_exports"`
		Visuals  int      `json:"visual_captures"`
	}
	if json.Unmarshal(data, &summary) != nil || len(summary.Modules) != 7 || summary.Exit != 1 || summary.Verified != 7 || summary.Visuals != 7 || len(summary.NotRun) != 1 {
		t.Fatal("evidence collection dropped results or exit status")
	}
	for _, status := range []string{"PASSED", "WARNING", "SKIPPED", "REVIEW", "FAILED", "INTERRUPTED", "UNKNOWN"} {
		if summary.Outcomes[status] != 1 {
			t.Fatal("original outcome was reclassified")
		}
	}
	html, err := os.ReadFile(filepath.Join(output, "index.html"))
	if err != nil || !bytes.Contains(html, []byte("exports/fixture-0.zip")) || !bytes.Contains(html, []byte("WARNING")) {
		t.Fatal("HTML report lost evidence links")
	}
	for _, name := range []string{"index.html", "summary.json", "suite-jwks.json", "exports/fixture-0.zip"} {
		stat, err := os.Stat(filepath.Join(output, name))
		if err != nil || stat.Mode().Perm() != 0600 {
			t.Fatal("private evidence permissions lost")
		}
	}
}

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
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

// A real HTTP 100 response proves the handler has reached its body read after
// initial authentication. Withhold that body until the competing operation has
// completed; no sleeps or portal internals establish the ordering.
func documentsDelayedRequest(t *testing.T, f *documentsE2E, token, operation string, payload any, whileReading func(), want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	method, path, body := documentsRequest(t, operation, payload)
	reading := make(chan struct{})
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{Got100Continue: func() { close(reading) }})
	req, err := http.NewRequestWithContext(ctx, method, f.server.URL+strings.TrimSuffix(f.base, "/")+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Expect", "100-continue")
	var response *http.Response
	var requestErr error
	finished := make(chan struct{})
	go func() {
		response, requestErr = f.client.Do(req)
		close(finished)
	}()
	// Always cancel/drain the request, including a Fatal in whileReading.
	defer func() {
		cancel()
		_ = writer.Close()
		<-finished
		if response != nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-reading:
	case <-ctx.Done():
		t.Fatal("Documents request did not reach its body read")
	}
	whileReading()
	if _, err := io.WriteString(writer, body); err != nil {
		t.Fatal("could not complete delayed Documents body", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	<-finished
	if requestErr != nil || response == nil {
		t.Fatal("delayed Documents request failed", requestErr)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != want {
		t.Fatalf("delayed %s: HTTP %d, want %d, read error %v", operation, response.StatusCode, want, err)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("delayed response lacks privacy headers")
	}
	openAPIJourneyResponse(t, f.server.URL+strings.TrimSuffix(f.base, "/"), req.URL, method, response.StatusCode, response.Header, data)
}

func TestE2EDocumentsRevalidatesAfterBodyRead(t *testing.T) {
	t.Run("credential_revocation", func(t *testing.T) {
		f := newDocumentsE2E(t, "/auth", true)
		token := f.login(t, "alice")
		key := f.enroll(t, token)
		file := documentsDecode[documents.File](t, f.message(t, token, "file.allocate", map[string]any{"size": 32, "chunks": 1}, 200))
		f.message(t, token, "file.manifest", map[string]any{"id": file.ID, "manifest": documents.Manifest{Metadata: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Envelope: documentsEnvelope(key)}}, 200)
		documentsDelayedRequest(t, f, token, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, func() {
			if err := f.store.RevokeUserSessions(t.Context(), key.UserID); err != nil {
				t.Fatal("revocation was blocked by the slow body", err)
			}
		}, http.StatusUnauthorized)
		// Different replacement ciphertext must succeed: a rejected upload must
		// not leave an immutable chunk behind before returning its error.
		token = f.login(t, "alice")
		ciphertext := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		f.message(t, token, "chunk.put", map[string]any{"id": file.ID, "idx": 0, "ciphertext": ciphertext}, 200)
		f.message(t, token, "file.commit", map[string]any{"id": file.ID}, 200)
		chunk := documentsDecode[map[string]string](t, f.message(t, token, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, 200))
		if chunk["ciphertext"] != ciphertext {
			t.Fatal("rejected upload changed stored ciphertext")
		}
	})
	t.Run("recipient_reset", func(t *testing.T) {
		f := newDocumentsE2E(t, "/auth", true)
		aliceToken, bobToken := f.login(t, "alice"), f.login(t, "bob")
		alice, bob := f.enroll(t, aliceToken), f.enroll(t, bobToken)
		file := f.ready(t, aliceToken, alice)
		var replacement documents.Key
		documentsDelayedRequest(t, f, aliceToken, "share.put", map[string]any{"id": file.ID, "user_id": bob.UserID, "envelope": documentsEnvelope(bob)}, func() {
			f.message(t, bobToken, "key.reset", map[string]any{"user_id": bob.UserID, "key_id": bob.KeyID}, 200)
			replacement = f.enroll(t, bobToken)
		}, http.StatusConflict)
		f.message(t, bobToken, "file.fetch", map[string]any{"id": file.ID}, 404)
		recipients := documentsDecode[map[string][]string](t, f.message(t, aliceToken, "share.list", map[string]any{"id": file.ID}, 200))
		if len(recipients["recipients"]) != 0 {
			t.Fatal("stale in-flight share survived recipient reset")
		}
		f.message(t, aliceToken, "share.put", map[string]any{"id": file.ID, "user_id": bob.UserID, "envelope": documentsEnvelope(replacement)}, 200)
		f.message(t, bobToken, "chunk.fetch", map[string]any{"id": file.ID, "idx": 0}, 200)
	})
}

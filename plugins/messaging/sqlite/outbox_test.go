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

package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
)

func testOutbox(t *testing.T) (*Outbox, *Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := &Config{Name: "mail", Path: filepath.Join(dir, "outbox.db")}
	out, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	})
	return out, config
}
func testMessage() *messaging.SendInput {
	return &messaging.SendInput{Subject: "Hello", Body: "<p>hello</p>\n", Recipients: []string{"alice@example.test"}}
}
func TestOutboxLeaseLifecycle(t *testing.T) {
	out, config := testOutbox(t)
	input := testMessage()
	if err := out.Send(input); err != nil {
		t.Fatal(err)
	}
	input.Recipients[0] = "other@example.test"
	msg, err := out.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID <= 0 || msg.CreatedAt == 0 || msg.Recipients[0] != "alice@example.test" {
		t.Fatal("bad detached message")
	}
	encoded, _ := json.Marshal(msg)
	if strings.Contains(string(encoded), msg.Lease) {
		t.Fatal("serialized worker lease")
	}
	if _, err := out.Claim(t.Context()); !errors.Is(err, ErrEmpty) {
		t.Fatal(err)
	}
	if err := out.Acknowledge(t.Context(), msg.ID, rand.Text()); !errors.Is(err, ErrLease) {
		t.Fatal(err)
	}
	otherConfig := *config
	otherConfig.Name = "other"
	other, err := New(t.Context(), &otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Claim(t.Context()); !errors.Is(err, ErrEmpty) {
		t.Fatal(err)
	}
	if err := other.Acknowledge(t.Context(), msg.ID, msg.Lease); !errors.Is(err, ErrLease) {
		t.Fatal(err)
	}
	if err := out.Release(t.Context(), msg.ID, msg.Lease); err != nil {
		t.Fatal(err)
	}
	next, err := out.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if next.ID != msg.ID || next.Lease == msg.Lease {
		t.Fatal("bad re-lease")
	}
	if err := out.Acknowledge(t.Context(), msg.ID, msg.Lease); !errors.Is(err, ErrLease) {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Claim(t.Context()); !errors.Is(err, ErrEmpty) {
		t.Fatal("restart lost active lease", err)
	}
	if err := reopened.Acknowledge(t.Context(), next.ID, next.Lease); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Acknowledge(t.Context(), next.ID, next.Lease); !errors.Is(err, ErrLease) {
		t.Fatal(err)
	}
	if _, err := reopened.Claim(t.Context()); !errors.Is(err, ErrEmpty) {
		t.Fatal(err)
	}
}
func TestOutboxLeaseExpiryAndConcurrentWorkers(t *testing.T) {
	out, config := testOutbox(t)
	other, err := New(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := out.Send(testMessage()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan *Message, 2)
	failures := make(chan error, 2)
	for _, worker := range []*Outbox{out, other} {
		wg.Go(func() { <-start; m, e := worker.Claim(t.Context()); results <- m; failures <- e })
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	var claimed *Message
	for m := range results {
		if m != nil {
			if claimed != nil {
				t.Fatal("double claim")
			}
			claimed = m
		}
	}
	if claimed == nil {
		t.Fatal("no worker won")
	}
	empty := 0
	for err := range failures {
		if errors.Is(err, ErrEmpty) {
			empty++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if empty != 1 {
		t.Fatal("missing losing worker")
	}
	if err := out.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, "UPDATE messages SET leased_until=1")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := out.Acknowledge(t.Context(), claimed.ID, claimed.Lease); !errors.Is(err, ErrLease) {
		t.Fatal(err)
	}
	next, err := other.Claim(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if next.ID != claimed.ID || next.Lease == claimed.Lease {
		t.Fatal("expiry did not redeliver with new lease")
	}
	if err := out.Release(t.Context(), claimed.ID, claimed.Lease); !errors.Is(err, ErrLease) {
		t.Fatal(err)
	}
	if err := other.Acknowledge(t.Context(), next.ID, next.Lease); err != nil {
		t.Fatal(err)
	}
}
func TestOutboxValidationAndFailures(t *testing.T) {
	out, config := testOutbox(t)
	if config.Timeout != "" {
		t.Fatal("mutated caller config")
	}
	config.Name = "changed"
	if out.AsMap()["name"] != "mail" {
		t.Fatal("config alias")
	}
	metadata := out.AsMap()
	metadata["name"] = "changed"
	if out.AsMap()["name"] != "mail" {
		t.Fatal("metadata alias")
	}
	for _, change := range []func(*messaging.SendInput){func(m *messaging.SendInput) { m.Subject = "bad\r\nBcc: x" }, func(m *messaging.SendInput) { m.Body = "" }, func(m *messaging.SendInput) { m.Body = string([]byte{255}) }, func(m *messaging.SendInput) { m.Body = strings.Repeat("x", 60001) }, func(m *messaging.SendInput) { m.Recipients = nil }, func(m *messaging.SendInput) { m.Recipients = []string{"Name <alice@example.test>"} }, func(m *messaging.SendInput) {
		m.Credentials = &credentials.GenericCredential{Password: "do-not-persist"}
	}} {
		m := testMessage()
		change(m)
		if err := out.Send(m); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if err := out.Send(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := out.Claim(t.Context()); !errors.Is(err, ErrEmpty) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := out.SendContext(ctx, testMessage()); err == nil {
		t.Fatal("canceled send accepted")
	}
	if err := out.Send(testMessage()); err != nil {
		t.Fatal(err)
	}
	if err := out.db.Write(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, "INSERT INTO messages(queue,payload,created,leased_until) SELECT 'mail',payload,created,0 FROM messages CROSS JOIN (WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<999) SELECT x FROM n)")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := out.Send(testMessage()); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Claim(t.Context()); err == nil {
		t.Fatal("closed claim accepted")
	}
	if err := out.Send(testMessage()); err == nil {
		t.Fatal("closed send accepted")
	}
	var nilOut *Outbox
	if nilOut.Validate() == nil || nilOut.AsMap() != nil || nilOut.Close() != nil {
		t.Fatal("nil handling")
	}
	if _, err := New(t.Context(), nil); err == nil {
		t.Fatal("nil config accepted")
	}
	for _, c := range []*Config{nil, {}, {Name: "mail", Path: "relative"}, {Name: "mail", Path: "/tmp/x", Timeout: "31s"}, {Name: "bad\n", Path: "/tmp/x"}} {
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

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

package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	"github.com/greenpau/go-authcrunch/plugins/messaging/sqlite/parser"
)

func TestE2ESQLiteMessagingConcurrentWorkers(t *testing.T) {
	for _, separateQueues := range []bool{false, true} {
		t.Run(fmt.Sprint("separate_queues=", separateQueues), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			var workers []*sqlite.Outbox
			for i := range 2 {
				name := "mail"
				if separateQueues {
					name = fmt.Sprint("mail", i)
				}
				config, err := parser.NewSQLiteMessagingConfigFromDirectives([]string{"name " + name, fmt.Sprintf("path %q", filepath.Join(dir, "outbox.db")), "timeout 2s"})
				if err != nil {
					t.Fatal(err)
				}
				worker, err := sqlite.New(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close()
				workers = append(workers, worker)
			}
			const messages = 64
			for i := range messages {
				if err := workers[i%len(workers)].SendContext(ctx, &messaging.SendInput{Subject: fmt.Sprint(i), Body: "queued body", Recipients: []string{"alice@example.test"}}); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			acknowledged := make(chan string, messages)
			failures := make(chan error, len(workers))
			var wg sync.WaitGroup
			for _, worker := range workers {
				wg.Go(func() {
					<-start
					for {
						message, err := worker.Claim(ctx)
						if errors.Is(err, sqlite.ErrEmpty) {
							return
						}
						if err != nil {
							failures <- err
							return
						}
						if err := worker.Acknowledge(ctx, message.ID, message.Lease); err != nil {
							failures <- err
							return
						}
						acknowledged <- message.Subject
					}
				})
			}
			close(start)
			wg.Wait()
			close(acknowledged)
			close(failures)
			for err := range failures {
				t.Error("live worker failed", err)
			}
			seen := make(map[string]bool)
			for subject := range acknowledged {
				if seen[subject] {
					t.Fatal("workers acknowledged duplicate work")
				}
				seen[subject] = true
			}
			if len(seen) != messages {
				t.Fatalf("acknowledged %d messages, want %d", len(seen), messages)
			}
			for _, worker := range workers {
				if _, err := worker.Claim(ctx); !errors.Is(err, sqlite.ErrEmpty) {
					t.Fatal("drained live handle is unavailable", err)
				}
				if err := worker.SendContext(ctx, &messaging.SendInput{Subject: "after drain", Body: "queued body", Recipients: []string{"alice@example.test"}}); err != nil {
					t.Fatal("drained handle cannot accept work", err)
				}
				message, err := worker.Claim(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := worker.Acknowledge(ctx, message.ID, message.Lease); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestE2ESQLiteRegistrationNotification(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config, err := parser.NewSQLiteMessagingConfigFromDirectives([]string{"name notifications", fmt.Sprintf("path %q", filepath.Join(dir, "outbox.db")), "timeout 750ms"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored sqlite.Config
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	producer, err := sqlite.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	messagingConfig := &messaging.Config{}
	if err := messagingConfig.AddProvider("notifications", producer); err != nil {
		t.Fatal(err)
	}
	if err := messagingConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	if !messagingConfig.FindProvider("notifications") || messagingConfig.GetProviderType("notifications") != "sqlite" || messagingConfig.ExtractProvider("notifications") != producer {
		t.Fatal("runtime binding missing")
	}
	registration := &registry.LocalUserRegistryProvider{EmailProviderName: "notifications", AdminEmails: []string{"admin@example.test"}}
	if err := registration.SetMessaging(messagingConfig); err != nil {
		t.Fatal(err)
	}
	data := map[string]string{"template": "registration_confirmation", "session_id": "session-id", "request_id": "request-id", "timestamp": "now", "registration_id": "registration-id", "registration_code": "123456", "username": "alice", "email": "alice@example.test", "registration_url": `https://portal.example.test/register"><img src=x onerror=alert(1)>`, "realm_name": "local", "src_ip": "192.0.2.10", "src_conn_ip": "192.0.2.11"}
	if err := registration.Notify(data); err != nil {
		t.Fatal(err)
	}
	data["template"] = "registration_ready"
	if err := registration.Notify(data); err != nil {
		t.Fatal(err)
	}
	if err := producer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := registration.Notify(data); err == nil {
		t.Fatal("notification hid queue failure")
	}
	worker, err := sqlite.New(t.Context(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	for _, recipient := range []string{"alice@example.test", "admin@example.test"} {
		msg, err := worker.Claim(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(msg.Recipients) != 1 || msg.Recipients[0] != recipient || msg.Subject == "" || msg.LeaseExpiresAt <= time.Now().Unix() {
			t.Fatal("wrong notification envelope")
		}
		decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(msg.Body)))
		if err != nil {
			t.Fatal(err)
		}
		body := string(decoded)
		if strings.Contains(body, "<img") || !strings.Contains(body, "alice") {
			t.Fatal("unsafe or incomplete rendered notification", body)
		}
		if recipient == "alice@example.test" && (!strings.Contains(body, "%22") || !strings.Contains(body, "%3cimg") || !strings.Contains(body, "123456")) {
			t.Fatal("confirmation link/code encoding", body)
		}
		if recipient == "admin@example.test" && !strings.Contains(body, "&lt;img") {
			t.Fatal("admin text encoding", body)
		}
		if err := worker.Acknowledge(t.Context(), msg.ID, msg.Lease); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := worker.Claim(t.Context()); !errors.Is(err, sqlite.ErrEmpty) {
		t.Fatal(err)
	}
}

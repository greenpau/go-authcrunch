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

package messaging_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/quotedprintable"
	"net"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
)

type smtpDelivery struct {
	authenticated bool
	recipients    []string
	message       []byte
}

// This fixture speaks SMTP over a real connection and observes actual closure.
func smtpDeliveryFixture(t *testing.T, stage string) (string, <-chan struct{}, <-chan struct{}, <-chan smtpDelivery) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reached := make(chan struct{})
	closed := make(chan struct{})
	messages := make(chan smtpDelivery, 1)
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-closed:
		case <-time.After(6 * time.Second):
			t.Error("SMTP fixture did not drain")
		}
	})
	go func() {
		defer close(closed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if stage == "greeting" || stage == "tls" {
			close(reached)
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		protocol := textproto.NewConn(conn)
		defer protocol.Close()
		if err := protocol.PrintfLine("220 fixture ESMTP"); err != nil {
			return
		}
		var delivery smtpDelivery
		for {
			line, err := protocol.ReadLine()
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "), strings.HasPrefix(line, "HELO "):
				if stage == "auth" {
					err = protocol.PrintfLine("250-fixture\r\n250 AUTH PLAIN")
				} else {
					err = protocol.PrintfLine("250 fixture")
				}
			case strings.HasPrefix(line, "AUTH PLAIN "):
				decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				if decodeErr != nil || string(decoded) != "\x00sender\x00synthetic-smtp-password" {
					_ = protocol.PrintfLine("535 rejected")
					return
				}
				delivery.authenticated = true
				err = protocol.PrintfLine("235 authenticated")
			case strings.HasPrefix(line, "MAIL FROM:"):
				err = protocol.PrintfLine("250 sender accepted")
			case strings.HasPrefix(line, "RCPT TO:"):
				delivery.recipients = append(delivery.recipients, strings.TrimPrefix(line, "RCPT TO:"))
				err = protocol.PrintfLine("250 recipient accepted")
			case line == "DATA":
				if err = protocol.PrintfLine("354 send message"); err != nil {
					return
				}
				delivery.message, err = protocol.ReadDotBytes()
				if err != nil {
					return
				}
				messages <- delivery
				if stage == "data" {
					close(reached)
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				err = protocol.PrintfLine("250 accepted")
			case line == "QUIT":
				if stage == "quit" {
					close(reached)
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				_ = protocol.PrintfLine("221 bye")
				return
			default:
				err = protocol.PrintfLine("500 unexpected command")
			}
			if err != nil {
				return
			}
		}
	}()
	return listener.Addr().String(), reached, closed, messages
}

func smtpProvider(t *testing.T, address, protocol string) *messaging.EmailProvider {
	t.Helper()
	provider, err := messaging.NewEmailProvider([]string{"kind email", "name delivery", "address " + address, "protocol " + protocol, "sender auth@example.test", "passwordless"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(&messaging.Config{EmailProviders: []*messaging.EmailProvider{provider}})
	if err != nil {
		t.Fatal(err)
	}
	var restored messaging.Config
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatal(err)
	}
	return restored.ExtractEmailProvider("delivery")
}
func smtpInput() *messaging.SendInput {
	return &messaging.SendInput{Subject: "Confirmation", Body: "<p>caf=C3=A9 &amp; welcome</p>", Recipients: []string{"alice@example.test", "admin@example.test"}}
}

func TestE2EEmailProviderContextDelivery(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy=", legacy), func(t *testing.T) {
			address, _, _, messages := smtpDeliveryFixture(t, "")
			provider := smtpProvider(t, address, "smtp")
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			var err error
			if legacy {
				err = provider.Send(smtpInput())
			} else {
				err = provider.SendContext(ctx, smtpInput())
			}
			if err != nil {
				t.Fatal("SMTP delivery failed", err)
			}
			var delivered smtpDelivery
			select {
			case delivered = <-messages:
			case <-ctx.Done():
				t.Fatal("SMTP envelope missing")
			}
			if len(delivered.recipients) != 2 || delivered.recipients[0] != "<alice@example.test>" || delivered.recipients[1] != "<admin@example.test>" {
				t.Fatal("SMTP recipient isolation failed")
			}
			message, err := mail.ReadMessage(strings.NewReader(string(delivered.message)))
			if err != nil {
				t.Fatal(err)
			}
			if message.Header.Get("Content-Transfer-Encoding") != "quoted-printable" || message.Header.Get("Content-Type") != `text/html; charset="utf-8"` || message.Header.Get("Subject") != "Confirmation" {
				t.Fatal("SMTP MIME contract changed")
			}
			body, err := io.ReadAll(quotedprintable.NewReader(message.Body))
			if err != nil || strings.TrimSpace(string(body)) != "<p>café &amp; welcome</p>" {
				t.Fatal("SMTP changed queued body encoding", err)
			}
		})
	}
}
func TestE2EEmailProviderContextCancellation(t *testing.T) {
	for _, stage := range []string{"greeting", "tls", "data", "quit"} {
		t.Run(stage, func(t *testing.T) {
			address, reached, closed, _ := smtpDeliveryFixture(t, stage)
			protocol := "smtp"
			if stage == "tls" {
				protocol = "smtps"
			}
			provider := smtpProvider(t, address, protocol)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- provider.SendContext(ctx, smtpInput()) }()
			select {
			case <-reached:
			case <-time.After(3 * time.Second):
				t.Fatal("SMTP stall stage not reached")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("SMTP did not return cancellation", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("SMTP cancellation did not bound delivery")
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("SMTP cancellation left a socket open")
			}
		})
	}
	address, _, closed, _ := smtpDeliveryFixture(t, "greeting")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := smtpProvider(t, address, "smtp").SendContext(ctx, smtpInput()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("SMTP deadline not returned", err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP deadline left a socket open")
	}
}
func TestE2EEmailProviderTLSVerification(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err := smtpProvider(t, server.Listener.Addr().String(), "smtps").SendContext(ctx, smtpInput())
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
		t.Fatal("untrusted SMTP TLS certificate not rejected", err)
	}
}
func TestEmailProviderContextInput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := (&messaging.EmailProvider{Address: "unused.invalid:25"}).SendContext(ctx, smtpInput()); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context attempted delivery", err)
	}
	if err := (*messaging.EmailProvider)(nil).SendContext(t.Context(), smtpInput()); err == nil {
		t.Fatal("nil provider accepted")
	}
	if err := (&messaging.EmailProvider{}).SendContext(t.Context(), nil); err == nil {
		t.Fatal("nil input accepted")
	}
}

func TestE2EEmailProviderContextCredentials(t *testing.T) {
	address, _, _, messages := smtpDeliveryFixture(t, "auth")
	provider := smtpProvider(t, address, "smtp")
	provider.Passwordless = false
	provider.Credentials = "transport"
	input := smtpInput()
	if err := provider.SendContext(t.Context(), input); err == nil {
		t.Fatal("missing credentials allowed anonymous delivery")
	}
	input.Credentials = &credentials.GenericCredential{Username: "sender", Password: "synthetic-smtp-password"}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := provider.SendContext(ctx, input); err != nil {
		t.Fatal("authenticated SMTP delivery failed", err)
	}
	select {
	case delivered := <-messages:
		if !delivered.authenticated {
			t.Fatal("configured SMTP authentication was skipped")
		}
		if strings.Contains(string(delivered.message), input.Credentials.Password) {
			t.Fatal("transport credential leaked into message")
		}
	case <-ctx.Done():
		t.Fatal("authenticated message missing")
	}
}

// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package messaging

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/util"
)

// Send sends an email message using the transport's default timeouts.
// Workers with leases or shutdown deadlines should use SendContext instead.
func (e *EmailProvider) Send(req *SendInput) error {
	return e.SendContext(context.Background(), req)
}

// SendContext sends an email while honoring cancellation through dialing, TLS,
// SMTP commands, message submission and shutdown. Cancellation closes the actual
// connection; it never leaves a delivery goroutine running. An error after DATA
// may follow server acceptance, so callers must allow duplicate delivery when
// retrying and must not interpret cancellation as proof that no mail was sent.
func (e *EmailProvider) SendContext(ctx context.Context, req *SendInput) (err error) {
	if e == nil || req == nil {
		return fmt.Errorf("email provider and send input are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !e.Passwordless && req.Credentials == nil {
		return fmt.Errorf("email transport credentials are required")
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	var conn net.Conn
	if e.Protocol == "smtps" {
		tlsDialer := &tls.Dialer{NetDialer: dialer}
		conn, err = tlsDialer.DialContext(ctx, "tcp", e.Address)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", e.Address)
	}
	if err != nil {
		return err
	}
	// go-smtp sets its own operation deadlines. Closing the connection on caller
	// cancellation remains authoritative even when a command replaces a deadline.
	cancelConnection := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer cancelConnection()
	defer conn.Close()
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	c := smtp.NewClient(conn)
	defer c.Close()

	/*
		if found, _ := c.Extension("STARTTLS"); found {
			if err := c.StartTLS(nil); err != nil {
				return err
			}
		}
	*/

	if !e.Passwordless && req.Credentials != nil {
		if found, _ := c.Extension("AUTH"); !found {
			return errors.ErrMessagingProviderAuthUnsupported
		}
		auth := sasl.NewPlainClient("", req.Credentials.Username, req.Credentials.Password)
		if err := c.Auth(auth); err != nil {
			return err
		}
	}

	if err := c.Mail(e.SenderEmail, nil); err != nil {
		return err
	}

	for _, rcpt := range req.Recipients {
		if err := c.Rcpt(rcpt, nil); err != nil {
			return err
		}
	}

	sender := e.SenderEmail
	if e.SenderName != "" {
		sender = `"` + e.SenderName + `" <` + e.SenderEmail + ">"
	}

	msg := "MIME-Version: 1.0\n"
	msg += "Date: " + time.Now().Format(time.RFC1123Z) + "\n"
	msg += "From: " + sender + "\n"
	msg += "Subject: " + req.Subject + "\n"
	msg += "Thread-Topic: Account Registration." + "\n"
	msg += "Message-ID: <" + util.GetRandomString(64) + "." + e.SenderEmail + ">" + "\n"
	msg += `To: ` + strings.Join(req.Recipients, ", ") + "\n"

	if len(e.BlindCarbonCopy) > 0 {
		bccRcpts := dedupRcpt(req.Recipients, e.BlindCarbonCopy)
		if len(bccRcpts) > 0 {
			msg += "Bcc: " + strings.Join(bccRcpts, ", ") + "\n"
		}
	}

	msg += "Content-Transfer-Encoding: quoted-printable" + "\n"
	msg += `Content-Type: text/html; charset="utf-8"` + "\n"

	msg += "\r\n" + req.Body

	// Write email subject body.
	wc, err := c.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(wc, "%s", msg)
	if err != nil {
		return err
	}

	if err := wc.Close(); err != nil {
		return err
	}

	// Close connection.
	if err := c.Quit(); err != nil {
		return err
	}

	return nil
}

func dedupRcpt(arr1, arr2 []string) []string {
	var output []string
	m := make(map[string]interface{})
	for _, s := range arr1 {
		m[s] = true
	}

	for _, s := range arr2 {
		if _, exists := m[s]; exists {
			continue
		}
		output = append(output, s)
	}
	return output
}

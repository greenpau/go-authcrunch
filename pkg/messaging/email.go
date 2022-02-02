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
	"fmt"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"strings"
)

// EmailProvider represents email messaging provider.
type EmailProvider struct {
	Name            string            `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Address         string            `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	Protocol        string            `json:"protocol,omitempty" xml:"protocol,omitempty" yaml:"protocol,omitempty"`
	Credentials     string            `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
	SenderEmail     string            `json:"sender_email,omitempty" xml:"sender_email,omitempty" yaml:"sender_email,omitempty"`
	SenderName      string            `json:"sender_name,omitempty" xml:"sender_name,omitempty" yaml:"sender_name,omitempty"`
	Templates       map[string]string `json:"templates,omitempty" xml:"templates,omitempty" yaml:"templates,omitempty"`
	Passwordless    bool              `json:"passwordless,omitempty" xml:"passwordless,omitempty" yaml:"passwordless,omitempty"`
	BlindCarbonCopy []string          `json:"blind_carbon_copy,omitempty" xml:"blind_carbon_copy,omitempty" yaml:"blind_carbon_copy,omitempty"`
}

// Send sends an email message.
func (e *EmailProvider) Send(creds *credentials.Generic, rcpt, subj, body string) error {
	dial := smtp.Dial
	if e.Protocol == "smtps" {
		dial = func(addr string) (*smtp.Client, error) {
			return smtp.DialTLS(addr, nil)
		}
	}

	c, err := dial(e.Address)
	if err != nil {
		return err
	}
	defer c.Close()

	if found, _ := c.Extension("STARTTLS"); found {
		if err := c.StartTLS(nil); err != nil {
			return err
		}
	}

	if !e.Passwordless && creds != nil {
		if found, _ := c.Extension("AUTH"); !found {
			return errors.ErrMessagingProviderAuthUnsupported
		}
		auth := sasl.NewPlainClient("", creds.Username, creds.Password)
		if err := c.Auth(auth); err != nil {
			return err
		}
	}

	if err := c.Mail(e.SenderEmail, nil); err != nil {
		return err
	}

	if err := c.Rcpt(rcpt); err != nil {
		return err
	}

	sender := e.SenderEmail
	if e.SenderName != "" {
		sender = `"` + e.SenderName + `" <` + e.SenderEmail + ">"
	}

	msg := "From: " + sender + "\n"
	msg += "To: " + rcpt + "\n"

	if len(e.BlindCarbonCopy) > 0 {
		msg += "Bcc: " + strings.Join(e.BlindCarbonCopy, ", ") + "\n"
	}
	msg += subj + "\r\n" + body

	// Write email subject body.
	wc, err := c.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(wc, msg)
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

// Validate validates EmailProvider configuration.
func (e *EmailProvider) Validate() error {
	if e.Name == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("name")
	}

	switch {
	case e.Credentials != "" && e.Passwordless:
		return errors.ErrMessagingProviderCredentialsWithPasswordless
	case e.Credentials == "" && !e.Passwordless:
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("credentials")
	}

	if e.Address == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("address")
	}

	switch e.Protocol {
	case "smtp":
	case "smtps":
	case "":
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("protocol")
	default:
		return errors.ErrMessagingProviderProtocolUnsupported.WithArgs(e.Protocol)
	}

	if e.SenderEmail == "" {
		return errors.ErrMessagingProviderKeyValueEmpty.WithArgs("sender_email")
	}
	if e.Templates != nil {
		for k := range e.Templates {
			switch k {
			case "password_recovery":
			case "registration_confirmation":
			case "registration_verdict":
			case "mfa_otp":
			default:
				return errors.ErrMessagingProviderInvalidTemplate.WithArgs(k)
			}
		}
	}
	return nil
}

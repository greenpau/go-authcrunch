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

package registry

import (
	"bytes"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"mime/quotedprintable"
	"strings"
	"text/template"
)

// Notify serves notifications.
func (r *LocaUserRegistry) Notify(data map[string]string) error {
	var requiredFields []string
	var rcpts []string

	commonRequiredFields := []string{
		"session_id", "request_id", "timestamp",
		"template",
	}

	if data == nil {
		return errors.ErrNotifyRequestDataNil
	}

	for _, fieldName := range commonRequiredFields {
		if _, exists := data[fieldName]; !exists {
			return errors.ErrNotifyRequestFieldNotFound.WithArgs(fieldName)
		}
	}

	tmplName := data["template"]
	switch tmplName {
	case "registration_confirmation":
		requiredFields = []string{
			"registration_id", "username", "email", "registration_url",
			"registration_code", "src_ip", "src_conn_ip",
		}
	case "registration_ready":
		requiredFields = []string{
			"registration_id", "username", "email", "registration_url",
			"src_ip", "src_conn_ip",
		}
	case "registration_verdict":
		requiredFields = []string{
			"username", "email", "verdict",
		}
	default:
		return errors.ErrNotifyRequestTemplateUnsupported.WithArgs(tmplName)
	}

	for _, fieldName := range requiredFields {
		if _, exists := data[fieldName]; !exists {
			return errors.ErrNotifyRequestFieldNotFound.WithArgs(fieldName)
		}
	}

	switch tmplName {
	case "registration_confirmation", "registration_verdict":
		rcpts = append(rcpts, data["email"])
	case "registration_ready":
		rcpts = r.config.AdminEmails
	}

	lang := "en"
	if v, exists := data["lang"]; exists {
		lang = v
	} else {
		data["lang"] = lang
	}

	switch lang {
	case "en":
	default:
		return errors.ErrNotifyRequestLangUnsupported.WithArgs(lang)
	}

	if r.config.messaging == nil {
		return errors.ErrNotifyRequestMessagingNil.WithArgs(r.config.EmailProvider)
	}

	tmplSubj, tmplSubjErr := template.New("email_subj").Parse(messaging.EmailTemplateSubject[lang+"/"+tmplName])
	if tmplSubjErr != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(r.config.EmailProvider, tmplSubjErr)
	}
	emailSubj := bytes.NewBuffer(nil)
	if err := tmplSubj.Execute(emailSubj, data); err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(r.config.EmailProvider, err)
	}

	tmplBody, tmplBodyErr := template.New("email_body").Parse(messaging.EmailTemplateBody[lang+"/"+tmplName])
	if tmplBodyErr != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(r.config.EmailProvider, tmplBodyErr)
	}
	emailBody := bytes.NewBuffer(nil)
	if err := tmplBody.Execute(emailBody, data); err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(r.config.EmailProvider, err)
	}

	var qpEmailBody string
	qpEmailBody, err := quotedPrintableBody(emailBody.String())
	if err != nil {
		return errors.ErrNotifyRequestEmail.WithArgs(r.config.EmailProvider, err)
	}

	qpEmailSubj := emailSubj.String()
	repl := strings.NewReplacer("\r", "", "\n", " ")
	qpEmailSubj = strings.TrimSpace(repl.Replace(qpEmailSubj))

	providerType := r.config.messaging.GetProviderType(r.config.EmailProvider)

	switch providerType {
	case "email":
		provider := r.config.messaging.ExtractEmailProvider(r.config.EmailProvider)
		if provider == nil {
			return errors.ErrNotifyRequestEmailProviderNotFound.WithArgs(r.config.EmailProvider)
		}

		providerCredName := r.config.messaging.FindProviderCredentials(r.config.EmailProvider)
		if providerCredName == "" {
			return errors.ErrNotifyRequestEmailProviderCredNotFound.WithArgs(r.config.EmailProvider)
		}

		var providerCred *credentials.Generic
		if providerCredName != "passwordless" {
			if r.config.credentials == nil {
				return errors.ErrNotifyRequestCredNil.WithArgs(r.config.EmailProvider)
			}
			providerCred = r.config.credentials.ExtractGeneric(providerCredName)
			if providerCred == nil {
				return errors.ErrNotifyRequestCredNotFound.WithArgs(r.config.EmailProvider, providerCredName)
			}
		}

		if err := provider.Send(&messaging.EmailProviderSendInput{
			Subject:     qpEmailSubj,
			Body:        qpEmailBody,
			Recipients:  rcpts,
			Credentials: providerCred,
		}); err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(r.config.EmailProvider, err)
		}
	case "file":
		provider := r.config.messaging.ExtractFileProvider(r.config.EmailProvider)
		if provider == nil {
			return errors.ErrNotifyRequestEmailProviderNotFound.WithArgs(r.config.EmailProvider)
		}
		if err := provider.Send(&messaging.FileProviderSendInput{
			Subject:    qpEmailSubj,
			Body:       qpEmailBody,
			Recipients: rcpts,
		}); err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(r.config.EmailProvider, err)
		}
	default:
		return errors.ErrNotifyRequestProviderTypeUnsupported.WithArgs(r.config.EmailProvider, providerType)
	}
	return nil
}

func quotedPrintableBody(s string) (string, error) {
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return b.String(), nil
}

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

package authn

import (
	"bytes"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"mime/quotedprintable"
	"text/template"
)

func (p *Portal) notify(data map[string]string) error {
	var requiredFields []string
	var providerName string
	var providerType string
	var providerCredName string
	var providerCred *credentials.Generic
	var provider *messaging.EmailProvider

	commonRequiredFields := []string{
		"provider_name", "provider_type",
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

	providerName = data["provider_name"]
	providerType = data["provider_type"]

	tmplName := data["template"]
	switch tmplName {
	case "registration_confirmation":
		requiredFields = []string{
			"registration_id", "username", "email", "registration_url",
			"src_ip", "src_conn_ip",
		}
	default:
		return errors.ErrNotifyRequestTemplateUnsupported.WithArgs(tmplName)
	}

	for _, fieldName := range requiredFields {
		if _, exists := data[fieldName]; !exists {
			return errors.ErrNotifyRequestFieldNotFound.WithArgs(fieldName)
		}
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

	switch providerType {
	case "email":
		if p.config.messaging == nil {
			return errors.ErrNotifyRequestMessagingNil.WithArgs(providerName)
		}
		provider = p.config.messaging.ExtractEmailProvider(providerName)
		if provider == nil {
			return errors.ErrNotifyRequestEmailProviderNotFound.WithArgs(providerName)
		}

		providerCredName = p.config.messaging.FindProviderCredentials(providerName)
		if providerCredName == "" {
			return errors.ErrNotifyRequestEmailProviderCredNotFound.WithArgs(providerName)
		}
		if providerCredName != "passwordless" {
			if p.config.credentials == nil {
				return errors.ErrNotifyRequestCredNil.WithArgs(providerName)
			}
			providerCred = p.config.credentials.ExtractGeneric(providerCredName)
			if providerCred == nil {
				return errors.ErrNotifyRequestCredNotFound.WithArgs(providerName, providerCredName)
			}
		}

		tmplSubj, tmplSubjErr := template.New("email_subj").Parse(messaging.EmailTemplateSubject[lang+"/"+tmplName])
		if tmplSubjErr != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(providerName, tmplSubjErr)
		}
		emailSubj := bytes.NewBuffer(nil)
		if err := tmplSubj.Execute(emailSubj, data); err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(providerName, err)
		}

		tmplBody, tmplBodyErr := template.New("email_body").Parse(messaging.EmailTemplateBody[lang+"/"+tmplName])
		if tmplBodyErr != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(providerName, tmplBodyErr)
		}
		emailBody := bytes.NewBuffer(nil)
		if err := tmplBody.Execute(emailBody, data); err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(providerName, err)
		}

		var qpEmailBody string
		qpEmailBody, err := quotedPrintableBody(emailBody.String())
		if err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(providerName, err)
		}

		if err := provider.Send(providerCred, data["email"], emailSubj.String(), qpEmailBody); err != nil {
			return errors.ErrNotifyRequestEmail.WithArgs(providerName, err)
		}
	default:
		return errors.ErrNotifyRequestProviderTypeUnsupported.WithArgs(providerName, providerType)
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

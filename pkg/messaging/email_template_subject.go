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

// EmailTemplateSubject stores email subject templates.
var EmailTemplateSubject = map[string]string{
	"en/registration_confirmation": `Registration Confirmation Required`,
	"en/registration_ready":        `Review User Registration`,
	"en/registration_verdict": `{{- if eq .verdict "approved" -}}
User Registration Approved
{{- else -}}
User Registration Declined
{{- end -}}`,
}

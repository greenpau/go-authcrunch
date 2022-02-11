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

// EmailTemplateBody stores email body templates.
var EmailTemplateBody = map[string]string{
	"en/registration_confirmation": `<html>
  <body>
    <p>
      Please confirm your registration by clicking this
      <a href="{{ .registration_url }}/ack/{{ .registration_id }}">link</a>
      and providing the registration code <b><code>{{ .registration_code }}</code></b>
      within the next 45 minutes. If you haven't done so, please re-register.
    </p>

    <p>The registation metadata follows:</p>
    <ul style="list-style-type: disc">
      <li>Session ID: {{ .session_id }}</li>
      <li>Request ID: {{ .request_id }}</li>
      <li>Username: <code>{{ .username }}</code></li>
      <li>Email: <code>{{ .email }}</code></li>
      <li>IP Address: <code>{{ .src_ip }}</code></li>
      <li>Timestamp: {{ .timestamp }}</li>
    </ul>
  </body>
</html>`,
	"en/registration_ready": `<html>
  <body>
    <p>
      The following user successfully registered with the portal.
      Please use management interface to approve or decline the registration.
    </p>

    <p>The registation metadata follows:</p>
    <ul style="list-style-type: disc">
      <li>Registration ID: {{ .registration_id }}</li>
      <li>Registration URL: <code>{{ .registration_url }}</code></li>
      <li>Session ID: {{ .session_id }}</li>
      <li>Request ID: {{ .request_id }}</li>
      <li>Username: <code>{{ .username }}</code></li>
      <li>Email: <code>{{ .email }}</code></li>
      <li>IP Address: <code>{{ .src_ip }}</code></li>
      <li>Timestamp: {{ .timestamp }}</li>
    </ul>
  </body>
</html>`,
	"en/registration_verdict": `<html>
  <body>
    <p>
    {{- if eq .verdict "approved" -}}
      Your registration has been approved.
      You may now login with the username or email
      address below.
    {{- else -}}
      Your registration has been declined.
    {{- end -}}
    </p>
    <p>The registation metadata follows:</p>
    <ul style="list-style-type: disc">
      <li>Username: <code>{{ .username }}</code></li>
      <li>Email: <code>{{ .email }}</code></li>
      <li>Timestamp: {{ .timestamp }}</li>
    </ul>
  </body>
</html>`,
}

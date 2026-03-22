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

import "github.com/greenpau/go-authcrunch/pkg/credentials"

// SendInput is input for Provider.Send function.
type SendInput struct {
	Subject     string                         `json:"subject,omitempty" xml:"subject,omitempty" yaml:"subject,omitempty"`
	Body        string                         `json:"body,omitempty" xml:"body,omitempty" yaml:"body,omitempty"`
	Recipients  []string                       `json:"recipients,omitempty" xml:"recipients,omitempty" yaml:"recipients,omitempty"`
	Credentials *credentials.GenericCredential `json:"credentials,omitempty" xml:"credentials,omitempty" yaml:"credentials,omitempty"`
}

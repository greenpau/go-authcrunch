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
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileProviderSendInput is input for FileProvider.Send function.
type FileProviderSendInput struct {
	Subject    string   `json:"subject,omitempty" xml:"subject,omitempty" yaml:"subject,omitempty"`
	Body       string   `json:"body,omitempty" xml:"body,omitempty" yaml:"body,omitempty"`
	Recipients []string `json:"recipients,omitempty" xml:"recipients,omitempty" yaml:"recipients,omitempty"`
}

// Send writes a message to a file system.
func (p *FileProvider) Send(req *FileProviderSendInput) error {
	fileInfo, err := os.Stat(p.RootDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.ErrMessagingProviderDir.WithArgs(err)
		}
		if err := os.MkdirAll(p.RootDir, 0700); err != nil {
			return errors.ErrMessagingProviderDir.WithArgs(err)
		}
	}
	if fileInfo != nil && !fileInfo.IsDir() {
		return errors.ErrMessagingProviderDir.WithArgs(p.RootDir + "is not a directory")
	}

	msgID := util.GetRandomString(64)
	fp := filepath.Join(p.RootDir, msgID[:32]+".eml")

	msg := "MIME-Version: 1.0\n"
	msg += "Date: " + time.Now().Format(time.RFC1123Z) + "\n"
	msg += "Subject: " + req.Subject + "\n"
	msg += "Thread-Topic: Account Registration." + "\n"
	msg += "Message-ID: <" + msgID + ">" + "\n"
	msg += `To: ` + strings.Join(req.Recipients, ", ") + "\n"

	msg += "Content-Transfer-Encoding: quoted-printable" + "\n"
	msg += `Content-Type: text/html; charset="utf-8"` + "\n"

	msg += "\r\n" + req.Body

	if err := ioutil.WriteFile(fp, []byte(msg), 0600); err != nil {
		return errors.ErrMessagingProviderSend.WithArgs(err)
	}
	return nil
}

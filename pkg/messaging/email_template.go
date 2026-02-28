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
	"crypto/sha1"
	"embed"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
)

var (
	//go:embed email_templates
	emailTemplatesFileSystem embed.FS

	// EmailTemplates is an instance of StaticAssetLibrary containing HTML templates for email messaging.
	EmailTemplates *ui.StaticAssetLibrary
)

func init() {
	var err error
	EmailTemplates, err = NewEmailTemplatesLibrary()
	if err != nil {
		panic(err)
	}
}

// NewEmailTemplatesLibrary returns an instance of StaticAssetLibrary.
func NewEmailTemplatesLibrary() (*ui.StaticAssetLibrary, error) {
	sal := ui.CreateStaticAssetLibrary()

	filePaths, err := ui.EnumerateEmbedFs(emailTemplatesFileSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate email templates file system: %s", err)
	}
	for _, filePath := range filePaths {
		b, err := emailTemplatesFileSystem.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("email template asset %s reading error: %s", filePath, err)
		}
		path := filePath
		oldPrefix := "email_templates/"
		newPrefix := ""
		if strings.HasPrefix(path, oldPrefix) {
			path = newPrefix + strings.TrimPrefix(path, oldPrefix)
		}
		oldSuffix := ".template"
		newSuffix := ""
		if strings.HasSuffix(path, oldSuffix) {
			path = newSuffix + strings.TrimSuffix(path, oldSuffix)
		}
		item := &ui.StaticAsset{
			Path:        path,
			FsPath:      filePath,
			ContentType: "text/plain",
			Content:     string(b),
		}
		h := sha1.New()
		io.WriteString(h, item.Content)
		item.Checksum = base64.URLEncoding.EncodeToString(h.Sum(nil))
		sal.UpdateAsset(path, item)
	}
	return sal, nil
}

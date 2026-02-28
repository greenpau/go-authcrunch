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

package ui

import (
	"crypto/sha1"
	"embed"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

var (
	//go:embed page_templates
	pageTemplatesFileSystem embed.FS

	// PageTemplates is an instance of StaticAssetLibrary containing HTML templates for the pages of the portal.
	PageTemplates *StaticAssetLibrary
)

func init() {
	var err error
	PageTemplates, err = NewPageTemplatesLibrary()
	if err != nil {
		panic(err)
	}
}

// NewPageTemplatesLibrary returns an instance of StaticAssetLibrary.
func NewPageTemplatesLibrary() (*StaticAssetLibrary, error) {
	sal := &StaticAssetLibrary{}
	sal.items = make(map[string]*StaticAsset)

	filePaths, err := EnumerateEmbedFs(pageTemplatesFileSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate page templates file system: %s", err)
	}
	for _, filePath := range filePaths {
		b, err := pageTemplatesFileSystem.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("page template asset %s reading error: %s", filePath, err)
		}
		ct, err := getContentType(filePath)
		if err != nil {
			return nil, fmt.Errorf("page template asset %s getting content type: %s", filePath, err)
		}
		path := filePath
		oldPrefix := "page_templates/"
		newPrefix := ""
		if strings.HasPrefix(path, oldPrefix) {
			path = newPrefix + strings.TrimPrefix(path, oldPrefix)
		}
		oldSuffix := ".template"
		newSuffix := ""
		if strings.HasSuffix(path, oldSuffix) {
			path = newSuffix + strings.TrimSuffix(path, oldSuffix)
		}
		item := &StaticAsset{
			Path:        path,
			FsPath:      filePath,
			ContentType: ct,
			Content:     string(b),
		}
		h := sha1.New()
		io.WriteString(h, item.Content)
		item.Checksum = base64.URLEncoding.EncodeToString(h.Sum(nil))
		sal.items[path] = item
	}
	return sal, nil
}

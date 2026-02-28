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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	//go:embed core
	coreFileSystem embed.FS

	// StaticAssets is an instance of StaticAssetLibrary containing plain HTML.
	StaticAssets *StaticAssetLibrary

	// AppAssets is an instance of StaticAssetLibrary containing React Apps.
	AppAssets *StaticAssetLibrary
)

// StaticAsset is a single static web asset.
type StaticAsset struct {
	Path           string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	FsPath         string `json:"fs_path,omitempty" xml:"fs_path,omitempty" yaml:"fs_path,omitempty"`
	Restricted     bool   `json:"restricted,omitempty" xml:"restricted,omitempty" yaml:"restricted,omitempty"`
	ContentType    string `json:"content_type,omitempty" xml:"content_type,omitempty" yaml:"content_type,omitempty"`
	Content        string `json:"content,omitempty" xml:"content,omitempty" yaml:"content,omitempty"`
	EncodedContent string `json:"encoded_content,omitempty" xml:"encoded_content,omitempty" yaml:"encoded_content,omitempty"`
	Checksum       string `json:"checksum,omitempty" xml:"checksum,omitempty" yaml:"checksum,omitempty"`
}

// StaticAssetLibrary contains a collection of static assets.
type StaticAssetLibrary struct {
	items map[string]*StaticAsset
}

func init() {
	var err error
	StaticAssets, err = NewStaticAssetLibrary()
	if err != nil {
		panic(err)
	}
	AppAssets, err = NewAppAssetLibrary()
	if err != nil {
		panic(err)
	}
}

func getContentType(filePath string) (string, error) {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".template":
		return "text/plain", nil
	case ".html":
		return "text/html", nil
	case ".ttf":
		return "font/ttf", nil
	case ".woff":
		return "font/woff", nil
	case ".woff2":
		return "font/woff2", nil
	case ".ico":
		return "image/x-icon", nil
	case ".js":
		return "application/javascript", nil
	case ".css":
		return "text/css", nil
	case ".eot":
		return "application/vnd.ms-fontobject", nil
	case ".svg":
		return "image/svg+xml", nil
	case ".jpg", ".jpeg":
		return "image/jpeg", nil
	case ".png":
		return "image/png", nil
	case ".gif":
		return "image/gif", nil
	case ".json":
		return "application/json", nil
	case ".txt":
		return "text/plain", nil
	case ".xml":
		return "application/xml", nil
	default:
		return "", fmt.Errorf("extension %q is not supported", ext)
	}
}

// NewAppAssetLibrary returns an instance of StaticAssetLibrary.
func NewAppAssetLibrary() (*StaticAssetLibrary, error) {
	sal := &StaticAssetLibrary{}
	sal.items = make(map[string]*StaticAsset)
	for path, embedPath := range embedPages {
		b, err := embedFileSystem.ReadFile(embedPath)
		if err != nil {
			return nil, fmt.Errorf("app asset %s reading error: %s", embedPath, err)
		}
		ct, err := getContentType(embedPath)
		if err != nil {
			return nil, fmt.Errorf("app asset %s getting content type: %s", embedPath, err)
		}
		item := &StaticAsset{
			Path:        path,
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

// EnumerateEmbedFs returns a slice of all file paths within the embedded filesystem.
func EnumerateEmbedFs(embedFs embed.FS) ([]string, error) {
	var filePaths []string

	// "." is the root of the embedded filesystem
	err := fs.WalkDir(embedFs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return filePaths, nil
}

// CreateStaticAssetLibrary returns an instance of StaticAssetLibrary.
func CreateStaticAssetLibrary() *StaticAssetLibrary {
	sal := &StaticAssetLibrary{}
	sal.items = make(map[string]*StaticAsset)
	return sal
}

// NewStaticAssetLibrary returns an instance of StaticAssetLibrary.
func NewStaticAssetLibrary() (*StaticAssetLibrary, error) {
	sal := CreateStaticAssetLibrary()

	filePaths, err := EnumerateEmbedFs(coreFileSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate core file system: %s", err)
	}
	for _, filePath := range filePaths {
		b, err := coreFileSystem.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("core asset %s reading error: %s", filePath, err)
		}
		ct, err := getContentType(filePath)
		if err != nil {
			return nil, fmt.Errorf("core asset %s getting content type: %s", filePath, err)
		}
		path := filePath
		oldPrefix := "core/"
		newPrefix := "assets/"
		if strings.HasPrefix(path, oldPrefix) {
			path = newPrefix + strings.TrimPrefix(path, oldPrefix)
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

// GetAsset returns an asset from path
func (sal *StaticAssetLibrary) GetAsset(path string) (*StaticAsset, error) {
	if item, exists := sal.items[path]; exists {
		return item, nil
	}
	return nil, fmt.Errorf("static asset %s not found", path)
}

// AddAsset adds asset to StaticAssetLibrary
func (sal *StaticAssetLibrary) AddAsset(path, contentType, fsPath string) error {
	rawContent, err := os.ReadFile(fsPath)
	if err != nil {
		return fmt.Errorf("failed to load asset file %s: %s", fsPath, err)
	}
	item := &StaticAsset{
		Path:           path,
		ContentType:    contentType,
		EncodedContent: base64.StdEncoding.EncodeToString(rawContent),
	}
	s, err := base64.StdEncoding.DecodeString(item.EncodedContent)
	if err != nil {
		return fmt.Errorf("static asset %s decoding error: %s", path, err)
	}
	item.Content = string(s)
	h := sha1.New()
	io.WriteString(h, item.Content)
	item.Checksum = base64.URLEncoding.EncodeToString(h.Sum(nil))
	sal.items[path] = item
	return nil
}

// GetAssetCount returns the total number of static assets in the library.
func (sal *StaticAssetLibrary) GetAssetCount() int {
	return len(sal.items)
}

// GetAssetPaths returns a slice of all asset paths, sorted alphanumerically.
func (sal *StaticAssetLibrary) GetAssetPaths() []string {
	paths := make([]string, 0, len(sal.items))
	for path := range sal.items {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// HasAsset checks if an asset exists in the library by its path.
func (sal *StaticAssetLibrary) HasAsset(path string) bool {
	// If the map is nil, we safely return false
	if sal.items == nil {
		return false
	}

	_, exists := sal.items[path]
	return exists
}

// UpdateAsset adds or updates an asset in the library.
func (sal *StaticAssetLibrary) UpdateAsset(path string, item *StaticAsset) {
	if sal.items == nil {
		sal.items = make(map[string]*StaticAsset)
	}
	sal.items[path] = item
}

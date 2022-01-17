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

package identity

import (
	"image"
)

// Image is base64 image
type Image struct {
	Title string `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	// Encoded Base64 string
	Body   string       `json:"body,omitempty" xml:"body,omitempty" yaml:"body,omitempty"`
	Config image.Config `json:"config,omitempty" xml:"config,omitempty" yaml:"config,omitempty"`
	Path   string       `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
}

// NewImage returns an instance of Image.
func NewImage() *Image {
	return &Image{}
}

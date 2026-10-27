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

import "embed"

// These directories are imported by make ui-apps from a portable UI export.
// all: also retains Vite assets whose basenames begin with an underscore.
//
//go:embed all:profile all:operator all:documents
var embedFileSystem embed.FS

// ApplicationBaseMarker is replaced only in an app's HTML entry by the portal.
const ApplicationBaseMarker = "__AUTHCRUNCH_APP_BASE_PATH__"

// ApplicationBaseTag is the sole deployment-dependent fragment in app exports.
const ApplicationBaseTag = `<base href="` + ApplicationBaseMarker + `" />`

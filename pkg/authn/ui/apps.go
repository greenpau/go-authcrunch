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
	"embed"
)

var (
	//go:embed profile
	embedFileSystem embed.FS
	embedPages      = map[string]string{
		"profile/":                           "profile/index.html",
		"profile/fonts/Inter-Black.ttf":      "profile/fonts/Inter-Black.ttf",
		"profile/fonts/Inter-Bold.ttf":       "profile/fonts/Inter-Bold.ttf",
		"profile/fonts/Inter-ExtraBold.ttf":  "profile/fonts/Inter-ExtraBold.ttf",
		"profile/fonts/Inter-ExtraLight.ttf": "profile/fonts/Inter-ExtraLight.ttf",
		"profile/fonts/Inter-Light.ttf":      "profile/fonts/Inter-Light.ttf",
		"profile/fonts/Inter-Medium.ttf":     "profile/fonts/Inter-Medium.ttf",
		"profile/fonts/Inter-Regular.ttf":    "profile/fonts/Inter-Regular.ttf",
		"profile/fonts/Inter-SemiBold.ttf":   "profile/fonts/Inter-SemiBold.ttf",
		"profile/fonts/Inter-Thin.ttf":       "profile/fonts/Inter-Thin.ttf",
		"profile/fonts/fonts.css":            "profile/fonts/fonts.css",
		"profile/images/banner.jpg":          "profile/images/banner.jpg",
		"profile/assets/index-DLdtk2Ib.css":  "profile/assets/index-DLdtk2Ib.css",
		"profile/assets/index-DOtSzC14.js":   "profile/assets/index-DOtSzC14.js",
		"profile/favicon.ico":                "profile/favicon.ico",
		"profile/logo192.png":                "profile/logo192.png",
		"profile/logo512.png":                "profile/logo512.png",
		"profile/manifest.json":              "profile/manifest.json",
		"profile/robots.txt":                 "profile/robots.txt",
		"profile/index.html":                 "profile/index.html",
	}
)

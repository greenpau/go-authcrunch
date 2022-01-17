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

// Link represents a single HTML link.
type Link struct {
	Link          string `json:"link,omitempty" xml:"link,omitempty" yaml:"link,omitempty"`
	Title         string `json:"title,omitempty" xml:"title,omitempty" yaml:"title,omitempty"`
	Style         string `json:"style,omitempty" xml:"style,omitempty" yaml:"style,omitempty"`
	OpenNewWindow bool   `json:"open_new_window,omitempty" xml:"open_new_window,omitempty" yaml:"open_new_window,omitempty"`
	Target        string `json:"target,omitempty" xml:"target,omitempty" yaml:"target,omitempty"`
	TargetEnabled bool   `json:"target_enabled,omitempty" xml:"target_enabled,omitempty" yaml:"target_enabled,omitempty"`
	IconName      string `json:"icon_name,omitempty" xml:"icon_name,omitempty" yaml:"icon_name,omitempty"`
	IconEnabled   bool   `json:"icon_enabled,omitempty" xml:"icon_enabled,omitempty" yaml:"icon_enabled,omitempty"`
}

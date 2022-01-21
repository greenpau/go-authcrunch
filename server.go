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

package aaasf

import (
	"github.com/greenpau/aaasf/pkg/authn"
	// "github.com/greenpau/aaasf/pkg/authz"
)

// Server represents AAA SF server.
type Server struct {
	Config  *Config         `json:"config,omitempty" xml:"config,omitempty" yaml:"config,omitempty"`
	Portals []*authn.Portal `json:"portals,omitempty" xml:"portals,omitempty" yaml:"portals,omitempty"`
}

// NewServer returns an instance of Server.
func NewServer(c *Config) *Server {
	return &Server{
		Config: c,
	}
}

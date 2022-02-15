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

package main

import (
	"bytes"
	fileutil "github.com/greenpau/go-authcrunch/pkg/util/file"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

// User represents input user identity.
type User struct {
	Username string   `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Password string   `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	Name     string   `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Email    string   `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Roles    []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
}

func addUser(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	wr.logger.Debug("adding user")

	b, err := fileutil.ReadFileBytes(c.String("batch"))
	if err != nil {
		return err
	}
	for _, entry := range bytes.Split(b, []byte("\n")) {
		if !bytes.HasPrefix(entry, []byte("{")) {
			// fmt.Fprintf(os.Stdout, string(b)+"\n")
		}
		wr.logger.Debug("user entry", zap.String("entry", string(entry)))
	}
	return nil
}

func listUsers(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}
	wr.logger.Debug("listing users")

	return nil
}

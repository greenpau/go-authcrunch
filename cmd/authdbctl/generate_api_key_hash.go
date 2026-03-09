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
	"fmt"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"github.com/urfave/cli/v2"
)

func generateAPIKeyHash(c *cli.Context) error {
	dbPath := c.String("db-path")
	cost := c.Int("cost")

	if dbPath == "" {
		dbPath = ":memory:"
	}
	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Cost: %d\n", cost)
	fmt.Printf("Status: Generating hash for API key\n")

	params := make(map[string]interface{})
	params["cost"] = cost

	secret := util.GetRandomString(72)
	p, err := identity.NewPasswordWithOptions(secret, "api", "bcrypt", params)
	if err != nil {
		return err
	}

	fmt.Printf("secret: %s\n", secret)
	fmt.Printf("api key %s \"%s:%d:%s\"\n", string(secret[:24]), p.Algorithm, p.Cost, p.Hash)

	return nil
}

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
	"syscall"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

func generatePasswordHash(c *cli.Context) error {
	password := c.String("password")
	dbPath := c.String("db-path")
	cost := c.Int("cost")

	if password == "" {
		fmt.Print("Enter Password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = string(bytePassword)
		fmt.Println()
	}

	if len(password) < 6 {
		return fmt.Errorf("password is too short: must be at least 6 characters (got %d)", len(password))
	}

	if dbPath == "" {
		dbPath = ":memory:"
	}
	fmt.Printf("Database: %s\n", dbPath)
	fmt.Printf("Cost: %d\n", cost)
	maskedPassword := fmt.Sprintf("%s...%s", password[:2], password[len(password)-2:])
	fmt.Printf("Status: Generating hash for password %s (length %d)\n", maskedPassword, len(password))

	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		return err
	}

	if err := db.CheckPolicyCompliance("foo", password); err != nil {
		return err
	}

	params := make(map[string]interface{})
	if dbPath == ":memory:" {
		params["cost"] = cost
	}

	p, err := identity.NewPasswordWithOptions(password, "generic", "bcrypt", params)
	if err != nil {
		return err
	}

	fmt.Printf("password \"%s:%d:%s\"\n", p.Algorithm, p.Cost, p.Hash)

	return nil
}

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
	"strconv"
	"syscall"

	"github.com/urfave/cli/v2"
	"golang.org/x/term"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	passwordparser "github.com/greenpau/go-authcrunch/pkg/identity/password/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func generatePasswordHash(c *cli.Context) error {
	password := c.String("password")
	dbPath := c.String("db-path")
	algorithm := c.String("algorithm")
	if algorithm == "" {
		algorithm = identity.PasswordAlgorithmBcrypt
	}
	statements := []string{cfgutil.EncodeArgs([]string{"algorithm", algorithm})}
	for _, name := range []string{"cost", "memory", "iterations", "parallelism"} {
		if c.IsSet(name) || (name == "cost" && algorithm == identity.PasswordAlgorithmBcrypt) {
			statements = append(statements, cfgutil.EncodeArgs([]string{name, strconv.Itoa(c.Int(name))}))
		}
	}
	config, err := passwordparser.NewPasswordHashConfigFromDirectives(statements)
	if err != nil {
		return err
	}

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
	fmt.Printf("Algorithm: %s\n", config.Algorithm)
	fmt.Printf("Status: Generating password hash (length %d)\n", len(password))

	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		return err
	}

	if err := db.CheckPasswordPolicyCompliance(password); err != nil {
		return err
	}

	p, err := identity.NewPasswordWithConfig(password, "generic", config)
	if err != nil {
		return err
	}

	fmt.Printf("password %q\n", p.EncodedHash())

	return nil
}

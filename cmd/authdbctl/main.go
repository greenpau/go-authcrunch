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
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/greenpau/versioned"
)

var (
	app        *versioned.PackageManager
	appVersion string
	gitBranch  string
	gitCommit  string
	buildUser  string
	buildDate  string
	sh         *cli.App
)

// getConfigPath returns a cross-platform path for config files.
// It uses ~/.config/authdbctl/... on Unix and %USERPROFILE%\.config\authdbctl\... on Windows.
func getConfigPath(fileName string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to relative path if home dir cannot be determined
		return filepath.Join(".config", "authdbctl", fileName)
	}
	return filepath.Join(home, ".config", "authdbctl", fileName)
}

func init() {
	app = versioned.NewPackageManager("authdbctl")
	app.Description = "AuthDB management client"
	app.Documentation = "https://github.com/greenpau/go-authcrunch/"
	app.SetVersion(appVersion, "1.1.32")
	app.SetGitBranch(gitBranch, "main")
	app.SetGitCommit(gitCommit, "v1.1.31-3-gc6e200a")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")

	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Fprintf(os.Stdout, "%s\n", app.Banner())
	}

	defaultConfigPath := getConfigPath("config.yaml")
	defaultTokenPath := getConfigPath("token.jwt")

	sh = cli.NewApp()
	sh.Name = app.Name
	sh.Version = app.Version
	sh.Usage = app.Description
	sh.Description = app.Documentation
	sh.HideHelp = false
	sh.HideVersion = false
	sh.Flags = append(sh.Flags, &cli.StringFlag{
		Name:        "config",
		Aliases:     []string{"c"},
		Usage:       "Sets `PATH` to configuration file",
		Value:       defaultConfigPath,
		DefaultText: defaultConfigPath,
		EnvVars:     []string{"AUTHDBCTL_CONFIG_PATH"},
	})
	sh.Flags = append(sh.Flags, &cli.StringFlag{
		Name:        "token-path",
		Usage:       "Sets `PATH` to token file",
		Value:       defaultTokenPath,
		DefaultText: defaultTokenPath,
		EnvVars:     []string{"AUTHDBCTL_TOKEN_PATH"},
	})
	sh.Flags = append(sh.Flags, &cli.StringFlag{
		Name:        "format",
		Usage:       "Sets `NAME` of the output format",
		Value:       `json`,
		DefaultText: `json`,
		EnvVars:     []string{"AUTHDBCTL_OUTPUT_FORMAT"},
	})
	sh.Flags = append(sh.Flags, &cli.BoolFlag{
		Name:  "debug",
		Usage: "Enabled debug logging",
	})
	sh.Flags = append(sh.Flags, &cli.IntFlag{
		Name:    "retries",
		Aliases: []string{"r"},
		Usage:   "Maximum number of retry attempts for network calls",
		Value:   3, // Default value
		EnvVars: []string{"AUTHDBCTL_MAX_RETRIES"},
	})
	sh.Flags = append(sh.Flags, &cli.StringFlag{
		Name:    "access-token-name",
		Usage:   "Sets the `NAME` of the access token key in the Authorization header",
		Value:   "authp_access_token",
		EnvVars: []string{"AUTHDBCTL_TOKEN_NAME"},
	})
	sh.Flags = append(sh.Flags, &cli.DurationFlag{
		Name:    "retry-interval",
		Usage:   "Interval between retries (e.g., 500ms, 1s, 5s)",
		Value:   250 * time.Millisecond,
		EnvVars: []string{"AUTHDBCTL_RETRY_INTERVAL"},
	})
	sh.Commands = []*cli.Command{
		{
			Name:   "connect",
			Usage:  "connect to auth portal and obtain access token",
			Action: connect,
		},
		{
			Name:   "metadata",
			Usage:  "fetch metadata",
			Action: metadata,
		},
		{
			Name:        "add",
			Usage:       "add database objects",
			Subcommands: addSubcmd,
		},
		{
			Name:        "delete",
			Usage:       "delete database objects",
			Subcommands: deleteSubcmd,
		},
		{
			Name:        "update",
			Usage:       "update database objects",
			Subcommands: updateSubcmd,
		},
		{
			Name:        "list",
			Usage:       "list database objects",
			Subcommands: listSubcmd,
		},
		{
			Name:        "info",
			Usage:       "get info about database objects",
			Subcommands: infoSubcmd,
		},
		{
			Name:   "reload",
			Usage:  "reload database",
			Action: reload,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:     "realm",
					Usage:    "The realm to reload",
					Required: true,
				},
			},
		},
		{
			Name:  "generate",
			Usage: "generate objects",
			Subcommands: []*cli.Command{
				{
					Name:  "password",
					Usage: "password management",
					Subcommands: []*cli.Command{
						{
							Name:   "hash",
							Usage:  "generate password hash",
							Action: generatePasswordHash,
							Flags: []cli.Flag{
								&cli.StringFlag{
									Name:     "password",
									Usage:    "The password to hash (insecure, use prompt instead)",
									Required: false,
								},
								&cli.IntFlag{
									Name:        "cost",
									Usage:       "The hashing cost factor",
									Value:       10,
									DefaultText: "10",
								},
								&cli.StringFlag{
									Name:     "db-path",
									Usage:    "Sets `PATH` to the database file",
									Required: false,
								},
							},
						},
					},
				},
				{
					Name:  "api",
					Usage: "api key management",
					Subcommands: []*cli.Command{
						{
							Name:   "key",
							Usage:  "generate api key",
							Action: generateAPIKeyHash,
							Flags: []cli.Flag{
								&cli.IntFlag{
									Name:        "cost",
									Usage:       "The hashing cost factor",
									Value:       10,
									DefaultText: "10",
								},
								&cli.StringFlag{
									Name:     "db-path",
									Usage:    "Sets `PATH` to the database file",
									Required: false,
								},
							},
						},
					},
				},
			},
		},
		systemSubcmd,
	}
}

func main() {
	err := sh.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

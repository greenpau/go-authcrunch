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
	"github.com/urfave/cli/v2"
	"log"
	"os"

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

func init() {
	app = versioned.NewPackageManager("authdbctl")
	app.Description = "AuthDB management client"
	app.Documentation = "https://github.com/greenpau/go-authcrunch/"
	app.SetVersion(appVersion, "1.0.46")
	app.SetGitBranch(gitBranch, "main")
	app.SetGitCommit(gitCommit, "v1.0.45-1-g04ef714")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")

	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Fprintf(os.Stdout, "%s\n", app.Banner())
	}

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
		Value:       `~/.config/authdbctl/config.yaml`,
		DefaultText: `~/.config/authdbctl/config.yaml`,
		EnvVars:     []string{"AUTHDBCTL_CONFIG_PATH"},
	})
	sh.Flags = append(sh.Flags, &cli.StringFlag{
		Name:        "token-path",
		Usage:       "Sets `PATH` to token file",
		Value:       `~/.config/authdbctl/token.jwt`,
		DefaultText: `~/.config/authdbctl/token.jwt`,
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
			Name:        "list",
			Usage:       "list database objects",
			Subcommands: listSubcmd,
		},
	}
}

func main() {
	err := sh.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

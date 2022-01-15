package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
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
	app = versioned.NewPackageManager("aaasfcli")
	app.Description = "AAA SF management client"
	app.Documentation = "https://github.com/greenpau/aaasf/"
	app.SetVersion(appVersion, "1.0.0")
	app.SetGitBranch(gitBranch, "")
	app.SetGitCommit(gitCommit, "")
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
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "Sets path to configuration from `CONFIG_PATH` (default: ~/.config/aaasfcli/config.json)",
		EnvVars: []string{"AUTHDBCTL_CONFIG_PATH"},
	})
}

func main() {
	sh.Run(os.Args)
}

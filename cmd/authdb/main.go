// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

// Command authdb serves AuthCrunch authentication portals without Caddy.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/greenpau/versioned"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/httpserver"
)

var appVersion, gitBranch, gitCommit, buildUser, buildDate string

const maxConfigBytes = 16 << 20

var app *versioned.PackageManager

func init() {
	app = versioned.NewPackageManager("authdb")
	app.Description = "AuthCrunch standalone HTTP server"
	app.Documentation = "https://github.com/greenpau/go-authcrunch/"
	app.SetVersion(appVersion, "1.3.2")
	app.SetGitBranch(gitBranch, "")
	app.SetGitCommit(gitCommit, "")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Fprintln(c.App.Writer, app.Banner())
	}
}

type configuration struct {
	HTTP     *httpserver.Config `json:"http"`
	Security *authcrunch.Config `json:"security"`
}

func main() {
	ctx, stop := newSignalContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "authdb:", err)
		os.Exit(1)
	}
}

func newSignalContext(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
	return newSignalContextWithLifecycle(
		parent,
		func(ch chan<- os.Signal) { signal.Notify(ch, signals...) },
		signal.Stop,
	)
}

func newSignalContextWithLifecycle(parent context.Context, notify, stop func(chan<- os.Signal)) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 1)
	notify(ch)
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			// Restore default handling before publishing cancellation so a second
			// signal cannot be consumed while the server begins graceful draining.
			stop(ch)
			cancel()
		})
	}
	go func() {
		select {
		case <-ch:
			cleanup()
		case <-ctx.Done():
			cleanup()
		}
	}()
	return ctx, cleanup
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return newCLI(stdout, stderr).RunContext(ctx, append([]string{"authdb"}, args...))
}

func newCLI(stdout, stderr io.Writer) *cli.App {
	configPath, debug := "authdb.json", false
	// Fresh flag actions apply root options first, then explicit run options.
	// Only root flags read the environment, so it cannot override a CLI value
	// when the run command is parsed. This also preserves --debug=false.
	flags := func(environment bool) []cli.Flag {
		config := &cli.StringFlag{
			Name: "config", Aliases: []string{"c"}, Usage: "Sets `PATH` to JSON server configuration", Value: "authdb.json",
			Action: func(_ *cli.Context, value string) error { configPath = value; return nil },
		}
		if environment {
			config.EnvVars = []string{"AUTHDB_CONFIG_PATH"}
		}
		return []cli.Flag{
			config,
			&cli.BoolFlag{
				Name: "debug", Usage: "Enable debug logging",
				Action: func(_ *cli.Context, value bool) error { debug = value; return nil },
			},
		}
	}
	return &cli.App{
		Name: app.Name, Version: app.Version, Usage: app.Description, Description: app.Documentation,
		Writer: stdout, ErrWriter: stderr, Flags: flags(true),
		// main owns process exit, including errors returned by built-in help.
		ExitErrHandler: func(*cli.Context, error) {},
		Action: func(c *cli.Context) error {
			if c.NArg() != 0 {
				return fmt.Errorf("unknown command; see 'authdb help'")
			}
			return cli.ShowAppHelp(c)
		},
		Commands: []*cli.Command{
			{
				Name: "run", Usage: "start the AuthCrunch HTTP server", Flags: flags(false),
				Action: func(c *cli.Context) error {
					if c.NArg() != 0 {
						return fmt.Errorf("run does not accept positional arguments")
					}
					return serve(c.Context, configPath, debug, stderr)
				},
			},
			{
				Name: "version", Usage: "print version and build information",
				Action: func(c *cli.Context) error {
					if c.NArg() != 0 {
						return fmt.Errorf("version does not accept positional arguments")
					}
					cli.ShowVersion(c)
					return nil
				},
			},
		},
	}
}

func newLogger(debug bool, output io.Writer) *zap.Logger {
	level := zap.InfoLevel
	if debug {
		level = zap.DebugLevel
	}
	encoder := zap.NewProductionEncoderConfig()
	encoder.EncodeTime = zapcore.ISO8601TimeEncoder
	encoder.TimeKey = "time"
	sink := zapcore.Lock(zapcore.AddSync(output))
	return zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(encoder), sink, level), zap.ErrorOutput(sink))
}

func serve(ctx context.Context, configPath string, debug bool, stderr io.Writer) error {
	config, err := loadConfiguration(configPath)
	if err != nil {
		return err
	}
	logger := newLogger(debug, stderr)
	defer func() { _ = logger.Sync() }()
	listener, err := net.Listen("tcp", config.HTTP.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return httpserver.Serve(ctx, listener, config.HTTP, config.Security, logger)
}

func loadConfiguration(filename string) (*configuration, error) {
	// Opening a named pipe can block before File.Stat is reached. Reject
	// nonregular paths first, then verify the opened file as well.
	info, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("stat server configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return nil, fmt.Errorf("server configuration must be a regular file at most 16 MiB")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open server configuration: %w", err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat server configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBytes {
		return nil, fmt.Errorf("server configuration must be a regular file at most 16 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxConfigBytes+1))
	decoder.DisallowUnknownFields()
	var config configuration
	if err := decoder.Decode(&config); err != nil {
		// Decoder errors can contain caller-supplied keys and secret values.
		return nil, fmt.Errorf("invalid server JSON configuration (check syntax, field names, and types)")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("server configuration must contain exactly one JSON object")
	}
	if err := config.HTTP.Validate(); err != nil {
		return nil, err
	}
	if config.Security == nil {
		return nil, fmt.Errorf("security configuration is required")
	}
	return &config, nil
}

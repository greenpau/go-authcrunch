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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	fileutil "github.com/greenpau/go-authcrunch/pkg/util/file"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Config holds the configuration for the CLI.
type Config struct {
	BaseURL    string `json:"base_url,omitempty" xml:"base_url,omitempty" yaml:"base_url,omitempty"`
	TokenPath  string `json:"token_path,omitempty" xml:"token_path,omitempty" yaml:"token_path,omitempty"`
	Username   string `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Password   string `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	Realm      string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	CookieName string `json:"cookie_name,omitempty" xml:"cookie_name,omitempty" yaml:"cookie_name,omitempty"`
	path       string
	token      string
}

type wrapper struct {
	config *Config
	logger *zap.Logger
}

func (wr *wrapper) configure(c *cli.Context) error {
	cfg := &Config{}
	cfg.path = c.String("config")

	if c.Bool("debug") {
		wr.logger = logutil.NewLogger()
	} else {
		wr.logger = logutil.NewInfoLogger()
	}

	cfgBytes, err := fileutil.ReadFileBytes(cfg.path)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			wr.logger.Debug(
				"configuration file does not exist",
				zap.String("path", cfg.path),
			)
		default:
			return err
		}
	} else {
		if err := yaml.Unmarshal(cfgBytes, cfg); err != nil {
			return err
		}
		cfg.path = c.String("config")
	}

	if cfg.TokenPath == "" && c.String("token-path") != "" {
		cfg.TokenPath = c.String("token-path")
	}

	cfg.TokenPath = fileutil.ExpandPath(cfg.TokenPath)

	if cfg.BaseURL == "" {
		return fmt.Errorf("the base_url configuration not found")
	}

	tokenBytes, err := fileutil.ReadFileBytes(cfg.TokenPath)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			wr.logger.Debug(
				"token file does not exist",
				zap.String("path", cfg.TokenPath),
			)
		default:
			return err
		}
	} else {
		cfg.token = string(parseTokenBytes(tokenBytes))
	}

	for _, s := range []string{"username", "realm"} {
		var skip bool
		switch {
		case (s == "username") && (cfg.Username != ""):
			skip = true
		case (s == "realm") && (cfg.Realm != ""):
			skip = true
		}
		if skip {
			continue
		}
		input, err := wr.readUserInput(s)
		if err != nil {
			return err
		}
		switch s {
		case "username":
			cfg.Username = input
		case "realm":
			cfg.Realm = input
		}
	}

	if cfg.CookieName == "" {
		cfg.CookieName = "access_token"
	}

	wr.logger.Debug(
		"runtime configuration",
		zap.String("config_path", cfg.path),
		zap.String("base_url", cfg.BaseURL),
		zap.String("token_path", cfg.TokenPath),
		zap.String("username", cfg.Username),
		zap.String("realm", cfg.Realm),
	)

	wr.config = cfg
	return nil
}

func parseTokenBytes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	f := func(c rune) bool {
		return unicode.IsSpace(c)
	}
	i := bytes.IndexFunc(b, f)
	if i < 0 {
		return b
	}
	return b[:i]
}

func (wr *wrapper) readUserInput(s string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter %s: ", s)
	input, err := reader.ReadString('\n')
	if err != nil {
		wr.logger.Error(
			"An error occured while reading input. Please try again.",
			zap.Error(err),
		)
		return "", err
	}
	input = strings.TrimSpace(input)
	if len(input) == 0 {
		wr.logger.Error("Empty input. Please try again.")
		return "", fmt.Errorf("empty input")
	}
	return input, nil
}

func (wr *wrapper) commitToken() error {
	fileDir := filepath.Dir(wr.config.TokenPath)

	if _, err := os.Stat(fileDir); os.IsNotExist(err) {
		wr.logger.Error("creating token file directory", zap.String("path", fileDir))
		if err := os.MkdirAll(fileDir, 0700); err != nil {
			return fmt.Errorf("failed creating %q directory: %v", fileDir, err)
		}
	}

	fh, err := os.OpenFile(wr.config.TokenPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed opening %q file: %v", wr.config.TokenPath, err)
	}
	if _, err := fh.WriteString(wr.config.token + "\n"); err != nil {
		return fmt.Errorf("failed writing to %q file: %v", wr.config.TokenPath, err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("failed closing %q file: %v", wr.config.TokenPath, err)
	}

	wr.logger.Debug("wrote token to file", zap.String("path", wr.config.TokenPath))
	return nil
}

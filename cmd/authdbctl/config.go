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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/util"
	fileutil "github.com/greenpau/go-authcrunch/pkg/util/file"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
)

// Config holds CLI file settings alongside reusable authentication settings.
type Config struct {
	authclient.Config `yaml:",inline"`
	TokenPath         string `json:"token_path,omitempty" xml:"token_path,omitempty" yaml:"token_path,omitempty"`
	// CookieName is retained for compatibility with existing configuration files.
	CookieName string `json:"cookie_name,omitempty" xml:"cookie_name,omitempty" yaml:"cookie_name,omitempty"`
}

type wrapper struct {
	config        *Config
	logger        *zap.Logger
	browser       *util.Browser
	authenticator *authclient.Client
	tokenStore    *authclient.FileTokenStore
	credentials   authclient.Credentials
	input         *bufio.Reader
}

func (wr *wrapper) configure(c *cli.Context) error {
	cfg := &Config{}
	configPath := c.String("config")
	if c.Bool("debug") {
		wr.logger = logutil.NewLogger()
	} else {
		wr.logger = logutil.NewInfoLogger()
	}
	cfgBytes, err := fileutil.ReadFileBytes(configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		wr.logger.Debug("configuration file does not exist", zap.String("path", configPath))
	} else if err := yaml.Unmarshal(cfgBytes, cfg); err != nil {
		// YAML conversion errors may contain configured secrets.
		return fmt.Errorf("invalid configuration YAML")
	}
	if cfg.TokenPath == "" {
		cfg.TokenPath = c.String("token-path")
	}
	cfg.TokenPath = fileutil.ExpandPath(cfg.TokenPath)
	if cfg.BaseURL == "" {
		return fmt.Errorf("the base_url configuration not found")
	}
	store, err := authclient.NewFileTokenStore(cfg.TokenPath)
	if err != nil {
		return err
	}
	// A wrapper normally serves one command. Reset state if it is configured again.
	wr.credentials = authclient.Credentials{}
	credentials, err := store.Load()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		wr.logger.Debug("token file does not exist", zap.String("path", cfg.TokenPath))
	} else {
		wr.credentials = *credentials
	}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"username", &cfg.Username},
		{"realm", &cfg.Realm},
	} {
		if field.name == "username" && cfg.APIKey != "" {
			continue
		}
		if *field.value == "" {
			input, err := wr.readUserInput(field.name)
			if err != nil {
				return err
			}
			*field.value = input
		}
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "AUTHP_ACCESS_TOKEN"
	}
	// Preserve legacy precedence: a cached name wins over the CLI fallback.
	if wr.credentials.AccessTokenName != "" {
		cfg.AccessTokenName = wr.credentials.AccessTokenName
	} else if cfg.AccessTokenName == "" {
		cfg.AccessTokenName = c.String("access-token-name")
	}
	if err := cfg.Config.Validate(); err != nil {
		return err
	}
	if wr.credentials.AccessTokenName == "" {
		wr.credentials.AccessTokenName = cfg.AccessTokenName
	}
	authenticator, err := authclient.NewClient(&cfg.Config, authclient.Options{
		Prompt:    wr.promptAuthentication,
		UserAgent: app.Name + "/" + app.Version,
	})
	if err != nil {
		return err
	}
	browser, err := util.NewBrowser()
	if err != nil {
		return err
	}
	wr.config = cfg
	wr.tokenStore = store
	wr.authenticator = authenticator
	wr.browser = browser
	wr.logger.Debug("runtime configuration",
		zap.String("config_path", configPath),
		zap.String("token_path", cfg.TokenPath),
		zap.String("username", cfg.Username),
		zap.String("realm", cfg.Realm),
	)
	return nil
}

func (wr *wrapper) readUserInput(s string) (string, error) {
	if wr.input == nil {
		wr.input = bufio.NewReader(os.Stdin)
	}
	fmt.Printf("Enter %s: ", s)
	input, err := wr.input.ReadString('\n')
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

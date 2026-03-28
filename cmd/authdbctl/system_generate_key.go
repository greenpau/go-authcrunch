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
	"os"

	"github.com/greenpau/go-authcrunch/pkg/system"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var (
	systemGenerateKeySubcmd = &cli.Command{
		Name:  "key",
		Usage: "Generate encryption key",
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:     "output-key-file",
				Usage:    "Path to the output encryption private key file",
				Required: true,
			},
		},
		Action: systemGenerateKey,
	}
)

func systemGenerateKey(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}

	keyFilePath := c.Path("output-key-file")

	wr.logger.Debug("generating private key for system communications",
		zap.String("output_key_file_path", keyFilePath),
	)

	if err := system.GenerateKey(keyFilePath); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Generated and wrote the key to %s\n", keyFilePath)
	return nil
}

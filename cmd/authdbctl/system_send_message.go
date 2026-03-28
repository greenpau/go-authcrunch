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
	systemSendMessageSubcmd = &cli.Command{
		Name:  "message",
		Usage: "Send an encrypted message from a file",
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:     "input-message-file",
				Usage:    "Path to the file containing the message to send",
				Required: true,
			},
			&cli.PathFlag{
				Name:     "encryption-key",
				Usage:    "Path to the file containing the encryption key",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "key-id",
				Usage:    "Key ID for the encryption key",
				Required: true,
			},
		},
		Action: systemSendMessage,
	}
)

func systemSendMessage(c *cli.Context) error {
	wr := new(wrapper)
	if err := wr.configure(c); err != nil {
		return err
	}

	messageFile := c.Path("input-message-file")
	keyFile := c.Path("encryption-key")
	keyID := c.Path("key-id")

	messageData, err := os.ReadFile(messageFile)
	if err != nil {
		return fmt.Errorf("failed to read input message file %q: %w", messageFile, err)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read encryption key file %q: %w", keyFile, err)
	}

	if keyID == "" {
		return fmt.Errorf("key id is emtpy")
	}

	endpointURL := wr.config.BaseURL + "/api/system"
	wr.logger.Debug("sending message to authentication portal",
		zap.String("endpoint_url", endpointURL),
		zap.String("input_message_file_path", messageFile),
		zap.Int("input_message_file_len", len(messageData)),
		zap.String("encryption_key_file_path", keyFile),
		zap.Int("encryption_key_file_len", len(keyData)),
	)

	encryptor, err := system.NewEncryptorFromKey(keyID, keyFile)
	if err != nil {
		return nil
	}

	if _, err := encryptor.EncryptMessage("foo"); err != nil {
		return err
	}

	// var reqData = []byte(`{
	//     "realm": "` + c.String("realm") + `",
	//     "query": "all"
	// }`)

	// respBody, err := wr.doRequestWithRetry(c, http.MethodPost, endpointURL, reqData)
	// if err != nil {
	// 	return fmt.Errorf("failed fetching database %q realm info: %w", c.String("realm"), err)
	// }

	// var data map[string]any
	// if err := json.Unmarshal([]byte(respBody), &data); err != nil {
	// 	return fmt.Errorf("failed to parse JSON response: %v", err)
	// }

	// fmt.Fprintf(os.Stdout, "%s\n", respBody)
	return nil
}

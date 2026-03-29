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
	"net/http"
	"os"
	"strings"

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

	messageFilePath := c.Path("input-message-file")
	keyFilePath := c.Path("encryption-key")
	keyID := c.Path("key-id")

	messageData, err := os.ReadFile(messageFilePath)
	if err != nil {
		return fmt.Errorf("failed to read input message file %q: %w", messageFilePath, err)
	}

	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read encryption key file %q: %w", keyFilePath, err)
	}

	if keyID == "" {
		return fmt.Errorf("key id is emtpy")
	}

	endpointURL := wr.config.BaseURL + "/api/system"
	wr.logger.Debug("sending message to authentication portal",
		zap.String("endpoint_url", endpointURL),
		zap.String("input_message_file_path", messageFilePath),
		zap.Int("input_message_file_len", len(messageData)),
		zap.String("encryption_key_file_path", keyFilePath),
		zap.Int("encryption_key_file_len", len(keyData)),
	)

	encryptor, err := system.NewEncryptorFromKey(keyID, keyFilePath)
	if err != nil {
		return nil
	}

	reqMsg, err := system.ParseMessage(messageData)
	if err != nil {
		return err
	}

	if err := reqMsg.Validate(); err != nil {
		return fmt.Errorf("failed to validate input message: %v", err)
	}

	reqData, err := encryptor.EncryptMessage(reqMsg)
	if err != nil {
		return err
	}

	opts := &requestOpts{
		disableAccessToken: true,
		maxAttempts:        1,
	}

	respBody, err := wr.doRequestWithRetry(c, http.MethodPost, endpointURL, opts, []byte(reqData))
	if err != nil {
		return fmt.Errorf("failed sending system message: %w", err)
	}

	if !strings.HasPrefix(respBody, "v4.local.") {
		return fmt.Errorf("unexpected system message response: %s", respBody)
	}

	respMsg, err := encryptor.DecryptMessage(respBody)
	if err != nil {
		return err
	}

	respMsgMap, err := respMsg.AsMap()
	if err != nil {
		return fmt.Errorf("failed to marshal system message response: %s: %v", respBody, err)
	}

	wr.logger.Debug("received response message from authentication portal",
		zap.String("endpoint_url", endpointURL),
		zap.Any("response", respMsgMap),
	)

	// var data map[string]any
	respData, err := respMsg.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	fmt.Fprintf(os.Stdout, "%s\n", respData)
	return nil
}

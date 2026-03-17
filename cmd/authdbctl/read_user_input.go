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
	"errors"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/term"
)

func (wr *wrapper) readUserInputWithTimeout(prompt string, timeout time.Duration) (string, error) {
	wr.logger.Debug("prompted user for input", zap.String("prompt", prompt), zap.Duration("timeout", timeout))
	fmt.Print(prompt)

	type result struct {
		pw  string
		err error
	}

	resChan := make(chan result, 1)
	fd := int(os.Stdin.Fd())

	go func() {
		byteInput, err := term.ReadPassword(fd)
		resChan <- result{string(byteInput), err}
	}()

	select {
	case res := <-resChan:
		fmt.Println()
		if res.err != nil {
			return "", res.err
		}
		return res.pw, nil

	case <-time.After(timeout):
		wr.logger.Error("user input timed out")
		return "", errors.New("user input timed out")
	}
}

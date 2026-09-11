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
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/term"
)

func (wr *wrapper) readUserInputWithTimeout(ctx context.Context, prompt string, timeout time.Duration) (string, error) {
	wr.logger.Debug("prompted user for input", zap.String("prompt", prompt), zap.Duration("timeout", timeout))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	stdin := os.Stdin
	fd := int(stdin.Fd())
	// Own terminal state in the caller. ReadPassword(fd) restores echo only
	// after input arrives, which leaves the terminal altered on timeout.
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", err
	}
	defer term.Restore(fd, state)
	fmt.Print(prompt)

	type result struct {
		pw  string
		err error
	}

	resChan := make(chan result, 1)
	// The line editor handles hidden input and Ctrl-C/Ctrl-D without changing
	// OS terminal state. A read left pending on cancellation therefore cannot
	// undo the caller's restoration. This command returns after cancellation.
	terminal := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{stdin, io.Discard}, "")
	go func() {
		input, err := terminal.ReadPassword("")
		resChan <- result{input, err}
	}()

	select {
	case res := <-resChan:
		fmt.Println()
		if res.err != nil {
			return "", res.err
		}
		return res.pw, nil

	case <-ctx.Done():
		return "", ctx.Err()
	}
}

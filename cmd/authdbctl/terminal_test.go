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
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

type terminalFixture struct {
	file   *os.File
	input  io.WriteCloser
	output *bufio.Reader
}

func newTerminalFixture(t *testing.T) *terminalFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX pseudo-terminal fixture; command E2E tests still run on Windows")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python 3 is required for the terminal tests, as in repository CI")
	}
	// t.Context is canceled before cleanup; the broker must survive until its
	// cleanup closes the PTY and unblocks any pending terminal read.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	cmd := exec.CommandContext(ctx, python, "-u", "testdata/terminal.py")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr // The fixture's diagnostics never include input values.
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &terminalFixture{input: stdin, output: bufio.NewReader(stdout)}
	t.Cleanup(func() {
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("terminal fixture failed: %v", err)
		}
		if f.file != nil {
			f.file.Close()
		}
		cancel()
	})
	name, err := f.output.ReadString('\n')
	if err != nil {
		t.Fatal("terminal fixture did not return its device")
	}
	f.file, err = os.OpenFile(strings.TrimSpace(name), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *terminalFixture) send(t *testing.T, value string) {
	t.Helper()
	if err := json.NewEncoder(f.input).Encode(map[string]string{"command": "input", "value": value}); err != nil {
		t.Fatal("failed to send terminal input")
	}
}

func (f *terminalFixture) expect(t *testing.T, want string) {
	t.Helper()
	got, err := f.output.ReadString('\n')
	if err != nil || strings.TrimSpace(got) != want {
		t.Fatal("terminal input or echo assertion failed")
	}
}

func (f *terminalFixture) assertRestored(t *testing.T) {
	t.Helper()
	if err := json.NewEncoder(f.input).Encode(map[string]string{"command": "echo"}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, "on")
}

func useStdin(t *testing.T, file *os.File) {
	t.Helper()
	previous := os.Stdin
	os.Stdin = file
	t.Cleanup(func() { os.Stdin = previous })
}

func TestAuthenticationTerminalPrompts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		kind        authclient.PromptKind
		input, want string
		wantErr     bool
	}{
		{"password", authclient.PromptPassword, "synthetic-terminal-password", "synthetic-terminal-password", false},
		{"TOTP", authclient.PromptTOTP, "123456", "123456", false},
		{"MFA TOTP", authclient.PromptMFA, " 1 ", "totp", false},
		{"MFA WebAuthn", authclient.PromptMFA, "2", "webauthn", false},
		{"invalid MFA", authclient.PromptMFA, "3", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terminal := newTerminalFixture(t)
			useStdin(t, terminal.file)
			wr := &wrapper{logger: zap.NewNop()}
			terminal.send(t, tc.input)
			got, err := wr.promptAuthentication(t.Context(), tc.kind)
			terminal.expect(t, "sent")
			terminal.assertRestored(t)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatal("incorrect prompt result")
			}
		})
	}
}

func TestAuthenticationPromptErrors(t *testing.T) {
	wr := &wrapper{logger: zap.NewNop()}
	if _, err := wr.promptAuthentication(t.Context(), authclient.PromptKind("unknown")); !errors.Is(err, authclient.ErrUnsupportedChallenge) {
		t.Fatal("unknown prompt accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := wr.promptAuthentication(ctx, authclient.PromptPassword); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := wr.readUserInputWithTimeout(t.Context(), "input", -time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	useStdin(t, f)
	if _, err := wr.promptAuthentication(t.Context(), authclient.PromptPassword); err == nil {
		t.Fatal("non-terminal input accepted as a hidden prompt")
	}
}

func TestReadUserInput(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        []string
		wantErr     bool
	}{
		{"multiple lines", "  jsmith  \nlocal\n", []string{"jsmith", "local"}, false},
		{"empty", "  \n", []string{""}, true},
		{"EOF", "partial", []string{""}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "input")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := io.WriteString(f, tc.input); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			useStdin(t, f)
			wr := &wrapper{logger: zap.NewNop()}
			_, _ = captureCommand(t, func(*cli.Context) error {
				for _, want := range tc.want {
					got, err := wr.readUserInput("identity")
					if (err != nil) != tc.wantErr || got != want {
						t.Fatalf("unexpected identity input result: %q, %v", got, err)
					}
				}
				return nil
			}, nil)
		})
	}
}

func TestTerminalTimeoutRestoresEcho(t *testing.T) {
	terminal := newTerminalFixture(t)
	useStdin(t, terminal.file)
	wr := &wrapper{logger: zap.NewNop()}
	_, err := captureCommand(t, func(*cli.Context) error {
		_, err := wr.readUserInputWithTimeout(t.Context(), "Timeout test: ", 50*time.Millisecond)
		return err
	}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	terminal.assertRestored(t)
}

func TestTerminalInterrupts(t *testing.T) {
	for _, input := range []string{"\x03", "\x04"} {
		t.Run("control "+string(rune('0'+input[0])), func(t *testing.T) {
			terminal := newTerminalFixture(t)
			useStdin(t, terminal.file)
			terminal.send(t, input)
			wr := &wrapper{logger: zap.NewNop()}
			_, err := wr.readUserInputWithTimeout(t.Context(), "Interrupt test: ", time.Second)
			terminal.expect(t, "sent")
			terminal.assertRestored(t)
			if !errors.Is(err, io.EOF) {
				t.Fatalf("terminal interrupt returned %v", err)
			}
		})
	}
}

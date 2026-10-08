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

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/greenpau/go-authcrunch/internal/openapi"
	"gopkg.in/yaml.v3"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openapi:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("openapi", flag.ContinueOnError)
	root := flags.String("root", ".", "AuthCrunch repository root")
	listen := flags.String("listen", "127.0.0.1:8080", "documentation HTTP listen address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	action := "generate"
	if flags.NArg() == 1 {
		action = flags.Arg(0)
	} else if flags.NArg() > 1 {
		return fmt.Errorf("expected generate, check, serve, sources, or artifact")
	}
	if action != "generate" && action != "check" && action != "serve" && action != "sources" && action != "artifact" {
		return fmt.Errorf("unknown action %q", action)
	}
	repository, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	repository, err = filepath.EvalSymlinks(repository)
	if err != nil {
		return err
	}
	if action == "sources" {
		sources, err := openapi.Sources(ctx, repository)
		if err != nil {
			return err
		}
		return yaml.NewEncoder(os.Stdout).Encode(sources)
	}
	if err := openapi.CheckSources(ctx, repository); err != nil {
		return err
	}
	directory := filepath.Join(repository, "assets/openapi")
	physical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	if physical != directory {
		return fmt.Errorf("assets/openapi must not use symlinks")
	}
	data, err := openapi.Bundle(filepath.Join(directory, "content"))
	if err != nil {
		return err
	}
	if err := openapi.CheckVersion(repository, data); err != nil {
		return err
	}
	if action == "artifact" {
		if err := openapi.WriteArtifact(filepath.Join(directory, "generated/artifact"), data); err != nil {
			return err
		}
		fmt.Println("Generated assets/openapi/generated/artifact/openapi.{json,yaml}")
		return nil
	}
	if action == "check" {
		previous, err := os.ReadFile(filepath.Join(directory, "generated/openapi.json"))
		if err != nil || !bytes.Equal(previous, data) {
			return fmt.Errorf("generated reference is absent or stale; run make openapi")
		}
		fmt.Println("OpenAPI sources and generated reference are current")
		return nil
	}
	if err := openapi.Write(filepath.Join(directory, "generated"), data); err != nil {
		return err
	}
	if action == "generate" {
		fmt.Println("Generated assets/openapi/generated/openapi.json")
		return nil
	}
	docroot, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer docroot.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: openapi.Handler(docroot), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Printf("OpenAPI reference: http://%s/ (Ctrl-C to stop)\n", listener.Addr())
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

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

package authz_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestAuthorizationRedirectBrowserWait(t *testing.T) {
	for _, tc := range []struct {
		name     string
		signal   func(chan struct{}, chan struct{}, chan error, context.CancelFunc)
		message  string
		cause    error
		duration time.Duration
	}{
		{
			name: "slow startup preserves journey budget",
			signal: func(started, completed chan struct{}, _ chan error, _ context.CancelFunc) {
				time.Sleep(40 * time.Second)
				close(started)
				time.Sleep(14 * time.Second)
				close(completed)
			},
			duration: 54 * time.Second,
		},
		{
			name:     "startup deadline",
			signal:   func(chan struct{}, chan struct{}, chan error, context.CancelFunc) {},
			message:  "Chrome startup did not complete",
			cause:    context.DeadlineExceeded,
			duration: 45 * time.Second,
		},
		{
			name: "journey deadline",
			signal: func(started, _ chan struct{}, _ chan error, _ context.CancelFunc) {
				close(started)
			},
			message:  "Chrome redirect journey did not complete",
			cause:    context.DeadlineExceeded,
			duration: 15 * time.Second,
		},
		{
			name: "startup cancellation",
			signal: func(_, _ chan struct{}, _ chan error, cancel context.CancelFunc) {
				time.Sleep(time.Second)
				cancel()
			},
			message:  "Chrome startup did not complete",
			cause:    context.Canceled,
			duration: time.Second,
		},
		{
			name: "journey cancellation",
			signal: func(started, _ chan struct{}, _ chan error, cancel context.CancelFunc) {
				close(started)
				time.Sleep(time.Second)
				cancel()
			},
			message:  "Chrome redirect journey did not complete",
			cause:    context.Canceled,
			duration: time.Second,
		},
		{
			name: "startup process failure",
			signal: func(_, _ chan struct{}, exited chan error, _ context.CancelFunc) {
				time.Sleep(time.Second)
				exited <- errors.New("fixture exit")
			},
			message:  "Chrome exited before startup completed (exit error: fixture exit)",
			duration: time.Second,
		},
		{
			name: "startup clean process exit",
			signal: func(_, _ chan struct{}, exited chan error, _ context.CancelFunc) {
				time.Sleep(time.Second)
				exited <- nil
			},
			message:  "Chrome exited before startup completed",
			duration: time.Second,
		},
		{
			name: "journey process failure",
			signal: func(started, _ chan struct{}, exited chan error, _ context.CancelFunc) {
				close(started)
				time.Sleep(time.Second)
				exited <- errors.New("fixture exit")
			},
			message:  "Chrome exited before redirect journey completed (exit error: fixture exit)",
			duration: time.Second,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Virtual time verifies the actual CI budgets without slow sleeps or
			// scheduler-dependent timing assertions in the regression suite.
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
				defer cancel()
				started, completed := make(chan struct{}), make(chan struct{})
				exited := make(chan error, 1)
				go tc.signal(started, completed, exited, cancel)
				start := time.Now()
				err := waitForAuthorizationRedirectBrowser(ctx, started, completed, exited)
				if tc.message == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.message) {
					t.Fatalf("error = %v, want %q", err, tc.message)
				}
				if tc.cause != nil && !errors.Is(err, tc.cause) {
					t.Fatalf("error = %v, want cause %v", err, tc.cause)
				}
				if elapsed := time.Since(start); elapsed != tc.duration {
					t.Fatalf("wait = %v, want %v", elapsed, tc.duration)
				}
			})
		})
	}
}

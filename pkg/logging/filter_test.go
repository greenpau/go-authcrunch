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

package logging_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/greenpau/go-authcrunch/pkg/logging"
)

func newFilter(t *testing.T, match, text string) *logging.Filter {
	t.Helper()
	f, err := logging.NewFilter(&logging.Config{Skip: []logging.SkipRule{{Match: match, Text: text}}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func wrapLogger(t *testing.T, f *logging.Filter, logger *zap.Logger) *zap.Logger {
	t.Helper()
	wrapped, err := f.WrapLogger(logger)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

func TestLoggingMatchStrategies(t *testing.T) {
	for _, tc := range []struct{ match, pattern, yes, no string }{
		{"exact", "no token", "no token", "reason: no token"},
		{"partial", "no token", "reason: no token found", "reason: No Token found"},
		{"prefix", "reason:", "reason: no token", "auth reason: no token"},
		{"suffix", "no token", "reason: no token", "reason: no token found"},
		{"regex", `reason: (no token|expired)`, "auth reason: expired token", "auth reason: invalid token"},
		{"regex", `^no token$`, "no token", "reason: no token"},
		{"exact", " Ω ", " Ω ", "Ω"},
	} {
		t.Run(tc.match+tc.pattern, func(t *testing.T) {
			f := newFilter(t, tc.match, tc.pattern)
			if !f.ShouldSkip(tc.yes) || f.ShouldSkip(tc.no) {
				t.Fatal("incorrect matching strategy")
			}
		})
	}
}

type textStringer string

func (s textStringer) String() string { return string(s) }

type panicError struct{}

func (*panicError) Error() string { panic("synthetic error") }

func TestLoggingTextFields(t *testing.T) {
	f := newFilter(t, "exact", "noise")
	for _, field := range []zap.Field{
		zap.String("detail", "noise"), zap.ByteString("detail", []byte("noise")),
		zap.Error(errors.New("noise")), zap.NamedError("failure", errors.New("noise")),
		zap.Any("error", errors.New("noise")), zap.Stringer("detail", textStringer("noise")),
	} {
		if !f.ShouldSkip("keep", field) {
			t.Fatalf("text field type %v not matched", field.Type)
		}
	}
	for _, field := range []zap.Field{
		zap.String("noise", "keep"), zap.Namespace("noise"), zap.Int("noise", 1),
		zap.Reflect("detail", "noise"), zap.Strings("detail", []string{"noise"}),
		zap.Object("detail", zapcore.ObjectMarshalerFunc(func(e zapcore.ObjectEncoder) error { e.AddString("detail", "noise"); return nil })),
		zap.Error(nil), zap.Error((*panicError)(nil)), zap.Error(&panicError{}),
	} {
		if f.ShouldSkip("keep", field) {
			t.Fatalf("nontext field type %v matched", field.Type)
		}
	}
	if newFilter(t, "partial", "a b").ShouldSkip("a", zap.String("detail", "b")) {
		t.Fatal("matcher joined independent values")
	}
	if !newFilter(t, "exact", `a "b"`).ShouldSkip("keep", zap.String("detail", `a "b"`)) {
		t.Fatal("matcher used JSON-escaped values")
	}
}

func TestLoggingBoundFieldsAndIsolation(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	base := zap.New(core, zap.AddCaller()).Named("security")
	filtered := wrapLogger(t, newFilter(t, "partial", "noise"), base)
	filtered.With(zap.String("detail", "noise")).Info("skip bound")
	filtered.WithLazy(zap.Error(errors.New("noise"))).Info("skip lazy")
	filtered.With(zap.String("scope", "keep")).With(zap.Error(errors.New("noise"))).Info("skip chained")
	filtered.With(zap.Namespace("nested"), zap.String("detail", "noise")).Info("skip namespace")
	filtered.Sugar().Errorw("skip sugar", "error", errors.New("noise"))
	if checked := filtered.Check(zap.ErrorLevel, "skip checked"); checked != nil {
		checked.Write(zap.Error(errors.New("noise")))
	}
	filtered.With(zap.String("scope", "keep")).Info("retained", zap.Int("count", 3))
	base.Error("noise")
	filtered.Info("parent retained")
	entries := observed.All()
	if len(entries) != 3 || entries[0].Message != "retained" || entries[1].Message != "noise" || entries[2].Message != "parent retained" {
		t.Fatal("filter escaped its logger or lost bound fields")
	}
	if entries[0].LoggerName != "security" || !entries[0].Caller.Defined || entries[0].ContextMap()["scope"] != "keep" || entries[0].ContextMap()["count"] != int64(3) {
		t.Fatal("retained entry lost metadata or fields")
	}
	var empty logging.Filter
	if same, err := empty.WrapLogger(base); err != nil || same != base || empty.WrapCore(core) != core {
		t.Fatal("empty filter changed logger")
	}
	if result, err := empty.WrapLogger(nil); result != nil || err == nil {
		t.Fatal("nil logger accepted")
	}
}

func TestLoggingSamplerTeeAndHooks(t *testing.T) {
	debugCore, debugLogs := observer.New(zap.DebugLevel)
	errorCore, errorLogs := observer.New(zap.ErrorLevel)
	var hookCalls int
	core := zapcore.NewTee(debugCore, errorCore)
	core = zapcore.RegisterHooks(core, func(zapcore.Entry) error { hookCalls++; return nil })
	core = zapcore.NewSamplerWithOptions(core, time.Hour, 1, 0)
	logger := wrapLogger(t, newFilter(t, "exact", "noise"), zap.New(core))
	logger.Error("same", zap.String("detail", "noise"))
	logger.Error("same", zap.String("detail", "keep"))
	logger.Error("same")
	logger.Debug("debug")
	if debugLogs.Len() != 2 || errorLogs.Len() != 1 || hookCalls != 2 || errorLogs.All()[0].ContextMap()["detail"] != "keep" {
		t.Fatal("filter bypassed sampling, tee levels or hooks, or consumed sampler quota")
	}
	level := zap.NewAtomicLevelAt(zap.WarnLevel)
	dynamicCore, dynamicLogs := observer.New(level)
	logger = wrapLogger(t, newFilter(t, "exact", "noise"), zap.New(dynamicCore))
	if logger.Level() != zap.WarnLevel {
		t.Fatal("minimum level lost")
	}
	logger.Info("disabled")
	level.SetLevel(zap.InfoLevel)
	logger.Info("enabled")
	if dynamicLogs.Len() != 1 || logger.Level() != zap.InfoLevel {
		t.Fatal("dynamic level changed")
	}
}

type failingCore struct {
	zapcore.Core
	syncs int
}

func (c *failingCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	return ce.AddCore(e, c)
}
func (c *failingCore) Write(zapcore.Entry, []zapcore.Field) error {
	return errors.New("synthetic write failure")
}
func (c *failingCore) Sync() error { c.syncs++; return errors.New("synthetic sync failure") }

func TestLoggingErrorOutputAndSync(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	failing := &failingCore{Core: core}
	var errorOutput bytes.Buffer
	filter := newFilter(t, "exact", "noise")
	logger := wrapLogger(t, filter, zap.New(failing, zap.ErrorOutput(zapcore.AddSync(&errorOutput))))
	logger.Info("noise")
	logger.Info("keep")
	if strings.Count(errorOutput.String(), "synthetic write failure") != 1 {
		t.Fatal("write errors did not reach original error sink once")
	}
	if err := logger.Sync(); err == nil || failing.syncs != 1 {
		t.Fatal("Sync was not preserved")
	}
	if err := filter.WrapCore(failing).Write(zapcore.Entry{Message: "noise"}, nil); err != nil {
		t.Fatal("direct core Write did not filter")
	}
	if err := filter.WrapCore(failing).Write(zapcore.Entry{Message: "keep"}, nil); err == nil {
		t.Fatal("direct core Write lost error")
	}
}

func TestLoggingTerminalActions(t *testing.T) {
	for _, fieldOnly := range []bool{false, true} {
		for _, development := range []bool{false, true} {
			t.Run(fmt.Sprintf("field=%v/development=%v", fieldOnly, development), func(t *testing.T) {
				core, observed := observer.New(zap.DebugLevel)
				logger := zap.New(core)
				if development {
					logger = logger.WithOptions(zap.Development())
				}
				logger = wrapLogger(t, newFilter(t, "exact", "noise"), logger)
				message := "noise"
				if fieldOnly {
					message = "keep"
				}
				defer func() {
					if recover() == nil {
						t.Error("suppression disabled panic behavior")
					}
					if observed.Len() != 0 {
						t.Error("panic entry was not suppressed")
					}
				}()
				if development {
					logger.DPanic(message, zap.String("detail", "noise"))
				} else {
					logger.Panic(message, zap.String("detail", "noise"))
				}
			})
		}
	}
	core, observed := observer.New(zap.DebugLevel)
	logger := wrapLogger(t, newFilter(t, "exact", "noise"), zap.New(core, zap.WithFatalHook(zapcore.WriteThenGoexit)))
	done := make(chan struct{})
	go func() { defer close(done); logger.Fatal("noise"); t.Error("suppression disabled fatal hook") }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fatal hook did not return")
	}
	if observed.Len() != 0 {
		t.Fatal("fatal entry was not suppressed")
	}
}

func TestLoggingConcurrentChildren(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	logger := wrapLogger(t, newFilter(t, "exact", "noise"), zap.New(core))
	var workers sync.WaitGroup
	for i := range 20 {
		workers.Go(func() {
			child := logger.With(zap.Int("worker", i))
			for range 50 {
				child.Info("keep")
				child.Info("skip", zap.Error(errors.New("noise")))
			}
		})
	}
	workers.Wait()
	if observed.Len() != 1000 || observed.FilterMessage("keep").Len() != 1000 {
		t.Fatal("concurrent filtering lost or leaked entries")
	}
}

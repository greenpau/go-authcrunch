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

package logging

import (
	"fmt"
	"slices"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Filter is an immutable snapshot safe for concurrent logging. Its zero value
// retains all entries. Create a new filter and logger for configuration reloads.
type Filter struct {
	rules []compiledRule
}

// NewFilter validates and snapshots configuration without modifying it. A nil
// configuration means filtering is disabled. Later config edits have no effect.
func NewFilter(config *Config) (*Filter, error) {
	if config == nil {
		return &Filter{}, nil
	}
	c := &Config{Skip: slices.Clone(config.Skip)}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Filter{rules: c.compiled}, nil
}

// ShouldSkip matches the message and individual string, byte-string, error and
// Stringer field values. It does not match keys, logger metadata, numeric values,
// reflected objects, arrays, or nested object contents. Error/Stringer conversion
// uses Zap's panic-safe field encoder. Values are neither joined nor JSON escaped.
// Hosts may use this decision at their logging boundary; never discard a returned
// authentication error or alter the HTTP response because a log entry matches.
func (f *Filter) ShouldSkip(message string, fields ...zap.Field) bool {
	return f.matches(message) || f.matchesFields(fields)
}

func (f *Filter) matches(text string) bool {
	for _, rule := range f.rules {
		if rule.matches(text) {
			return true
		}
	}
	return false
}

func (f *Filter) matchesFields(fields []zapcore.Field) bool {
	if len(f.rules) == 0 {
		return false
	}
	for _, field := range fields {
		switch field.Type {
		case zapcore.StringType:
			if f.matches(field.String) {
				return true
			}
		case zapcore.ByteStringType, zapcore.ErrorType, zapcore.StringerType:
			encoder := zapcore.NewMapObjectEncoder()
			field.AddTo(encoder)
			if text, ok := encoder.Fields[field.Key].(string); ok && f.matches(text) {
				return true
			}
		}
	}
	return false
}

// WrapLogger returns a filtered clone, preserving the supplied logger and its
// options. Install the filter before With/WithLazy to match their bound fields:
// fields already embedded in an opaque core cannot be inspected. Nil loggers fail.
// Empty rules return the original logger. The host continues to own flushing.
func (f *Filter) WrapLogger(logger *zap.Logger) (*zap.Logger, error) {
	if logger == nil {
		return nil, fmt.Errorf("logging logger is nil")
	}
	if len(f.rules) == 0 {
		return logger, nil
	}
	return logger.WithOptions(zap.WrapCore(f.WrapCore)), nil
}

// WrapCore adapts a core for zap.WrapCore or an embedding host's logging pipeline.
// It preserves levels, sinks, sampling, hooks, field encoding and Sync. Underlying
// Check is deferred until Write supplies fields, so suppressed entries do not
// consume sampler quotas. Consequently Logger.Check can return a non-nil entry
// that is subsequently filtered or sampled out. Panic/Fatal actions still run.
func (f *Filter) WrapCore(core zapcore.Core) zapcore.Core {
	if len(f.rules) == 0 {
		return core
	}
	return &filterCore{Core: core, filter: f}
}

type filterCore struct {
	zapcore.Core
	filter *Filter
	skip   bool
}

func (c *filterCore) Level() zapcore.Level { return zapcore.LevelOf(c.Core) }

func (c *filterCore) With(fields []zapcore.Field) zapcore.Core {
	return &filterCore{Core: c.Core.With(fields), filter: c.filter, skip: c.skip || c.filter.matchesFields(fields)}
}

func (c *filterCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(entry.Level) || c.skip || c.filter.matches(entry.Message) {
		return checked
	}
	writer := &checkedCore{filterCore: c}
	checked = checked.AddCore(entry, writer)
	writer.checked = checked
	return checked
}

// Write also supports callers using a core directly after their own Check.
func (c *filterCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if c.skip || c.filter.ShouldSkip(entry.Message, fields...) {
		return nil
	}
	return c.Core.Write(entry, fields)
}

type checkedCore struct {
	*filterCore
	checked *zapcore.CheckedEntry
}

func (c *checkedCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	if c.filter.ShouldSkip(entry.Message, fields...) {
		return nil
	}
	// Calling Write directly on the underlying core would bypass Check-based
	// samplers and tee routing, and drop registered hooks. Let it select its own
	// cores, then forward errors through the original logger's error destination.
	if downstream := c.Core.Check(entry, nil); downstream != nil {
		downstream.ErrorOutput = c.checked.ErrorOutput
		downstream.Write(fields...)
	}
	return nil
}

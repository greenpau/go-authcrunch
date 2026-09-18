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

package authn

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	passwordAttemptLimit           = 5
	passwordAttemptBlockDuration   = 5 * time.Minute
	passwordAttemptLimiterCapacity = 65536
	unknownPasswordSource          = "unknown"
)

var errPasswordAttemptLimited = errors.New("password authentication temporarily unavailable")

type passwordAttemptLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	capacity int
	closed   bool
	sources  map[string]*passwordAttemptSource
	blocks   map[string]time.Time
}

type passwordAttemptSource struct {
	failures  int
	inFlight  int
	expiresAt time.Time
}

type passwordAttempt struct {
	limiter  *passwordAttemptLimiter
	source   string
	block    string
	state    *passwordAttemptSource
	finished bool
}

func newPasswordAttemptLimiter(now func() time.Time, capacity int) *passwordAttemptLimiter {
	return &passwordAttemptLimiter{
		now:      now,
		capacity: capacity,
		sources:  make(map[string]*passwordAttemptSource),
		blocks:   make(map[string]time.Time),
	}
}

func (l *passwordAttemptLimiter) begin(sourceAddress string) (*passwordAttempt, error) {
	source, block := passwordAttemptKeys(sourceAddress)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil, errPasswordAttemptLimited
	}
	if blockedUntil, exists := l.blocks[block]; exists {
		if blockedUntil.After(now) {
			return nil, errPasswordAttemptLimited
		}
		delete(l.blocks, block)
	}

	state := l.sources[source]
	if state != nil && state.inFlight == 0 && !state.expiresAt.IsZero() && !state.expiresAt.After(now) {
		delete(l.sources, source)
		state = nil
	}
	if state == nil {
		if len(l.sources) >= l.capacity {
			l.expireLocked(now)
			if len(l.sources) >= l.capacity {
				return nil, errPasswordAttemptLimited
			}
		}
		state = &passwordAttemptSource{}
		l.sources[source] = state
	}
	if state.failures+state.inFlight >= passwordAttemptLimit {
		return nil, errPasswordAttemptLimited
	}
	state.inFlight++
	return &passwordAttempt{limiter: l, source: source, block: block, state: state}, nil
}

// finish returns false when a concurrent failure blocked the source network
// before a successful password verification completed.
func (a *passwordAttempt) finish(success bool) bool {
	l := a.limiter
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if a.finished {
		return false
	}
	a.finished = true
	if l.closed || l.sources[a.source] != a.state {
		return false
	}
	if a.state.inFlight > 0 {
		a.state.inFlight--
	}

	blockedUntil, blocked := l.blocks[a.block]
	blocked = blocked && blockedUntil.After(now)
	if !success {
		a.state.failures++
		a.state.expiresAt = now.Add(passwordAttemptBlockDuration)
		if a.state.failures >= passwordAttemptLimit {
			l.blocks[a.block] = now.Add(passwordAttemptBlockDuration)
			blocked = true
		}
	} else if !blocked {
		a.state.failures = 0
		a.state.expiresAt = time.Time{}
	}

	if a.state.failures == 0 && a.state.inFlight == 0 {
		delete(l.sources, a.source)
	}
	if blocked {
		return false
	}
	return success
}

func (l *passwordAttemptLimiter) expireLocked(now time.Time) {
	for source, state := range l.sources {
		if state.inFlight == 0 && !state.expiresAt.IsZero() && !state.expiresAt.After(now) {
			delete(l.sources, source)
		}
	}
	for block, blockedUntil := range l.blocks {
		if !blockedUntil.After(now) {
			delete(l.blocks, block)
		}
	}
}

func (l *passwordAttemptLimiter) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	clear(l.sources)
	clear(l.blocks)
}

func passwordAttemptKeys(sourceAddress string) (string, string) {
	addr, err := parsePasswordSourceAddress(sourceAddress)
	if err != nil {
		return unknownPasswordSource, unknownPasswordSource
	}
	addr = addr.Unmap().WithZone("")
	source := addr.String()
	if addr.Is4() {
		bits := 24
		if isRFC1918Address(addr) {
			bits = 32
		}
		return source, netip.PrefixFrom(addr, bits).Masked().String()
	}
	return source, netip.PrefixFrom(addr, 128).String()
}

func parsePasswordSourceAddress(sourceAddress string) (netip.Addr, error) {
	sourceAddress = strings.TrimSpace(sourceAddress)
	if addr, err := netip.ParseAddr(sourceAddress); err == nil {
		return addr, nil
	}
	host, _, err := net.SplitHostPort(sourceAddress)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(host)
}

func isRFC1918Address(addr netip.Addr) bool {
	return netip.MustParsePrefix("10.0.0.0/8").Contains(addr) ||
		netip.MustParsePrefix("172.16.0.0/12").Contains(addr) ||
		netip.MustParsePrefix("192.168.0.0/16").Contains(addr)
}

func (p *Portal) authenticatePassword(sourceAddress string, authenticate func() error) error {
	attempt, err := p.passwordAttempts.begin(sourceAddress)
	if err != nil {
		return err
	}
	if err := authenticate(); err != nil {
		attempt.finish(false)
		return err
	}
	if !attempt.finish(true) {
		return errPasswordAttemptLimited
	}
	return nil
}

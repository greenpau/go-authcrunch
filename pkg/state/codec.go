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

package state

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
)

type boundedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.remaining {
		return 0, ErrCapacity
	}
	n, err := b.Buffer.Write(data)
	b.remaining -= n
	return n, err
}

// Decode restores an authenticated component snapshot. An absent snapshot
// returns false. Use only private persistence DTOs, never request-supplied data.
func (r *Record) Decode(value any) (bool, error) {
	data, err := r.Load()
	if err != nil {
		return false, err
	}
	if len(data) == 0 {
		return false, nil
	}
	reader := bytes.NewReader(data)
	if gob.NewDecoder(reader).Decode(value) != nil || reader.Len() != 0 {
		return false, fmt.Errorf("invalid component state")
	}
	return true, nil
}

// Encode commits a private component snapshot. Gob is intentional: server-only
// proof structs keep their public JSON/XML/YAML serialization exclusions.
func (r *Record) Encode(value any) error {
	data, err := r.PrepareEncode(value)
	if errors.Is(err, ErrCapacity) {
		r.store.mu.Lock()
		r.store.failed = true
		r.store.mu.Unlock()
		return fmt.Errorf("encode component state: %w: %w", ErrCapacity, ErrUnavailable)
	}
	if err != nil {
		return err
	}
	return r.Save(data)
}

// PrepareEncode serializes a candidate snapshot and bounds its encoded payload
// without changing the record or writing to disk. A capacity refusal leaves the
// store available, allowing transactional consumers to preserve their previously
// committed state. Callers remain responsible for bounding their in-memory DTO;
// encoding/gob may stage data internally before writing. Save the returned bytes
// before publishing the candidate mutation.
func (r *Record) PrepareEncode(value any) ([]byte, error) {
	if err := r.Err(); err != nil {
		return nil, err
	}
	b := &boundedBuffer{remaining: maxRecordPayloadSize}
	if err := gob.NewEncoder(b).Encode(value); err != nil {
		if errors.Is(err, ErrCapacity) {
			return nil, ErrCapacity
		}
		return nil, fmt.Errorf("encode component state")
	}
	if err := r.Err(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

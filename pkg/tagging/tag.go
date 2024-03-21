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

package tagging

import (
	"fmt"
)

// Tag represents key-value tag.
type Tag struct {
	Key   string `json:"key,omitempty" xml:"key,omitempty" yaml:"key,omitempty"`
	Value string `json:"value,omitempty" xml:"value,omitempty" yaml:"value,omitempty"`
}

// NewTag returns an instance of Tag
func NewTag(key, value string) *Tag {
	return &Tag{Key: key, Value: value}
}

func extractStringFromInteface(i interface{}) (string, error) {
	switch v := i.(type) {
	case string:
		return v, nil
	}
	return "", fmt.Errorf("not string")
}

func extractMapKeyFromInteface(k string, m map[string]interface{}) (string, error) {
	if v, exists := m[k]; exists {
		key, err := extractStringFromInteface(v)
		if err != nil {
			return "", fmt.Errorf("tag %s is malformed: %v", k, err)
		}
		return key, nil
	}

	return "", fmt.Errorf("tag has no %s", k)
}

func extractTagFromMap(m map[string]interface{}) (*Tag, error) {
	if m == nil {
		return nil, fmt.Errorf("tag is nil")
	}
	key, err := extractMapKeyFromInteface("key", m)
	if err != nil {
		return nil, err
	}
	value, err := extractMapKeyFromInteface("value", m)
	if err != nil {
		return nil, err
	}
	tag := &Tag{
		Key:   key,
		Value: value,
	}
	return tag, nil
}

// ExtractTags extracts tags fom a map.
func ExtractTags(m map[string]interface{}) ([]*Tag, error) {
	tags := []*Tag{}
	if m == nil {
		return tags, fmt.Errorf("input data is nil")
	}

	extractedTags, tagExists := m["tags"]
	if !tagExists {
		return tags, nil
	}

	switch vs := extractedTags.(type) {
	case []interface{}:
		for _, extractedTag := range vs {

			switch v := extractedTag.(type) {
			case map[string]interface{}:
				tag, err := extractTagFromMap(v)
				if err != nil {
					return tags, fmt.Errorf("malformed extracted tags: %v", err)
				}
				tags = append(tags, tag)
			default:
				return tags, fmt.Errorf("extracted tag is %T", extractedTag)
			}
		}
	default:
		return tags, fmt.Errorf("extracted tags are %T", vs)
	}
	return tags, nil
}

// ExtractLabels extracts labels fom a map.
func ExtractLabels(m map[string]interface{}) ([]string, error) {
	labels := []string{}
	if m == nil {
		return labels, fmt.Errorf("input data is nil")
	}

	extractedLabels, labelsExists := m["labels"]
	if !labelsExists {
		return labels, nil
	}

	switch vs := extractedLabels.(type) {
	case []interface{}:
		for _, extractedLabel := range vs {

			switch label := extractedLabel.(type) {
			case string:
				labels = append(labels, label)
			default:
				return labels, fmt.Errorf("extracted label is %T", label)
			}
		}
	default:
		return labels, fmt.Errorf("extracted labels are %T", vs)
	}
	return labels, nil
}

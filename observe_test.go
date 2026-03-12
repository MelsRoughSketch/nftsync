// Copyright 2026 the nftsync Authors and Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package nftsync

import (
	"testing"
	"time"
)

func TestGetTTLConverter(t *testing.T) {
	tests := []struct {
		name   string
		minTTL uint32
		input  uint32
		want   time.Duration
	}{
		{
			name:   "input is smaller than minttl",
			minTTL: defaultMinTTL,
			input:  3,
			want:   time.Duration(defaultMinTTL+TimeoutOffset) * time.Second,
		},
		{
			name:   "input is the same as minttl",
			minTTL: defaultMinTTL,
			input:  defaultMinTTL,
			want:   time.Duration(defaultMinTTL+TimeoutOffset) * time.Second,
		},
		{
			name:   "input is bigger than minttl",
			minTTL: defaultMinTTL,
			input:  20,
			want:   time.Duration(20+TimeoutOffset) * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := getTTLConverter(tt.minTTL)
			got := converter(tt.input)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

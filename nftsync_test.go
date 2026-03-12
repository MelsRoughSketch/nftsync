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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	nft "github.com/google/nftables"
)

// type Tree interface {
// 	Search(string) []ipSet
// 	Build(map[string]ipSet)
// }

// treeStab implements Tree.
type treeStab struct {
	searchStab func(string) []ipSet
}

func (t *treeStab) Search(s string) []ipSet { return t.searchStab(s) }
func (t *treeStab) Build(map[string]ipSet)  {}

// TestUpdateSetByNames is integration test.
func TestUpdateSetByNames(t *testing.T) {
	tests := []struct {
		name   string
		iNames []string
		iV4    []nft.SetElement
		iV6    []nft.SetElement

		// since it's difficult to sort results and expected values in strict weak order
		// while preserving the message type sequence, so fixing the return value of Search()
		treeStab func(string) []ipSet

		wantUpdateElm []fakeSetMessage
		wantErr       bool
	}{
		{
			"happy path",
			[]string{"example.com."},
			[]nft.SetElement{
				{Key: netip.MustParseAddr("192.0.2.1").AsSlice()},
				{Key: netip.MustParseAddr("192.0.2.2").AsSlice()},
			},
			[]nft.SetElement{
				{Key: netip.MustParseAddr("2001:db8::1").AsSlice()},
				{Key: netip.MustParseAddr("2001:db8::2").AsSlice()},
			},
			func(s string) []ipSet {
				return []ipSet{
					{&nft.Set{Name: "s4_1"}, &nft.Set{Name: "s6_1"}},
					{&nft.Set{Name: "s4_2"}, &nft.Set{Name: "s6_2"}},
				}
			},
			[]fakeSetMessage{
				// we first want the destroy msg, then an add msg
				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice()},
						{Key: netip.MustParseAddr("192.0.2.2").AsSlice()},
					},
					destroy,
				},
				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice()},
						{Key: netip.MustParseAddr("192.0.2.2").AsSlice()},
					},
					add,
				},

				{
					&nft.Set{Name: "s6_1"},
					[]fakeElement{
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice()},
						{Key: netip.MustParseAddr("2001:db8::2").AsSlice()},
					},
					destroy,
				},
				{
					&nft.Set{Name: "s6_1"},
					[]fakeElement{
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice()},
						{Key: netip.MustParseAddr("2001:db8::2").AsSlice()},
					},
					add,
				},

				{
					&nft.Set{Name: "s4_2"},
					[]fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice()},
						{Key: netip.MustParseAddr("192.0.2.2").AsSlice()},
					},
					destroy,
				},
				{
					&nft.Set{Name: "s4_2"},
					[]fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice()},
						{Key: netip.MustParseAddr("192.0.2.2").AsSlice()},
					},
					add,
				},

				{
					&nft.Set{Name: "s6_2"},
					[]fakeElement{
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice()},
						{Key: netip.MustParseAddr("2001:db8::2").AsSlice()},
					},
					destroy,
				},
				{
					&nft.Set{Name: "s6_2"},
					[]fakeElement{
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice()},
						{Key: netip.MustParseAddr("2001:db8::2").AsSlice()},
					},
					add,
				},
			},
			false,
		},
		{
			"multi names and only one family",
			[]string{"example.com.", "sub.example.com."},
			[]nft.SetElement{
				{Key: netip.MustParseAddr("192.0.2.1").AsSlice()},
			},
			nil,
			func(s string) []ipSet { return []ipSet{{&nft.Set{Name: "s4_1"}, &nft.Set{Name: "s6_1"}}} },
			[]fakeSetMessage{
				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
					destroy,
				},
				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
					add,
				},

				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
					destroy,
				},
				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
					add,
				},
			},
			false,
		},
		{
			"set object nil",
			[]string{"example.com."},
			[]nft.SetElement{
				{Key: netip.MustParseAddr("192.0.2.1").AsSlice()},
			},
			[]nft.SetElement{
				{Key: netip.MustParseAddr("2001:db8::1").AsSlice()},
			},
			func(s string) []ipSet { return []ipSet{{&nft.Set{Name: "s4_1"}, nil}} },
			[]fakeSetMessage{
				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
					destroy,
				},
				{
					&nft.Set{Name: "s4_1"},
					[]fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice()}},
					add,
				},
			},
			false,
		},
		{
			"nil elements",
			[]string{"example.com."},
			nil,
			nil,
			func(s string) []ipSet { return []ipSet{{&nft.Set{Name: "s4_1"}, &nft.Set{Name: "s6_1"}}} },
			nil,
			false,
		},
		{
			"empty elements",
			[]string{"example.com."},
			[]nft.SetElement{},
			[]nft.SetElement{},
			func(s string) []ipSet { return []ipSet{{&nft.Set{Name: "s4_1"}, &nft.Set{Name: "s6_1"}}} },
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns := NewNftSync()
			fake := NewNetlinkFake()
			ns.SetConn(fake)
			ns.SetTree(&treeStab{searchStab: tt.treeStab})

			err := ns.updateSetByNames(tt.iNames, tt.iV4, tt.iV6)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if diff := cmp.Diff(fake.m, tt.wantUpdateElm, cmpopts.IgnoreFields(nft.Set{}, "KeyType", "DataType")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestAddUpdatingElementMessage(t *testing.T) {
	ns := NewNetlinkFake()
	v4Set, v6Set, err := getDefaultSet(t, ns)
	if err != nil {
		t.Fatalf("failed get set: %v", err)
	}
	tests := []struct {
		name        string
		iSet        *nft.Set
		iElm        []nft.SetElement
		wantMessage []fakeSetMessage
		wantErr     bool
	}{
		{
			"v4set",
			v4Set,
			[]nft.SetElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout}},
			[]fakeSetMessage{
				{
					Set:   v4Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout}},
					Flag:  destroy,
				},
				{
					Set:   v4Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout}},
					Flag:  add,
				},
			},
			false,
		},
		{
			"v6set",
			v6Set,
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute}},
			[]fakeSetMessage{
				{
					Set:   v6Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute}},
					Flag:  destroy,
				},
				{
					Set:   v6Set,
					Elems: []fakeElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute}},
					Flag:  add,
				},
			},
			false,
		},
		{
			"set is nil",
			nil,
			[]nft.SetElement{{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout}},
			nil,
			false,
		},
		{
			"elm is nil",
			v4Set,
			nil,
			nil,
			false,
		},
		{
			"multi elems",
			v4Set,
			[]nft.SetElement{
				{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
				{Key: netip.MustParseAddr("1.1.1.2").AsSlice(), Timeout: defaultTimeout + time.Minute},
			},
			[]fakeSetMessage{
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("1.1.1.2").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: destroy,
				},
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("1.1.1.2").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: add,
				},
			},
			false,
		},
		{
			"mixed family",
			v4Set,
			[]nft.SetElement{
				{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
				{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute},
			},
			[]fakeSetMessage{
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: destroy,
				},
				{
					Set: v4Set,
					Elems: []fakeElement{
						{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: defaultTimeout},
						{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: defaultTimeout + time.Minute},
					},
					Flag: add,
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { ns.m = nil }()
			err := addUpdatingElementMessage(ns, tt.iSet, tt.iElm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if diff := cmp.Diff(ns.m, tt.wantMessage, cmpopts.IgnoreFields(nft.Set{}, "KeyType", "DataType")); diff != "" {
				t.Error(diff)
			}
		})
	}
}

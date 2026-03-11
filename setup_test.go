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
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/coredns/caddy"
	nft "github.com/google/nftables"
)

func TestGetTableFamilyByName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantFam nft.TableFamily
		wantOk  bool
	}{
		{`valid inet`, `inet`, nft.TableFamilyINet, true},
		{`uppercase`, `IPv4`, nft.TableFamilyIPv4, true},
		{`mixed uppercase`, `Ipv6`, nft.TableFamilyIPv6, true},
		{`invalid`, `unknown`, 0, false},
		{`empty`, ``, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, ok := getTableFamilyByName(tt.input)
			if f != tt.wantFam || ok != tt.wantOk {
				t.Errorf("Expected (%v, %v) but found (%v, %v)", f, ok, tt.wantFam, tt.wantOk)
			}
		})
	}
}

type testNftsync struct {
	name          string
	input         string
	wantErr       bool
	wantConn      reflect.Type
	wantFamily    nft.TableFamily
	wantTableName string
	wantMinttl    uint32
}

func setuptester(test testNftsync, t *testing.T) {
	t.Helper()

	c := caddy.NewTestController("dns", test.input)
	ns, err := NftSyncParse(c)
	if test.wantErr {
		assert.Error(t, err)
		return
	} else {
		assert.NoError(t, err)
	}

	if reflect.TypeOf(ns.conn) != test.wantConn {
		t.Errorf("Expected Conn %v but found: %v", test.wantConn, reflect.TypeOf(ns.conn))
	}
	if ns.table.Name != test.wantTableName {
		t.Errorf("Expected Conn %v but found: %v", test.wantTableName, ns.table.Name)
	}
	if ns.minttl != test.wantMinttl {
		t.Errorf("Expected Conn %v but found: %v", test.wantMinttl, ns.minttl)
	}
}

func TestSetup(t *testing.T) {
	t.Run("without mocking socket", func(t *testing.T) {
		if !*enableSystemTest {
			t.SkipNow()
		}
		tests := []testNftsync{
			{`valid inet t`, `nftsync inet t`, false, reflect.TypeFor[*nft.Conn](), nft.TableFamilyINet, defaultTableName, defaultMinTTL},

			// fails
			// dont make ipv4 and ipv6 table
			{`missing ipv4 t`, `nftsync ipv4 t`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, defaultTableName, defaultMinTTL},
			{`missing ipv6 t`, `nftsync ipv6 t`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv6, defaultTableName, defaultMinTTL},
			{`debug typo`, `nftsync de inet t`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, defaultTableName, defaultMinTTL},
			{`debug typo and ttl specifying`, `nftsync de inet t 10`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, defaultTableName, 10},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				setuptester(tt, t)
			})
		}
	})

	t.Run("with mocking socket", func(t *testing.T) {

		tests := []testNftsync{

			{`check connection`, `nftsync debug inet t`, false, reflect.TypeFor[*NetlinkFake](), nft.TableFamilyINet, defaultTableName, defaultMinTTL},
			{`ipv4`, `nftsync debug ipv4 t`, false, reflect.TypeFor[*NetlinkFake](), nft.TableFamilyIPv4, defaultTableName, defaultMinTTL},
			{`ipv6`, `nftsync debug ipv6 t`, false, reflect.TypeFor[*NetlinkFake](), nft.TableFamilyIPv6, defaultTableName, defaultMinTTL},
			{`setting ttl`, `nftsync debug inet t 10`, false, reflect.TypeFor[*NetlinkFake](), nft.TableFamilyIPv6, defaultTableName, 10},

			//fails
			{`missing table`, `nftsync inet notfound`, true, reflect.TypeFor[*nft.Conn](), nft.TableFamilyIPv4, `notfound`, defaultMinTTL},
			{`ttl zero`, `nftsync debug inet t 0`, true, reflect.TypeFor[*NetlinkFake](), nft.TableFamilyIPv4, defaultTableName, 0},
			{`ttl nega`, `nftsync debug inet t -1`, true, reflect.TypeFor[*NetlinkFake](), nft.TableFamilyIPv4, defaultTableName, 0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				setuptester(tt, t)
			})
		}
	})
}

func TestSync(t *testing.T) {
	fakeConn := NewNetlinkFake()
	fTable, err := fakeConn.ListTableOfFamily(defaultTableName, defaultTableFamily)
	if err != nil {
		t.Fatalf("table not found: %v", err)
	}
	tests := []struct {
		name    string
		input   string
		wantCfg map[string]ipSet
		wantErr bool
	}{
		{
			`valid`,
			`sync host example.com. s4 s6`,
			map[string]ipSet{
				"example.com.": {
					V4: &nft.Set{Table: fTable, Name: "s4"},
					V6: &nft.Set{Table: fTable, Name: "s6"},
				},
			},
			false,
		},
		{
			`missing v4 set`,
			`sync host example.com. notfound s6`,
			map[string]ipSet{
				"example.com.": {
					V4: nil, // nil if missing, not address of empty struct
					V6: &nft.Set{Table: fTable, Name: "s6"},
				},
			},
			false,
		},
		{
			`missing v6 set`,
			`sync host example.com. s4 s5`,
			map[string]ipSet{
				"example.com.": {
					V4: &nft.Set{Table: fTable, Name: "s4"},
				},
			},
			false,
		},
		{
			`missing set`,
			`sync host example.com. not found`,
			map[string]ipSet{},
			false,
		},
		{
			`multi domains`,
			"sync host example.com. s4 s6\nsync host sub.example.com. s4 s6",
			map[string]ipSet{
				"example.com.": {
					V4: &nft.Set{Table: fTable, Name: "s4"},
					V6: &nft.Set{Table: fTable, Name: "s6"},
				},
				"sub.example.com.": {
					V4: &nft.Set{Table: fTable, Name: "s4"},
					V6: &nft.Set{Table: fTable, Name: "s6"},
				},
			},
			false,
		},
		{
			`tree flag`,
			"sync host example.com. s4 s6\nsync tree example.com. s4 s6",
			map[string]ipSet{
				"example.com.": {
					V4: &nft.Set{Table: fTable, Name: "s4"},
					V6: &nft.Set{Table: fTable, Name: "s6"},
				},
				"*.example.com.": {
					V4: &nft.Set{Table: fTable, Name: "s4"},
					V6: &nft.Set{Table: fTable, Name: "s6"},
				},
			},
			false,
		},

		// fails
		{
			`invalid keyword`,
			`synnc tree example.com. s4 s6`,
			nil,
			true,
		},
		{
			`invalid flag`,
			`sync treee example.com. s4 s6`,
			nil,
			true,
		},
		{
			`invalid domain`,
			`sync tree example..com. s4 s6`,
			nil,
			true,
		},
		{
			`domain with wildcard`,
			`sync tree *.example.com. s4 s6`,
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := caddy.NewTestController("dns", fmt.Sprintf("nftsync debug inet t {\n%s\n}", tt.input))
			ns, err := NftSyncParse(c)
			if tt.wantErr {
				assert.Error(t, err)
				return
			} else if !assert.NoError(t, err) {
				return
			}

			if diff := cmp.Diff(ns.config, tt.wantCfg, cmpopts.IgnoreFields(nft.Set{}, "KeyType", "DataType")); diff != "" {
				t.Errorf("want %v but %v", tt.wantCfg, ns.config)
			}
		})
	}
}

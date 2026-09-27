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
	"flag"
	"net/netip"
	"testing"

	nft "github.com/google/nftables"
)

var enableSystemTest = flag.Bool("system_test", false, "Run tests that operate kernel")

func getDefaultSet(t *testing.T, c NetlinkConn) (*nft.Set, *nft.Set, error) {
	t.Helper()
	table, err := c.ListTableOfFamily(defaultTableName, defaultTableFamily)
	if err != nil {
		return nil, nil, err
	}
	s4, err := c.GetSetByName(table, defaultSetV4Name)
	if err != nil {
		return nil, nil, err
	}
	s6, err := c.GetSetByName(table, defaultSetV6Name)
	return s4, s6, err
}

func TestNetlinkFakeMatchesConnector(t *testing.T) {
	if !*enableSystemTest {
		t.SkipNow()
	}

	t.Run("lookup", func(t *testing.T) {
		real, err := NewConnector()
		if err != nil {
			t.Fatal(err)
		}
		fake := NewNetlinkFake()
		for _, name := range []string{defaultTableName, "missing"} {
			r, rerr := real.ListTableOfFamily(name, defaultTableFamily)
			f, ferr := fake.ListTableOfFamily(name, defaultTableFamily)
			if (r == nil) != (f == nil) || (rerr == nil) != (ferr == nil) {
				t.Errorf("table %q mismatch: real=(%v, %v), fake=(%v, %v)", name, r, rerr, f, ferr)
			}
		}
	})

	tests := []struct {
		name, set string
		key       []byte
	}{
		{"ipv4", defaultSetV4Name, netip.MustParseAddr("192.0.2.1").AsSlice()},
		{"ipv6", defaultSetV6Name, netip.MustParseAddr("2001:db8::1").AsSlice()},
		{"wrong family", defaultSetV4Name, netip.MustParseAddr("2001:db8::1").AsSlice()},
		{"invalid address", defaultSetV4Name, []byte{1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			real, err := NewConnector()
			if err != nil {
				t.Fatal(err)
			}
			fake := NewNetlinkFake()
			rerr := updateAndFlush(real, tt.set, tt.key)
			ferr := updateAndFlush(fake, tt.set, tt.key)
			if (rerr == nil) != (ferr == nil) {
				t.Errorf("real error=%v, fake error=%v", rerr, ferr)
			}
		})
	}
}

func updateAndFlush(c NetlinkConn, setName string, key []byte) error {
	table, err := c.ListTableOfFamily(defaultTableName, defaultTableFamily)
	if err != nil {
		return err
	}
	set, err := c.GetSetByName(table, setName)
	if err != nil {
		return err
	}
	elements := []nft.SetElement{{Key: key, Timeout: defaultTimeout}}
	if err = c.SetDestroyElements(set, elements); err != nil {
		return err
	}
	if err = c.SetAddElements(set, elements); err != nil {
		return err
	}
	return c.Flush()
}

func TestNetlinkFakeClearsFailedBatch(t *testing.T) {
	fake := NewNetlinkFake()
	if err := updateAndFlush(fake, phantomSetName, netip.MustParseAddr("192.0.2.1").AsSlice()); err == nil {
		t.Fatal("phantom set flush succeeded")
	}
	if err := fake.Flush(); err != nil {
		t.Fatalf("failed batch was not cleared: %v", err)
	}
}

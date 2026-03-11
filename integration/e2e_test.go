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

package integration

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"time"

	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	nft "github.com/google/nftables"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/MelsRoughSketch/nftsync"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
)

var enableSystemTest = flag.Bool("system_test", false, "Run tests that operate operate kernel")

const (
	tableName string          = "e2e_test"
	family    nft.TableFamily = nft.TableFamilyINet
)

// testHander implements plugin.Handler.
type testHandler struct {
	Response *test.Case
	Next     plugin.Handler
}

func (t *testHandler) Name() string { return "dummy" }

func (t *testHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	d := new(dns.Msg)
	d.SetReply(r)
	if t.Response != nil {
		d.Answer = t.Response.Answer
		d.Ns = t.Response.Ns
		d.Extra = t.Response.Extra
		d.Rcode = t.Response.Rcode
	}
	if err := w.WriteMsg(d); err != nil {
		return 1, err
	}
	return 0, nil
}

// TestE2E performs tests to verify the nftset state using actual Netlink connections.
func TestE2E(t *testing.T) {
	if !*enableSystemTest {
		t.SkipNow()
	}

	nftConn, err := nft.New()
	if err != nil {
		t.Fatalf("failed get connection: %v", err)
	}

	tableObj, err := nftConn.ListTableOfFamily(tableName, family)
	if err != nil {
		t.Fatalf("failed get table: %v", err)
	}

	sets, err := nftConn.GetSets(tableObj)
	if err != nil {
		t.Fatalf("failed get set: %v", err)
	}

	// transfer it to a map for easier handling
	setMap := make(map[string]*nft.Set, len(sets))
	for _, s := range sets {
		setMap[s.Name] = s
		nftConn.FlushSet(s)
	}

	if err = nftConn.Flush(); err != nil {
		t.Fatalf("failed flush set: %v", err)
	}

	tests := []struct {
		name          string
		policy        string
		testCase      test.Case
		wantErr       bool
		wantElements  map[string][]nft.SetElement
		afterFlushing bool // Whether to flash after the evaluation is complete
	}{
		{
			name: "valid",
			policy: "sync host example.com. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("example.com.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_2": nil,
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: false,
		},
		{
			name: "check override element",
			policy: "sync host example.com. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("example.com.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_2": nil,
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name: "check tree",
			policy: "sync tree example.com. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "sub.example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("sub.example.com.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_2": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name: "check tree",
			policy: "sync tree example.com. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("example.com.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_2": nil,
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name: "check cname chain",
			policy: "sync host mels.cdn.net. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "sub.example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("sub.example.com.	6000	IN	CNAME	mels.cdn.net."),
					test.A("mels.cdn.net.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_2": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name: "check cname chain(tree)",
			policy: "sync host mels.cdn.net. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2\n" +
				"sync tree cdn.net. e2e_s4_3 e2e_s6_3",
			testCase: test.Case{
				Qname: "sub.example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("sub.example.com.	6000	IN	CNAME	mels.cdn.net."),
					test.A("mels.cdn.net.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_2": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_3": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
				},
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name: "broken cname chain",
			policy: "sync host mels.cdn.net. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "sub.example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("sub.example.com.	6000	IN	CNAME	mels.cdn.net."),
					test.A("broken.cdn.net.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": nil,
				"e2e_s4_2": nil,
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name:   "looped cname chain",
			policy: "sync host mels.cdn.net. e2e_s4_1 e2e_s6_1",
			testCase: test.Case{
				Qname: "sub.example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("sub.example.com.	6000	IN	CNAME	mels.cdn.net."),
					test.CNAME("mels.cdn.net.	6000	IN	CNAME	mels.cdn.com."),
					test.CNAME("mels.cdn.com.	6000	IN	CNAME	mels.cdn.net."),
					test.A("broken.cdn.net.	3600	IN	A	192.0.2.1"),
				},
			},
			wantErr: true,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": nil,
				"e2e_s4_2": nil,
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name: "multi address",
			policy: "sync host mels.cdn.net. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "sub.example.com.", Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.CNAME("sub.example.com.	6000	IN	CNAME	mels.cdn.net."),
					test.A("mels.cdn.net.	3600	IN	A	192.0.2.1"),
					test.A("mels.cdn.net.	3700	IN	A	192.0.2.2"),
					test.A("mels.cdn.net.	3800	IN	A	192.0.2.3"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
					{Key: netip.MustParseAddr("192.0.2.2").AsSlice(), Timeout: 3705 * time.Second, Expires: 3705 * time.Second},
					{Key: netip.MustParseAddr("192.0.2.3").AsSlice(), Timeout: 3805 * time.Second, Expires: 3805 * time.Second},
				},
				"e2e_s4_2": {
					{Key: netip.MustParseAddr("192.0.2.1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
					{Key: netip.MustParseAddr("192.0.2.2").AsSlice(), Timeout: 3705 * time.Second, Expires: 3705 * time.Second},
					{Key: netip.MustParseAddr("192.0.2.3").AsSlice(), Timeout: 3805 * time.Second, Expires: 3805 * time.Second},
				},
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": nil,
				"e2e_s6_2": nil,
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
		{
			name: "multi v6 address",
			policy: "sync host mels.cdn.net. e2e_s4_1 e2e_s6_1\n" +
				"sync host sub.example.com. e2e_s4_2 e2e_s6_2",
			testCase: test.Case{
				Qname: "sub.example.com.", Qtype: dns.TypeAAAA,
				Answer: []dns.RR{
					test.CNAME("sub.example.com.	6000	IN	CNAME	mels.cdn.net."),
					test.AAAA("mels.cdn.net.	3600	IN	AAAA	2001:db8::1"),
					test.AAAA("mels.cdn.net.	3700	IN	AAAA	2001:db8::2"),
					test.AAAA("mels.cdn.net.	3800	IN	AAAA	2001:db8::3"),
				},
			},
			wantErr: false,
			wantElements: map[string][]nft.SetElement{
				"e2e_s4_1": nil,
				"e2e_s4_2": nil,
				"e2e_s4_3": nil,
				"e2e_s4_4": nil,
				"e2e_s6_1": {
					{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
					{Key: netip.MustParseAddr("2001:db8::2").AsSlice(), Timeout: 3705 * time.Second, Expires: 3705 * time.Second},
					{Key: netip.MustParseAddr("2001:db8::3").AsSlice(), Timeout: 3805 * time.Second, Expires: 3805 * time.Second},
				},
				"e2e_s6_2": {
					{Key: netip.MustParseAddr("2001:db8::1").AsSlice(), Timeout: 3605 * time.Second, Expires: 3605 * time.Second},
					{Key: netip.MustParseAddr("2001:db8::2").AsSlice(), Timeout: 3705 * time.Second, Expires: 3705 * time.Second},
					{Key: netip.MustParseAddr("2001:db8::3").AsSlice(), Timeout: 3805 * time.Second, Expires: 3805 * time.Second},
				},
				"e2e_s6_3": nil,
				"e2e_s6_4": nil,
			},
			afterFlushing: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns",
				fmt.Sprintf("nftsync inet %s {\n%s\n}", tableName, tt.policy))
			ns, err := nftsync.NftSyncParse(c)
			if err != nil {
				t.Fatalf("failed load setting: %v", err)
			}

			testHandler := &testHandler{
				Response: &tt.testCase,
				Next:     nil,
			}
			ns.Next = testHandler

			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			req := tt.testCase.Msg()

			_, err = ns.ServeDNS(context.TODO(), rec, req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			} else if !assert.NoError(t, err) {
				return
			}

			opt := cmp.Options{
				cmpopts.SortSlices(func(a, b nft.SetElement) bool {
					addrA, ok := netip.AddrFromSlice(a.Key)
					if !ok {
						panic("failed parse addr")
					}
					addrB, ok := netip.AddrFromSlice(b.Key)
					if !ok {
						panic("failed parse addr")
					}
					return addrA.Less(addrB)
				}),
				cmp.Transformer("DurationToSeconds", func(d time.Duration) float64 {
					return d.Seconds()
				}),
				cmpopts.EquateApprox(0, 0.5),
			}

			for k, v := range setMap {
				actualElement, err := nftConn.GetSetElements(v)
				if err != nil {
					t.Fatalf("failed get element: %v", err)
				}

				if diff := cmp.Diff(tt.wantElements[k], actualElement, opt); diff != "" {
					t.Error(diff)
				}

				if tt.afterFlushing {
					nftConn.FlushSet(v)
				}
			}
			if tt.afterFlushing {
				if err := nftConn.Flush(); err != nil {
					t.Fatalf("failed flush set: %v", err)
				}
			} else {
				t.Log("waiting until the 'Expires margin' expires")
				time.Sleep(time.Second)
			}
		})
	}
}

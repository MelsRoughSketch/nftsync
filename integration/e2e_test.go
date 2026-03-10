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
	w.WriteMsg(d)
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
			name:   "test",
			policy: "sync host example.com. e2e_s4_1 e2e_s6_1",
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

			// Expires allows for some margin of error
			isExpiresField := func(p cmp.Path) bool {
				return p.String() == "Expires"
			}
			opt := cmp.FilterPath(isExpiresField, cmp.Options{
				cmp.Transformer("DurationToSeconds", func(d time.Duration) float64 {
					return d.Seconds()
				}),
				cmpopts.EquateApprox(0, 0.5),
			})

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
			}
		})
	}
}

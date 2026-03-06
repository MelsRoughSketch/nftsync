package nftsync

import (
	"context"
	"time"

	"github.com/MelsRoughSketch/nftsync/nametrie"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/google/nftables"
	"github.com/miekg/dns"
)

type nameMap struct {
	v4Set *nftables.Set
	v6Set *nftables.Set
}

// NftSync is a plugin that synchronizes dns and nftables set.
type NftSync struct {
	NetlinkConn
	*nametrie.TrieTree[nameMap]
	Next   plugin.Handler
	family nftables.TableFamily
	table  *nftables.Table
	minttl uint32

	zoneMetricLabel string
	viewMetricLabel string
}

// New returns an initialized NftSync with default settings. It's up to the
// caller to set the Next handler.
func New() *NftSync {
	return &NftSync{
		TrieTree: &nametrie.TrieTree[nameMap]{},
		minttl:   defaultMinTTL,
	}
}

// SetConn injects connection to NftSync.
func (n *NftSync) SetConn(conn NetlinkConn) { n.NetlinkConn = conn }

// Name implements plugin.Handler.
func (n *NftSync) Name() string { return "nftsync" }

// ServeDNS implements plugin.Handler.
func (n *NftSync) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	server := metrics.WithServer(ctx)
	nw := NewResponseWriter(server, w, n)
	return plugin.NextOrFailure(n.Name(), n.Next, ctx, nw, r)
}

const defaultMinTTL = uint32(dnsutil.MinimalDefaultTTL / time.Second)

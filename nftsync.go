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

type ipSet struct {
	V4 *nftables.Set
	V6 *nftables.Set
}

// Tree is an object that functions like a map linking domain names to sets.
// It will not be modified later. A new one will be created each time settings are changed.
type Tree interface {
	Search(string) []ipSet
	Build(map[string]ipSet)
}

// NftSync is a plugin that synchronizes dns and nftables set.
type NftSync struct {
	Next plugin.Handler
	conn NetlinkConn

	tree   Tree
	family nftables.TableFamily
	table  *nftables.Table
	minttl uint32
	config map[string]ipSet

	zoneMetricLabel string
	viewMetricLabel string
}

// NewNftSync returns an initialized NftSync with default settings. It's up to the
// caller to set the Next handler.
func NewNftSync() *NftSync {
	return &NftSync{
		conn:   NewNetlinkFake(),
		tree:   &nametrie.TrieTree[ipSet]{},
		minttl: defaultMinTTL,
		config: make(map[string]ipSet),
	}
}

// SetConn injects connection to NftSync.
func (n *NftSync) SetConn(c NetlinkConn) { n.conn = c }

// SetTree injects tree to NftSync.
func (n *NftSync) SetTree(t Tree) { n.tree = t }

// Name implements plugin.Handler.
func (n *NftSync) Name() string { return "nftsync" }

// ServeDNS implements plugin.Handler.
func (n *NftSync) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	srv := metrics.WithServer(ctx)
	nw := NewResponseWriter(srv, w, n)
	return plugin.NextOrFailure(n.Name(), n.Next, ctx, nw, r)
}

const defaultMinTTL = uint32(dnsutil.MinimalDefaultTTL / time.Second)

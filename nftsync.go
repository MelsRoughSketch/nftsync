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
	nw := NewResponseWriter(srv, w, n, ctx)
	return plugin.NextOrFailure(n.Name(), n.Next, ctx, nw, r)
}

const defaultMinTTL = uint32(dnsutil.MinimalDefaultTTL / time.Second)

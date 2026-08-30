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
	"fmt"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	nft "github.com/google/nftables"
	"github.com/miekg/dns"
)

const defaultMinTTL = uint32(dnsutil.MinimalDefaultTTL / time.Second)

type ipSet struct {
	V4 *nft.Set
	V6 *nft.Set
}

// NftSync is a plugin that synchronizes dns and nftables set.
type NftSync struct {
	Next plugin.Handler
	conn NetlinkConn

	family nft.TableFamily
	table  *nft.Table
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
		minttl: defaultMinTTL,
		config: make(map[string]ipSet),
	}
}

// Name implements plugin.Handler.
func (n *NftSync) Name() string { return "nftsync" }

// ServeDNS implements plugin.Handler.
func (n *NftSync) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	srv := metrics.WithServer(ctx)
	nw := &ResponseWriter{server: srv, ResponseWriter: w, NftSync: n, ctx: ctx}
	return plugin.NextOrFailure(n.Name(), n.Next, ctx, nw, r)
}

func (ns *NftSync) updateSetByName(name string, v4, v6 []nft.SetElement) error {
	name = plugin.Name(name).Normalize()
	// ponytail: linear scan suits small static configs; restore an index if profiles show otherwise.
	for pattern, s := range ns.config {
		if pattern != name && (!strings.HasPrefix(pattern, "*.") || !dns.IsSubDomain(pattern[2:], name)) {
			continue
		}
		if err := addUpdatingElementMessage(ns.conn, s.V4, v4); err != nil {
			return err
		}
		if err := addUpdatingElementMessage(ns.conn, s.V6, v6); err != nil {
			return err
		}
	}
	return nil
}

// addUpdatingElementMessage adds message for atomic replace elements.
func addUpdatingElementMessage(n NetlinkConn, s *nft.Set, e []nft.SetElement) error {
	if len(e) == 0 || s == nil {
		return nil
	}

	if err := n.SetDestroyElements(s, e); err != nil {
		return fmt.Errorf("failed add message for destroy elm, set:%s, elm:%v, %v\n",
			getSetFullName(s), e, err)
	}

	if err := n.SetAddElements(s, e); err != nil {
		return fmt.Errorf("failed add message for add elm, set:%s, elm:%v, %v\n",
			getSetFullName(s), e, err)
	}
	return nil
}

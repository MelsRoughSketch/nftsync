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
	"time"

	nft "github.com/google/nftables"
	"github.com/miekg/dns"
)

const (
	TimeoutOffset uint32 = 5
	maxCNAMEHops  int    = 20
)

type resolvedTarget struct {
	name       string
	v4Elements []nft.SetElement
	v6Elements []nft.SetElement
}

// ResponseWriter observes the RRs
// and adds the results to nftset via netlink conn.
type ResponseWriter struct {
	dns.ResponseWriter
	*NftSync
	server string // Server hanling the request.
	ctx    context.Context
}

func (r *ResponseWriter) WriteMsg(res *dns.Msg) error {
	qname := res.Question[0].Name
	ttlConverter := getTTLConverter(r.minttl)

	switch res.Question[0].Qtype {
	// handling queries that return results in the answer section
	case dns.TypeA, dns.TypeAAAA:
		names, v4, v6, err := parseAnswer(r.ctx, qname, res.Answer, ttlConverter)
		if err != nil {
			return err
		}
		for _, n := range names {
			if err = r.NftSync.updateSetByName(n, v4, v6); err != nil {
				return err
			}
		}

	// handling queries that initiate a new communication using info from additional section
	case dns.TypeNS, dns.TypeMX, dns.TypeSRV, dns.TypeSVCB, dns.TypeHTTPS:
		for n, results := range parseExtra(qname, res.Extra, ttlConverter) {
			if err := r.NftSync.updateSetByName(n, results.v4Elements, results.v6Elements); err != nil {
				return err
			}
		}

	default:
	}

	if err := r.conn.Flush(); err != nil {
		updateFailureCount.WithLabelValues(r.server, r.zoneMetricLabel, r.viewMetricLabel, qname).Inc()
		return err
	}

	return r.ResponseWriter.WriteMsg(res)
}

// closure for getting ttl
func getTTLConverter(minttl uint32) func(uint32) time.Duration {
	return func(ttl uint32) time.Duration {
		if ttl < minttl {
			ttl = minttl
		}
		return time.Duration(ttl+TimeoutOffset) * time.Second
	}
}

func parseAnswer(ctx context.Context, qname string, answer []dns.RR, c func(uint32) time.Duration) (
	[]string, []nft.SetElement, []nft.SetElement, error) {
	nodes := make(map[string]*resolvedTarget)

	for _, rr := range answer {
		h := rr.Header()
		name := h.Name

		if nodes[name] == nil {
			nodes[name] = &resolvedTarget{}
		}

		switch res := rr.(type) {
		case *dns.CNAME:
			nodes[name].name = res.Target
		case *dns.A:
			nodes[name].v4Elements = append(nodes[name].v4Elements, nft.SetElement{Key: res.A.To4(), Timeout: c(h.Ttl)})
		case *dns.AAAA:
			nodes[name].v6Elements = append(nodes[name].v6Elements, nft.SetElement{Key: res.AAAA.To16(), Timeout: c(h.Ttl)})
		}
	}

	curr := qname
	var v4Elms, v6Elms []nft.SetElement
	var names []string
	visited := make(map[string]bool)

	for i := range maxCNAMEHops {
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		default:
		}

		// loop check
		if visited[curr] {
			return nil, nil, nil, fmt.Errorf("CNAME loop detected at %s", curr)
		}
		visited[curr] = true

		node, exists := nodes[curr]
		if !exists {
			break
		}

		names = append(names, curr)
		if node.v4Elements != nil {
			v4Elms = append(v4Elms, node.v4Elements...)
		}
		if node.v6Elements != nil {
			v6Elms = append(v6Elms, node.v6Elements...)
		}

		if node.name == "" {
			break
		}
		curr = node.name

		if i == maxCNAMEHops-1 {
			return nil, nil, nil, fmt.Errorf("exceeded max CNAME jumps (%d)", maxCNAMEHops)
		}
	}
	return names, v4Elms, v6Elms, nil
}

func parseExtra(qname string, extra []dns.RR, c func(uint32) time.Duration) map[string]*resolvedTarget {
	results := make(map[string]*resolvedTarget, len(extra))

	for _, rr := range extra {
		h := rr.Header()
		name := h.Name

		// in-domain check
		if !dns.IsSubDomain(qname, name) {
			continue
		}

		if results[name] == nil {
			results[name] = &resolvedTarget{}
		}
		switch res := rr.(type) {
		case *dns.A:
			results[name].v4Elements = append(results[name].v4Elements, nft.SetElement{Key: res.A.To4(), Timeout: c(h.Ttl)})
		case *dns.AAAA:
			results[name].v6Elements = append(results[name].v6Elements, nft.SetElement{Key: res.AAAA.To16(), Timeout: c(h.Ttl)})
		}
	}
	return results
}

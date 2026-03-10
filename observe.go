package nftsync

import (
	"time"

	nft "github.com/google/nftables"
	"github.com/miekg/dns"
)

const TimeoutOffset uint32 = 5

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
}

// NewResponseWriter returns a pointer to a new ResponseWriter
func NewResponseWriter(srv string, w dns.ResponseWriter, n *NftSync) *ResponseWriter {
	return &ResponseWriter{server: srv, ResponseWriter: w, NftSync: n}
}

func (r *ResponseWriter) WriteMsg(res *dns.Msg) error {

	qname := res.Question[0].Name

	// ignore Additional Section(res.Extra)
	ns, v4, v6 := extractNameAndIPs(qname, res.Answer, getTTLConverter(r.minttl))
	err := updateSetByNames(r.NftSync, ns, v4, v6)
	if err != nil {
		return err
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

func extractNameAndIPs(qname string, answer []dns.RR, c func(uint32) time.Duration) (names []string, v4Elms, v6Elms []nft.SetElement) {
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
			nodes[name].v4Elements = append(nodes[name].v4Elements, nft.SetElement{Key: res.A, Timeout: c(h.Ttl)})
		case *dns.AAAA:
			nodes[name].v6Elements = append(nodes[name].v6Elements, nft.SetElement{Key: res.AAAA, Timeout: c(h.Ttl)})
		}
	}

	curr := qname
	for {
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
	}
	return
}

// for mocking addUpdateElementMessage
type elementUpdater func(NetlinkConn, *nft.Set, []nft.SetElement) error

var addUpdateElementFunc elementUpdater = addUpdateElementMessage

func updateSetByNames(ns *NftSync, names []string, v4, v6 []nft.SetElement) error {
	for _, n := range names {
		sets := ns.tree.Search(n)
		for _, s := range sets {
			if err := addUpdateElementFunc(ns.conn, s.V4, v4); err != nil {
				return err
			}
			if err := addUpdateElementFunc(ns.conn, s.V6, v6); err != nil {
				return err
			}
		}
	}
	return nil
}

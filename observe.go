package nftsync

import (
	"net"
	"time"

	nft "github.com/google/nftables"
	"github.com/miekg/dns"
)

const TimeoutOffset uint32 = 5

type record struct {
	ip  net.IP
	ttl time.Duration
}

type dnsNode struct {
	targetName string
	ipv4       []record
	ipv6       []record
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
	if len(res.Question) == 0 {
		log.Debug("question length is zero.")
		return r.ResponseWriter.WriteMsg(res)
	}

	qname := res.Question[0].Name

	// ignore Additional Section(res.Extra)
	n, v4, v6 := extractNameAndIPs(qname, res.Answer, getTTLConverter(r.minttl))

	v4elm := convertElement(v4)
	v6elm := convertElement(v6)

	updateSetByNames(r.NftSync, n, v4elm, v6elm)
	if err := r.Flush(); err != nil {
		updateFailureCount.WithLabelValues(
			r.server, r.zoneMetricLabel, r.viewMetricLabel, qname).Inc()
		log.Error(err)
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

func extractNameAndIPs(qname string, answer []dns.RR, c func(uint32) time.Duration) (names []string, ipv4 []record, ipv6 []record) {
	nodes := make(map[string]*dnsNode)

	for _, rr := range answer {
		h := rr.Header()
		n := h.Name

		if nodes[n] == nil {
			nodes[n] = &dnsNode{}
		}

		switch res := rr.(type) {
		case *dns.CNAME:
			nodes[n].targetName = res.Target
		case *dns.A:
			nodes[n].ipv4 = append(nodes[n].ipv4, record{ip: res.A, ttl: c(h.Ttl)})
		case *dns.AAAA:
			nodes[n].ipv6 = append(nodes[n].ipv6, record{ip: res.AAAA, ttl: c(h.Ttl)})
		}
	}

	curr := qname
	for {
		node, offset := nodes[curr]
		if !offset {
			break
		}

		names = append(names, curr)
		if node.ipv4 != nil {
			ipv4 = append(ipv4, node.ipv4...)
		}
		if node.ipv6 != nil {
			ipv6 = append(ipv6, node.ipv6...)
		}

		if node.targetName == "" {
			break
		}
		curr = node.targetName
	}
	return
}

func convertElement(rs []record) []nft.SetElement {
	e := make([]nft.SetElement, 0, len(rs))
	for _, r := range rs {
		e = append(e, nft.SetElement{Key: r.ip, Timeout: r.ttl})
	}
	return e
}

func updateSetByNames(ns *NftSync, names []string, v4elm []nft.SetElement, v6elm []nft.SetElement) {
	for _, n := range names {
		set := ns.Search(n)
		for _, s := range set {
			if err := addUpdateElementMessage(ns.NetlinkConn, s.v4Set, v4elm); err != nil {
				loggingFailure(s.v4Set, v4elm, err)
			}
			if err := addUpdateElementMessage(ns.NetlinkConn, s.v6Set, v6elm); err != nil {
				loggingFailure(s.v6Set, v6elm, err)
			}
		}
	}
}

func loggingFailure(s *nft.Set, e []nft.SetElement, err error) {
	log.Errorf("failed add message for update set:%s, elm:%v, %v\n",
		getSetFullName(s), e, err)
}

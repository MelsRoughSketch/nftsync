package nftsync

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	nft "github.com/google/nftables"
)

type Flag string

const (
	add                Flag            = "add"
	destroy            Flag            = "dsy"
	defaultTableName   string          = "t"
	defaultTableFamily nft.TableFamily = nft.TableFamilyINet
	defaultSetV4Name   string          = "s4"
	defaultSetV6Name   string          = "s6"
	defaultTimeout     time.Duration   = 10 * time.Minute

	// phantomSet declare ipv4_addr
	phantomSetName string = "e"

	batchPrefix = "[NFT_BATCH]"
	nilFamily   = "nilfam"
	nilTable    = "niltab"
)

// for Stringer
type fakeElement nft.SetElement

func (e *fakeElement) String() string {
	return fmt.Sprintf("%s, timeout %s", net.IP(e.Key), e.Timeout)
}

func castSlice(vals []nft.SetElement) (es []fakeElement) {
	for _, v := range vals {
		es = append(es, fakeElement(v))
	}
	return
}

type fakeSetMessage struct {
	Set   *nft.Set
	Elems []fakeElement
	Flag  Flag
}

func (m fakeSetMessage) String() string {
	var s []string
	for _, e := range m.Elems {
		s = append(s, e.String())
	}

	var family, table string
	if m.Set.Table == nil {
		family = nilFamily
		table = nilTable
	} else {
		family = getStringFamily(m.Set.Table.Family)
		table = m.Set.Table.Name
	}

	return fmt.Sprintf("%s %s %s %s %s: {%s}\n",
		batchPrefix, m.Flag, family, table, m.Set.Name, s)
}

// NetlinkFake implements NetlinkConn.
type NetlinkFake struct {
	m         []fakeSetMessage
	prevbatch []fakeSetMessage
}

func NewNetlinkFake() *NetlinkFake { return &NetlinkFake{} }

// String implements Stringer.
func (n *NetlinkFake) String() string {
	var s strings.Builder
	for _, m := range n.m {
		s.WriteString(m.String())
	}
	return s.String()
}

func (n *NetlinkFake) ListTableOfFamily(name string, family nft.TableFamily) (*nft.Table, error) {
	if name == defaultTableName {
		return &nft.Table{Name: name, Family: family}, nil
	}
	return nil, fmt.Errorf("missing table name: %s", name)
}

func (n *NetlinkFake) GetSetByName(t *nft.Table, name string) (*nft.Set, error) {
	if t == nil {
		panic("recieved nil")
	}
	if name == defaultSetV4Name || name == phantomSetName {
		return &nft.Set{Table: t, Name: name}, nil
	}
	if name == defaultSetV6Name {
		return &nft.Set{Table: t, Name: name}, nil
	}
	return nil, fmt.Errorf("missing set name: %s", name)
}

func (n *NetlinkFake) SetDestroyElements(s *nft.Set, vals []nft.SetElement) error {
	if s == nil {
		panic("recieved nil")
	}
	n.m = append(n.m, fakeSetMessage{Set: s, Elems: castSlice(vals), Flag: destroy})
	return nil
}

func (n *NetlinkFake) SetAddElements(s *nft.Set, vals []nft.SetElement) error {
	if s == nil {
		panic("recieved nil")
	}
	n.m = append(n.m, fakeSetMessage{Set: s, Elems: castSlice(vals), Flag: add})
	return nil
}

func (n *NetlinkFake) Flush() error {
	log.Info(n)
	defer func() { n.prevbatch = n.m; n.m = nil }()

	for _, m := range n.m {
		if m.Set.Name == phantomSetName {
			return errors.New("detected set name e, return err")
		}

		for _, e := range m.Elems {
			addr, ok := netip.AddrFromSlice(e.Key)
			if !ok {
				return errors.New("invalid ip format")
			}

			switch m.Set.Name {
			case defaultSetV4Name, phantomSetName:
				if addr.Is6() {
					return errors.New("invalid family")
				}
			case defaultSetV6Name:
				if addr.Is4() {
					return errors.New("invalid family")
				}
			}
		}
	}
	return nil
}

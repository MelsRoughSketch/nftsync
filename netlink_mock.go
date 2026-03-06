package nftsync

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/nftables"
	nft "github.com/google/nftables"
)

type Flag string

const (
	add                Flag            = "add"
	destroy            Flag            = "destroy"
	defaultTableName   string          = "t"
	defaultTableFamily nft.TableFamily = nft.TableFamilyINet
	defaultSetV4Name   string          = "s4"
	defaultSetV6Name   string          = "s6"
	defaultTimeout     time.Duration   = 10 * time.Minute

	// phantomSet declare ipv4_addr
	phantomSetName string = "e"
)

type mockElement nftables.SetElement

func (e *mockElement) String() string {
	return fmt.Sprintf("%s, timeout %s;", net.IP(e.Key), e.Timeout)
}

func castSlice(vals []nftables.SetElement) (es []mockElement) {
	for _, v := range vals {
		es = append(es, mockElement(v))
	}
	return
}

type nlSetMessage struct {
	s       *nftables.Set
	es      []mockElement
	f       Flag
	invalid bool
}

func (n nlSetMessage) String() string {
	var s []string
	for _, e := range n.es {
		s = append(s, e.String())
	}
	return fmt.Sprintf("%s %s %s %s: {%s}",
		n.f, getStringFamily(n.s.Table.Family), n.s.Table.Name, n.s.Name, s)
}

type NetlinkMock struct {
	m         []nlSetMessage
	prevbatch string
}

func NewNetlinkMock() *NetlinkMock { return &NetlinkMock{} }

func (n *NetlinkMock) ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error) {
	if name == defaultTableName {
		return &nftables.Table{Name: name, Family: family}, nil
	}
	return nil, fmt.Errorf("not found table name: %s", name)
}

func (n *NetlinkMock) GetSetByName(t *nftables.Table, name string) (*nftables.Set, error) {
	if t == nil {
		panic("recieved nil")
	}
	if name == defaultSetV4Name || name == phantomSetName {
		return &nftables.Set{Table: t, Name: name}, nil
	}
	if name == defaultSetV6Name {
		return &nftables.Set{Table: t, Name: name}, nil
	}
	return nil, fmt.Errorf("not found set name: %s", name)
}

func (n *NetlinkMock) SetDestroyElements(s *nftables.Set, vals []nftables.SetElement) error {
	if s == nil {
		panic("recieved nil")
	}
	n.m = append(n.m, nlSetMessage{s: s, es: castSlice(vals), f: destroy})
	return nil
}

func (n *NetlinkMock) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	if s == nil {
		panic("recieved nil")
	}
	n.m = append(n.m, nlSetMessage{s: s, es: castSlice(vals), f: add})
	return nil
}

func (n *NetlinkMock) Flush() error {
	log.Info(n)

	// Compare the strings later to test.
	n.prevbatch = n.String()
	defer func() { n.m = nil }()

	for _, m := range n.m {
		if m.s.Name == phantomSetName {
			return errors.New("detected set name e, return err")
		}

		for _, e := range m.es {
			addr, ok := netip.AddrFromSlice(e.Key)
			if !ok {
				return errors.New("invalid ip format")
			}

			switch m.s.Name {
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

func (n *NetlinkMock) String() string {
	var s strings.Builder
	for _, m := range n.m {
		s.WriteString("[NFT_BATCH] " + m.String() + "\n")
	}
	return s.String()
}

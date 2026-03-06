package nftsync

import (
	"strconv"

	"github.com/google/nftables"
)

// NetlinkConn consists of the Netlink socket operations required by nftsync.
type NetlinkConn interface {
	ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error)
	GetSetByName(t *nftables.Table, name string) (*nftables.Set, error)
	SetDestroyElements(s *nftables.Set, vals []nftables.SetElement) error
	SetAddElements(s *nftables.Set, vals []nftables.SetElement) error
	Flush() error
}

func NewConnector() (NetlinkConn, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// addUpdateElementMessage adds message for atomic replace elements.
func addUpdateElementMessage(n NetlinkConn, s *nftables.Set, e []nftables.SetElement) error {
	if len(e) == 0 || s == nil {
		return nil
	}

	if err := n.SetDestroyElements(s, e); err != nil {
		return err
	}
	return n.SetAddElements(s, e)
}

func getStringFamily(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyUnspecified:
		return "unspec"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ipv4"
	case nftables.TableFamilyIPv6:
		return "ipv6"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyNetdev:
		return "netdev"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return "code_" + strconv.Itoa(int(f))
	}
}

func getSetFullName(s *nftables.Set) string {
	if s == nil || s.Table == nil {
		return ""
	}
	return getStringFamily(s.Table.Family) + "_" + s.Table.Name + "_" + s.Name
}

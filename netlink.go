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
	"fmt"
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
		return fmt.Errorf("failed add message for destroy elm, set:%s, elm:%v, %v\n",
			getSetFullName(s), e, err)
	}

	if err := n.SetAddElements(s, e); err != nil {
		return fmt.Errorf("failed add message for add elm, set:%s, elm:%v, %v\n",
			getSetFullName(s), e, err)
	}
	return nil
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

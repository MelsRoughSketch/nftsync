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
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/google/nftables"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("nftsync")

func init() { plugin.Register("nftsync", setup) }

func setup(c *caddy.Controller) error {

	ns, err := NftSyncParse(c)
	if err != nil {
		return plugin.Error("nftsync", err)
	}

	c.OnStartup(func() error {
		ns.viewMetricLabel = dnsserver.GetConfig(c).ViewName

		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ns.Next = next
		return ns
	})

	return nil
}

func NftSyncParse(c *caddy.Controller) (*NftSync, error) {
	ns := NewNftSync()
	ns.zoneMetricLabel = dnsserver.GetConfig(c).Zone
	conn, err := NewConnector()
	if err != nil {
		return nil, err
	}
	ns.SetConn(conn)

	j := 0

	for c.Next() {
		if j > 0 {
			return nil, plugin.ErrOnce
		}
		j++

		// nftsync [debug] family table_name [minttl]
		args := c.RemainingArgs()
		if len(args) < 2 || 4 < len(args) {
			return nil, c.ArgErr()
		}

		if args[0] == "debug" {
			log.Infof("mocking netlink connection, zone:%s", ns.zoneMetricLabel)
			ns.SetConn(NewNetlinkFake())
			args = args[1:]
		}

		// first args may family
		if family, ok := getTableFamilyByName(args[0]); ok {
			ns.family = family
		} else {
			return nil, fmt.Errorf("nftsync Table family is invalid value: %s", args[0])
		}

		//second args may table name
		table, err := ns.conn.ListTableOfFamily(args[1], ns.family)
		if err != nil {
			return nil, fmt.Errorf("nftsync Table not found: %s, %v", args[1], err)
		}
		ns.table = table

		if len(args) == 3 {
			// last args may be just a number, then it is the ttl
			if ttl, err := strconv.ParseUint(args[2], 10, 32); err == nil {
				if ttl <= 0 {
					return nil, fmt.Errorf("nftsync minTTL can not be zero or negative: %d", ttl)
				}
				ns.minttl = uint32(ttl)
			} else {
				return nil, c.ArgErr()
			}
		}

		// In an extra block
		for c.NextBlock() {
			switch c.Val() {
			case "sync":
				args := c.RemainingArgs()
				// tree or host, name, v4set, v6set
				if len(args) != 4 {
					return nil, c.ArgErr()
				}

				var isTree bool
				switch strings.ToLower(args[0]) {
				case "tree":
					isTree = true
				case "host":
					isTree = false
				default:
					return nil, fmt.Errorf("invalid flags: %s", args[0])
				}

				nn := plugin.Name(args[1]).Normalize()
				if _, ok := dns.IsDomainName(nn); !ok {
					return nil, fmt.Errorf("invalid domain name: %s", args[1])
				}

				if strings.Contains(nn, "*") {
					return nil, fmt.Errorf("name contains '*'. "+
						"regex matching is not supported, please consider using the tree flag: %s", nn)
				}

				// TODO: refactoring
				// the current Tree implicitly requires a feature that handles `*.`
				fn := nn
				if isTree {
					fn = "*." + nn
				}

				sets := [2]*nftables.Set{}
				for i, idx := range []int{2, 3} {
					s, err := ns.conn.GetSetByName(ns.table, args[idx])
					if err != nil {
						log.Warningf("nftset not found binding %s, set: %s, %v", nn, args[idx], err)
					} else {
						// nil if missing set
						sets[i] = s
					}
				}

				// to optimize tree traversal, execute only if the set is found
				if sets[0] != nil || sets[1] != nil {
					ns.config[fn] = ipSet{V4: sets[0], V6: sets[1]}
				}

			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	ns.tree.Build(ns.config)
	return ns, nil
}

func getTableFamilyByName(name string) (nftables.TableFamily, bool) {
	switch strings.ToLower(name) {
	case "inet":
		return nftables.TableFamilyINet, true
	case "ipv4":
		return nftables.TableFamilyIPv4, true
	case "ipv6":
		return nftables.TableFamilyIPv6, true
	default:
		return 0, false
	}
}

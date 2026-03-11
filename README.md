# What is this
This is an **unofficial** plugin for [CoreDNS](https://coredns.io/).

## Name
*nftsync* - synchronizes dns and nftables sets.

## Description
*nftsync* inspects DNS responses and adds the resolved IP addresses to a specified nftset. It is designed to bridge the gap between DNS resolution and firewall dynamic filtering.

## Syntax
```txt
nftsync [debug] FAMILY TABLE_NAME [MINTTL] {
        sync host|tree NAME IPv4_SET_NAME IPv6_SET_NAME
}
```
* `debug` will mocks Netlink socket to fake connection.
It also records the operation it attempted to perform to stdout.
It simulates the presence of the following nftables configuration. 
```txt
  table inet t {
          set s4 {
                  type ipv4_addr
                  flags dynamic,timeout
          }

          set s6 {
                  type ipv6_addr
                  flags dynamic,timeout
          }

          // This set exists at startup
          // but always behaves as if it fails when updating elements.
          set e {
                  type ipv4_addr
                  flags dynamic,timeout
          }
  }
  ```

* **FAMILY** and **TABLE_NAME** are the nftables table and its family containing the target sets.

* **MINTTL** - determines the minimum timeout value of the IP elements. The default is 5 seconds, which is the `minTTL` of the *cache* plugin.
(In other words, by default, IP addresses are retained in the set for at least 5 seconds.)<br>
If this value is set shorter than *cache* plugin's `minTTL`, you will be unable to update set 
using the query response until the cache entry expires. Therefore, we recommend setting a value 
equal to or greater than the minimum `minTTL` specified in the *cache* plugin configuration.

* `sync` - qname of a request, or a name used in a CNAME contained within RRs, matches the `NAME`, 
add the result of the A record to `IPv4_SET_NAME` and the result of the AAAA record to `IPv6_SET_NAME`.<br>
  * When adding query results to a `nftset`, **the `Timeout`/`Expires` parameters of the set elements are updated atomically** 
via Netlink socket. 
These parameters will be set to values that include a small margin (5 seconds) added to the entry's TTL.<br>
Elements are only removed by `Expires`. 
When a query resolves, old IPs are not explicitly cleared.<br>
***Note:** Results returned in the `additional section` are **not** processed by nftsync.*

* `host|tree` - when you want to target all leaves of `NAME` 
(if specifying each hostname individually is cumbersome), using `tree` will target all subdomains.

You can declare as many `sync`s consecutively as you like.

## Metrics
If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

* `coredns_nftsync_update_failure_count_total{"server", "zone", "view", "name"}` - Counter for the number of failed updates to ip elements. <br>
If this value is increasing, it is likely that set operations failed due to factors such as the set being deleted after the CoreDNS startup.


## Examples
In this configration, `nftsync` adds the IP address to set s4/s6 when a response related to example.org is returned. <br>
This setting applies not only to **example.org**. but also to subdomains such as **sub.example.org**.<br>

```txt
. {
        forward . 9.9.9.9
        nftsync inet t {
                sync tree example.org s4 s6
        }
}
```
At this point, the nftables configuration looks like this:
```txt
table inet t {
        set s4 {
                type ipv4_addr
                flags dynamic,timeout
                // It will be added when name resolution occurs.
                + elements = { 104.18.26.120 timeout 1m36s expires 1m34s576ms, ... }
        }

        set s6 {
                type ipv6_addr
                flags dynamic,timeout
        }
}
```

## Considerations
1. Only works on Linux
2. Requires POSIX capabilities for Netlink
3. I recommend placing *nftsync* after *cache*
4. Currently, it is not possible to specify a particular namespace.

---
### Regarding the possibility of race conditions
When used in combination with plugins such as *view*, 
individual query and *nftsync* blocks may cause race conditions 
regarding the timeout parameter for the **same nftset**. <br>
The following settings are recommended:
* one set pair(IPv4/IPv6) per domain name
* Avoid using the **EXACTLY THE SAME** domain name settings across multiple query routings<br>
(When the destination is AD or similar and the resolved domain name is local, 
duplicates are allowed, but use a different set pair.)


## LICENSE
**All Right Reserved** For Now. <br>
Copyright (c) [2026] [MelsRoughSketch]
   All rights reserved.
   No part of this software may be reproduced, distributed, 
   or transmitted in any form or by any means, including photocopying, 
   recording, or other electronic or mechanical methods, without the prior
   written permission of the copyright holder.

## DISCLAIMER
   This repository may be released under a more permissive license.
   In such a cases only, the following disclaimer shall apply:
      Under no circumstances shall I have any liability to you for 
      any loss or damage of any kind incurred as a result of the
      use of this project. Your use of the project and your reliance 
      on any information is solely at your own risk.
   (As mentioned earlier, it is All rights reserved for now.) 
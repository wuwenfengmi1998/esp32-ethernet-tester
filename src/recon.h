#pragma once

#include <Arduino.h>
#include "w5500_raw.h"
#include "ip_stack.h"

// =============================================================================
// Network reconnaissance module
//
//   - reconPassive : silently sniff broadcast/multicast traffic and infer the
//                    local topology (ARP, DHCP, mDNS, LLMNR, NetBIOS, CDP/LLDP)
//   - reconSweep   : ICMP ping sweep of a subnet (active host discovery)
//   - reconTrace   : ICMP traceroute to a target (TTL expiry walk)
// =============================================================================

// Passively observe traffic for `seconds`, summarising hosts and protocols.
void reconPassive(W5500Raw &eth, uint32_t seconds);

// Ping every host in [startIp, endIp] inclusive; prints responders + RTT.
uint32_t reconSweep(W5500Raw &eth, IpStack &ip, uint32_t startIp, uint32_t endIp);

// ICMP traceroute to `target` up to `maxHops`.
void reconTrace(W5500Raw &eth, IpStack &ip, uint32_t target, uint8_t maxHops = 20);

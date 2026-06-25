#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// DHCPv6 assessment (RFC 8415) -- client probe and rogue server
// (authorized testing only)
//
//   - dhcpv6Probe : SOLICIT and decode ADVERTISE/REPLY to verify a DHCPv6
//                   server, revealing its DUID, offered IA address and DNS
//   - dhcpv6Rogue : answer SOLICIT (ADVERTISE) and REQUEST (REPLY), handing out
//                   addresses from `prefix`::/64 and advertising our DNS, to
//                   take over stateful IPv6 addressing
//
// All frames are emitted at L2 over the W5500 in MACRAW mode (EtherType 0x86DD,
// UDP 546/547). Source addresses are the device link-local (EUI-64) address.
// =============================================================================

// SOLICIT and report any DHCPv6 server response within `seconds`. Returns true
// if a server replied.
bool dhcpv6Probe(W5500Raw &eth, const uint8_t srcMac[6], uint32_t seconds);

// Run a rogue DHCPv6 server for `seconds`. `prefix16` is a 16-byte base address
// whose last byte is incremented per lease; `dns16` is the DNS server handed to
// clients (16 bytes). Returns the number of leases offered.
uint32_t dhcpv6Rogue(W5500Raw &eth, const uint8_t srcMac[6],
                     const uint8_t prefix16[16], const uint8_t dns16[16],
                     uint32_t seconds);

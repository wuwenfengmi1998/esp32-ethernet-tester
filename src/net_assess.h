#pragma once

#include <Arduino.h>
#include "w5500_raw.h"
#include "ip_stack.h"

// =============================================================================
// Combined network assessment — ping sweep + ARP scan + port scan in one pass
//
// Runs three phases over a given IP range:
//   1. Ping sweep   — ICMP echo to discover live hosts
//   2. ARP scan     — L2 discovery (finds hosts that block ICMP)
//   3. Port scan    — TCP SYN probe of each discovered host
//
// The IP range can be specified as start/end IPs or as a CIDR subnet.
// =============================================================================

// Parse a CIDR notation string (e.g. "192.168.1.0/24") into start and end IPs
// (host order). Returns true on success.
bool cidrToRange(const char *cidr, uint32_t *startIp, uint32_t *endIp);

// Flags for netAssess options
#define ASSESS_RANDOMIZE_ORDER  0x01   // Shuffle host and port scan order
#define ASSESS_RANDOMIZE_MAC   0x02   // Randomize source MAC per target host

// Run the combined assessment. `ports` is a list of TCP ports to scan on each
// live host. If ports is nullptr, defaults to {21, 22, 80, 443}.
// Returns the total number of live hosts found.
uint32_t netAssess(W5500Raw &eth, IpStack &ip, const uint8_t srcMac[6],
                   uint32_t startIp, uint32_t endIp,
                   const uint16_t *ports = nullptr, uint32_t nPorts = 0,
                   uint8_t flags = 0);

#pragma once

#include <Arduino.h>

// =============================================================================
// Capture filter engine -- supports a subset of Wireshark/tcpdump BPF syntax.
//
// Supported primitives:
//   arp, ip, ip6, tcp, udp, icmp, vlan
//   host <ip>          -- matches src OR dst IP
//   src host <ip>      -- matches source IP only
//   dst host <ip>      -- matches destination IP only
//   net <ip/cidr>      -- matches src OR dst in subnet
//   src net <ip/cidr>
//   dst net <ip/cidr>
//   port <n>           -- matches src OR dst port (TCP/UDP)
//   src port <n>
//   dst port <n>
//   ether host <mac>   -- matches src OR dst MAC
//   ether src <mac>
//   ether dst <mac>
//   portrange <lo>-<hi>
//
// Combinators:
//   and, or, not, ( )
//
// Examples:
//   "tcp and port 80"
//   "host 192.168.1.1 and not arp"
//   "udp and portrange 5000-6000"
//   "ether host aa:bb:cc:dd:ee:ff"
//   "net 10.0.0.0/8"
//   "(tcp or udp) and dst port 443"
// =============================================================================

// Maximum number of filter nodes (expression tree). Increase if needed.
#define PCAP_FILTER_MAX_NODES 32

// Parse a filter expression string. Returns true on success (or if filter is
// empty/null -- which means "capture everything"). On failure, prints error
// message and returns false.
bool pcapFilterCompile(const char *expr);

// Clear the compiled filter (accept all frames).
void pcapFilterClear();

// Returns true if a filter is currently active.
bool pcapFilterActive();

// Evaluate the compiled filter against a raw Ethernet frame.
// Returns true if the frame passes (should be captured).
bool pcapFilterMatch(const uint8_t *frame, uint16_t len);

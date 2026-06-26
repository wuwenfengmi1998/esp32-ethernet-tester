#pragma once

#include <Arduino.h>
#include "w5500_raw.h"
#include "ip_stack.h"

// =============================================================================
// TCP port scanner / service prober (authorized testing only)
//
// Builds TCP segments by hand over the W5500 MACRAW driver (the hardware TCP/IP
// stack is intentionally unused). Supports:
//   - SYN scan of a port list or range  (open / closed / filtered)
//   - banner grab via a full three-way handshake on a single open port
// =============================================================================

// Enable/disable port order randomization for scan functions.
void tcpScanSetRandomize(bool enable);

// SYN-scan ports [first, last] inclusive on `target`. Prints open ports.
// Returns the number of open ports found.
uint32_t tcpSynScan(W5500Raw &eth, IpStack &ip, uint32_t target,
                    uint16_t first, uint16_t last, uint32_t perPortMs = 300);

// SYN-scan an explicit list of common ports on `target`.
uint32_t tcpScanCommon(W5500Raw &eth, IpStack &ip, uint32_t target, uint32_t perPortMs = 300);

// SYN-scan a caller-supplied array of ports on `target`.
uint32_t tcpScanPortList(W5500Raw &eth, IpStack &ip, uint32_t target,
                         const uint16_t *ports, uint32_t nPorts, uint32_t perPortMs = 300);

// SYN-scan ports then banner-grab each open port. Returns number of open ports.
// `openPorts` (if non-null) is filled with the open port numbers (up to maxOpen).
uint32_t tcpScanAndBanner(W5500Raw &eth, IpStack &ip, uint32_t target,
                          const uint16_t *ports, uint32_t nPorts,
                          uint16_t *openPorts = nullptr, uint32_t maxOpen = 0,
                          uint32_t perPortMs = 300);

// Full handshake to target:port, optionally send `probe`, then print up to
// `maxBytes` of returned banner data. Returns true if the port was open.
bool tcpBannerGrab(W5500Raw &eth, IpStack &ip, uint32_t target, uint16_t port,
                   const char *probe, uint32_t maxBytes = 256, uint32_t timeoutMs = 2000);

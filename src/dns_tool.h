#pragma once

#include <Arduino.h>
#include "w5500_raw.h"
#include "ip_stack.h"

// =============================================================================
// DNS assessment module (authorized testing only)
//
//   - dnsResolve : unicast DNS A-record query via the configured gateway/DNS
//   - dnsSpoof   : listen for DNS queries on the wire and inject forged replies,
//                  redirecting the queried name(s) to our IP (authorized lab use)
//
// All frames are emitted at L2 over the W5500 in MACRAW mode (EtherType 0x0800).
// DNS uses UDP port 53.
// =============================================================================

// Resolve a hostname via unicast DNS A-record query. `dnsServer` is the DNS
// server IP (host order); if 0 uses the IP stack gateway. Prints result.
// Returns resolved IP (host order) or 0 on failure.
uint32_t dnsResolve(W5500Raw &eth, IpStack &ip, const char *hostname,
                    uint32_t dnsServer = 0, uint32_t timeoutMs = 3000);

// Run a rogue DNS responder for `seconds`. Answers any A-record query with
// `spoofIp`. Returns the number of queries answered.
// Requires armed mode (offensive test).
uint32_t dnsSpoof(W5500Raw &eth, const uint8_t srcMac[6], uint32_t spoofIp,
                  uint32_t seconds);

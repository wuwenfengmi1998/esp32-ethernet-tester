#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// IPv6 / NDP assessment module (authorized testing only)
//
//   - ipv6Listen : passively decode ICMPv6 NDP traffic (RS/RA/NS/NA/Redirect)
//   - ipv6RogueRa: transmit rogue Router Advertisements (SLAAC takeover) to
//                  install this device as the default IPv6 router / DNS
//
// All frames are emitted at L2 over the W5500 in MACRAW mode (EtherType 0x86DD).
// =============================================================================

// Sniff and decode ICMPv6 NDP messages for `seconds`. Returns count decoded.
uint32_t ipv6Listen(W5500Raw &eth, uint32_t seconds);

// Send `count` rogue Router Advertisements (router lifetime `lifetime` s,
// advertising prefix 2001:db8:1::/64 for SLAAC). Use lifetime 0 to *withdraw*.
void ipv6RogueRa(W5500Raw &eth, const uint8_t src[6], uint16_t lifetime,
                 uint32_t count, uint32_t intervalMs = 1000);

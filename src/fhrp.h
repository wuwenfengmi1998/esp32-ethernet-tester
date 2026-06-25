#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// FHRP (First-Hop Redundancy Protocol) assessment -- HSRP and VRRP
// (authorized testing only)
//
//   - fhrpListen : passively decode HSRP (UDP/1985) and VRRP (IP proto 112)
//                  advertisements, revealing groups, virtual IPs and priorities
//   - hsrpHijack : send HSRP Hellos as the ACTIVE router with max priority,
//                  sourced from the HSRP virtual MAC (00:00:0c:07:ac:GG), to
//                  take over the default gateway
//   - vrrpHijack : send VRRP advertisements with max priority, sourced from the
//                  VRRP virtual MAC (00:00:5e:00:01:VR), to take over the master
//
// All frames are emitted at L2 over the W5500 in MACRAW mode (EtherType 0x0800).
// A real source IPv4 must be configured on the tester for hijack frames.
// =============================================================================

// Sniff and decode HSRP + VRRP for `seconds`. Returns count of messages decoded.
uint32_t fhrpListen(W5500Raw &eth, uint32_t seconds);

// Become the HSRP active router for `group` advertising `virtualIp` at
// `priority` (default 255). Sends `count` Hellos `intervalMs` apart. The first
// frame is a Coup to force preemption.
void hsrpHijack(W5500Raw &eth, const uint8_t srcMac[6], uint32_t srcIp,
                uint8_t group, uint32_t virtualIp, uint8_t priority,
                uint32_t count, uint32_t intervalMs = 3000);

// Become the VRRP master for `vrid` advertising `virtualIp` at `priority`
// (default 255 = address owner). Sends `count` advertisements `intervalMs`
// apart, sourced from the VRRP virtual MAC so switches redirect gateway traffic.
void vrrpHijack(W5500Raw &eth, const uint8_t srcMac[6], uint32_t srcIp,
                uint8_t vrid, uint32_t virtualIp, uint8_t priority,
                uint32_t count, uint32_t intervalMs = 1000);

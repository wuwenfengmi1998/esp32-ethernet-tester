#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// Layer-2 switch assessment / attack module (authorized testing only)
//
// Validates switch hardening by exercising the classic L2 weaknesses:
//   - VLAN hopping (single 802.1Q tag and double-tagging / Q-in-Q)
//   - DTP trunk negotiation (Cisco Dynamic Trunking Protocol)
//   - CAM-table (MAC address) flooding
//   - Spanning-tree: passive BPDU decode, root-bridge takeover, TCN injection
//   - LLDP / CDP neighbour-table flooding
//
// All frames are emitted at L2 over the W5500 in MACRAW mode.
// =============================================================================

// ---- VLAN hopping ----
// Inject `count` test frames carrying a single 802.1Q tag for `vid`.
void l2VlanSingle(W5500Raw &eth, const uint8_t src[6], uint16_t vid,
                  uint8_t pcp, uint32_t count);

// Double-tagging (Q-in-Q) hop: outer tag = `nativeVid`, inner tag = `targetVid`.
// A frame that escapes onto `targetVid` when the trunk's native VLAN matches.
void l2VlanDouble(W5500Raw &eth, const uint8_t src[6],
                  uint16_t nativeVid, uint16_t targetVid, uint32_t count);

// ---- DTP ----
// Send a Cisco DTP "desirable" frame to try to negotiate a trunk on the port.
void l2DtpTrunk(W5500Raw &eth, const uint8_t src[6]);

// ---- CAM flooding ----
// Flood the switch with frames bearing random source MACs to overflow the CAM
// table (tests port-security / MAC limits). rateHz caps the send rate.
void l2MacFlood(W5500Raw &eth, uint32_t count, uint32_t rateHz);

// ---- Spanning tree ----
// Listen for and decode STP/RSTP BPDUs for `seconds`. Returns count decoded.
uint32_t l2StpListen(W5500Raw &eth, uint32_t seconds);

// Claim the root bridge by transmitting superior Configuration BPDUs with
// priority `priority` for `seconds` (hello every 2 s). Tests BPDU/Root Guard.
void l2StpRoot(W5500Raw &eth, const uint8_t src[6], uint16_t priority, uint32_t seconds);

// Inject `count` Topology Change Notification BPDUs (forces MAC table flushes).
void l2StpTcn(W5500Raw &eth, const uint8_t src[6], uint32_t count);

// ---- Discovery-protocol flooding ----
// Flood `count` LLDP or CDP advertisements with randomised device identities.
void l2LldpFlood(W5500Raw &eth, uint32_t count);
void l2CdpFlood (W5500Raw &eth, uint32_t count);

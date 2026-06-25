#pragma once

#include <Arduino.h>
#include "w5500_raw.h"
#include "ip_stack.h"

// =============================================================================
// ARP assessment toolkit (authorized testing only)
//
//   - arpScan       : sweep a range and list responders (live-host discovery)
//   - arpGratuitous : announce an IP->MAC binding (cache poisoning primitive)
//   - arpSpoof      : bidirectional MITM between a victim and the gateway
//   - arpStorm      : flood ARP requests (broadcast-domain stress test)
//
// All frames are emitted at L2 over the W5500 in MACRAW mode.
// =============================================================================

// Sweep [startIp, endIp] inclusive (host-order). Prints each responder's IP+MAC.
uint32_t arpScan(W5500Raw &eth, const uint8_t src[6], uint32_t srcIp,
                 uint32_t startIp, uint32_t endIp);

// Send `count` gratuitous ARP replies binding `ip` to our `src` MAC.
void arpGratuitous(W5500Raw &eth, const uint8_t src[6], uint32_t ip, uint32_t count);

// MITM: for `seconds`, repeatedly tell `victimIp` that `gatewayIp` is at our MAC
// and tell `gatewayIp` that `victimIp` is at our MAC. Resolves both real MACs
// first via the IP stack. Re-ARPs every 2 s. Any key aborts.
void arpSpoof(W5500Raw &eth, IpStack &ip, const uint8_t src[6],
              uint32_t victimIp, uint32_t gatewayIp, uint32_t seconds);

// Flood `count` ARP requests with random sender addresses (rateHz caps speed).
void arpStorm(W5500Raw &eth, const uint8_t src[6], uint32_t srcIp,
              uint32_t count, uint32_t rateHz);

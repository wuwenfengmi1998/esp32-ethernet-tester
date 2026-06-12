#pragma once

#include <Arduino.h>
#include "ip_stack.h"

// =============================================================================
// Multicast reachability probe (Ethernet / IP-stack side)
//
// Resolves a "<name>.local" hostname via multicast DNS (224.0.0.251:5353) over
// the minimal IP stack, then verifies reachability with an ICMP echo (ping).
// This is independent of the ESP32 Wi-Fi side mDNS responder.
// =============================================================================

// Resolve `name` (with or without a trailing ".local") to an IPv4 address via
// mDNS. Returns true and sets *ipOut on success.
bool mdnsResolve(IpStack &ip, const char *name, uint32_t *ipOut, uint32_t timeoutMs = 2000);

// Resolve `name` via mDNS and ping it. Prints progress/results to Serial.
// Returns true if the host both resolved and replied to at least one ping.
bool probeHostname(IpStack &ip, const char *name, uint8_t pingCount = 4);

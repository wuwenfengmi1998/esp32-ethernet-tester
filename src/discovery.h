#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// LLDP / CDP neighbour discovery (passive listener)
//
// The W5500 runs in MACRAW mode with no MAC filter, so it already receives the
// multicast frames a switch emits:
//   LLDP : DA 01:80:C2:00:00:0E, EtherType 0x88CC
//   CDP  : DA 01:00:0C:CC:CC:CC, 802.3 length + LLC/SNAP (OUI 00:00:0C, 0x2000)
//
// These helpers decode those PDUs and print the neighbour information
// (switch name, port, VLAN, platform, management address, etc.).
// =============================================================================

// Decode one received frame. If it is an LLDP or CDP PDU the decoded fields
// are printed to Serial and true is returned; otherwise false.
bool discoveryDecode(const uint8_t *frame, uint16_t len);

// Block and listen for LLDP/CDP frames for `seconds`, decoding each one.
// Pressing any key aborts early. Returns the number of PDUs decoded.
uint32_t discoveryListen(W5500Raw &eth, uint32_t seconds);

// =============================================================================
// Advertisement (transmit) configuration
// Fields are advertised in both LLDP and CDP PDUs where applicable.
// =============================================================================
struct DiscoveryAdvert {
    bool     lldpEnabled;       // advertise LLDP
    bool     cdpEnabled;        // advertise CDP
    char     sysName[40];       // LLDP System Name / CDP Device ID
    char     portId[32];        // LLDP Port ID / CDP Port ID
    char     platform[48];      // LLDP System Desc / CDP Platform+Version
    uint32_t mgmtIp;            // management IPv4 (0 = none), host byte order
    uint16_t vlan;              // port/native VLAN (0 = none)
    uint16_t ttl;               // advertised TTL (seconds)
    uint32_t intervalMs;        // transmit interval (ms)
};

// Initialise advertisement config with sensible defaults (both protocols off).
void discoveryAdvertInit(DiscoveryAdvert &a);

// Build an LLDP / CDP PDU into buf (without FCS). Returns frame length.
uint16_t buildLLDP(uint8_t *buf, const uint8_t src[6], const DiscoveryAdvert &a);
uint16_t buildCDP (uint8_t *buf, const uint8_t src[6], const DiscoveryAdvert &a);

// Transmit advertisements if enabled and the interval has elapsed.
// Call frequently from loop(). Non-blocking.
void discoveryAdvertTick(W5500Raw &eth, const uint8_t src[6], DiscoveryAdvert &a);

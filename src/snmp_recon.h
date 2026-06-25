#pragma once

#include <Arduino.h>
#include "w5500_raw.h"
#include "ip_stack.h"

// =============================================================================
// SNMP reconnaissance module (authorized testing only)
//
//   - snmpProbe    : probe a host for common community strings (public, private,
//                    etc.) via SNMPv1/v2c GET of sysDescr.0 (OID 1.3.6.1.2.1.1.1.0)
//   - snmpSweep    : probe an IP range for SNMP-responsive hosts using a given
//                    community string
//
// All frames are emitted at L2 over the W5500 in MACRAW mode (EtherType 0x0800).
// SNMP uses UDP port 161.
// =============================================================================

// Probe a single host with one or more community strings. Prints sysDescr if
// successful. Returns true if any community string was accepted.
bool snmpProbe(W5500Raw &eth, IpStack &ip, uint32_t target,
               const char *communities[] = nullptr, uint8_t numCommunities = 0,
               uint32_t timeoutMs = 2000);

// Probe an IP range for SNMP-responsive hosts using a single community string.
// Returns the number of hosts that responded.
uint32_t snmpSweep(W5500Raw &eth, IpStack &ip, uint32_t startIp, uint32_t endIp,
                   const char *community = "public", uint32_t timeoutMs = 1500);

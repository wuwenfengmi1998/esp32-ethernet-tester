#pragma once

#include <Arduino.h>

// =============================================================================
// Persistent configuration stored in NVS (ESP32 Preferences, namespace "tester")
//
// Holds Wi-Fi station credentials, the device hostname (used for the mDNS
// responder and as device identity), and is loaded automatically at boot so
// the tester reconnects to the last known network on power-up.
// =============================================================================
struct NetConfig {
    char     wifiSsid[33];      // up to 32 chars + NUL
    char     wifiPass[65];      // up to 64 chars + NUL (WPA2 max)
    char     hostname[33];      // device hostname (<hostname>.local)
    bool     wifiEnabled;       // attempt STA connection on boot

    // ---- IP / L3 test defaults (Ethernet side, applied to the IP stack) ----
    bool     useDhcp;           // true: obtain address via DHCP; false: static
    uint32_t staticIp;          // host-order IPv4 (used when useDhcp == false)
    uint32_t staticMask;
    uint32_t staticGw;
};

// Load configuration from NVS into `cfg`. Missing keys take sensible defaults.
void netConfigLoad(NetConfig &cfg);

// Persist the entire configuration to NVS.
void netConfigSave(const NetConfig &cfg);

// Reset NVS configuration to defaults (does not erase Wi-Fi until saved).
void netConfigDefaults(NetConfig &cfg);

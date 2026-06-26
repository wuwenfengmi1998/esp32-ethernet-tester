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
    bool     wifiEnabled;       // bring up the Wi-Fi management interface on boot

    // ---- Wi-Fi management mode ----
    bool     apMode;            // true: host own soft AP (field use); false: join infrastructure (STA)
    char     apSsid[33];        // soft-AP SSID  (empty -> derived from hostname)
    char     apPass[65];        // soft-AP passphrase (empty or <8 chars -> open network)

    // ---- 802.1X (EAPOL) supplicant credentials ----
    char     dot1xUser[33];     // 802.1X identity / username (EAP-MD5 + EAP-TLS)
    char     dot1xPass[65];     // 802.1X password (EAP-MD5)
    uint8_t  dot1xMethod;       // EAP method: 0 = EAP-MD5, 1 = EAP-TLS (certs)
    char     dot1xKeyPass[65];  // private-key passphrase for EAP-TLS (optional)
    uint8_t  dot1xTarget[6];    // target authenticator MAC (all-zeros = PAE multicast)
    uint32_t dot1xTargetIp;     // target IP (host-order, 0 = unused)

    // ---- IP / L3 test defaults (Ethernet side, applied to the IP stack) ----
    bool     useDhcp;           // true: obtain address via DHCP; false: static
    uint32_t staticIp;          // host-order IPv4 (used when useDhcp == false)
    uint32_t staticMask;
    uint32_t staticGw;

    // ---- Safety ----
    bool     authorizedMode;    // gates disruptive/offensive tests (must be armed)

    // ---- Behaviour ----
    bool     randomMacDefault;  // auto-randomize src MAC before operations (off by default)
};

// Load configuration from NVS into `cfg`. Missing keys take sensible defaults.
void netConfigLoad(NetConfig &cfg);

// Persist the entire configuration to NVS.
void netConfigSave(const NetConfig &cfg);

// Reset NVS configuration to defaults (does not erase Wi-Fi until saved).
void netConfigDefaults(NetConfig &cfg);

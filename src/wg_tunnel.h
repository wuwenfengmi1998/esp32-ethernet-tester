#pragma once

#include <Arduino.h>

// =============================================================================
// WireGuard VPN tunnel
//
// Provides encrypted remote access to the device CLI over a WireGuard tunnel.
// Configuration is persisted in NVS. The tunnel runs over Wi-Fi.
// A TCP listener on the WG interface accepts CLI connections (telnet-style).
// =============================================================================

#define WG_NVS_NS       "wg"
#define WG_TCP_PORT     23      // Telnet-style CLI port on WG interface
#define WG_KEY_LEN      44      // Base64-encoded WireGuard key length (32 bytes -> 44 chars)

struct WgConfig {
    bool     enabled;
    bool     webOff;            // Disable web server when tunnel is active
    char     localIp[16];       // IP of the ESP32 inside the tunnel (e.g. "10.0.0.2")
    char     privateKey[48];    // Base64 private key
    char     peerPubKey[48];    // Base64 public key of the peer/server
    char     endpoint[64];      // Peer endpoint hostname or IP
    uint16_t endpointPort;      // Peer endpoint port (default 51820)
    char     presharedKey[48];  // Optional pre-shared key (empty = none)
};

// Load config from NVS. Returns true if valid config exists.
bool wgLoadConfig(WgConfig &cfg);

// Save config to NVS.
void wgSaveConfig(const WgConfig &cfg);

// Clear config from NVS.
void wgClearConfig();

// Start the WireGuard tunnel (call after Wi-Fi is connected and time is synced).
// Returns true if tunnel was started successfully.
bool wgStart();

// Stop the WireGuard tunnel.
void wgStop();

// Returns true if the tunnel interface is currently active.
bool wgIsActive();

// Get the current config (read from NVS or RAM cache).
const WgConfig &wgGetConfig();

// Start the TCP CLI listener on the WG interface.
void wgTcpListenerStart();

// Call from loop() to accept and service TCP CLI clients.
void wgTcpListenerTick();

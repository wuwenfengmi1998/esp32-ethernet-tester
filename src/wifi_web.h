#pragma once

#include <Arduino.h>
#include <functional>
#include "net_config.h"

// =============================================================================
// Wi-Fi manager + ESPAsyncWebServer control interface.
//
// On begin():
//   - If Wi-Fi is enabled and credentials exist, connect as a station and
//     register an mDNS responder so the device is reachable as <hostname>.local.
//   - Otherwise (or on connection failure) start a fallback Access Point
//     ("ESP32-Tester-Setup") hosting the same web UI so credentials can be set.
//
// The web UI shows live status (read via a status-provider callback) and lets
// the user dispatch tester commands. Commands are queued and executed from the
// main loop (loop()) so the async server callbacks never block.
// =============================================================================

class WebControl {
public:
    using StatusFn  = std::function<String()>;                 // returns JSON
    using CommandFn = std::function<void(const String &)>;     // run a CLI command
    using ConfigFn  = std::function<void(const String &ssid,
                                         const String &pass,
                                         const String &host,
                                         bool wifiEnabled,
                                         bool apMode,
                                         const String &apSsid,
                                         const String &apPass)>;

    WebControl();

    void setStatusProvider(StatusFn fn) { _statusFn = fn; }
    void setCommandHandler(CommandFn fn) { _cmdFn = fn; }
    void setConfigHandler(ConfigFn fn)   { _cfgFn = fn; }

    // Connect Wi-Fi (or start AP) and start the web server.
    void begin(const NetConfig &cfg);

    // Drive queued command execution. Call from loop().
    void loop();

    bool isConnected() const { return _staConnected; }
    IPAddress ip()     const { return _ip; }

private:
    StatusFn  _statusFn;
    CommandFn _cmdFn;
    ConfigFn  _cfgFn;

    bool      _staConnected = false;
    bool      _apMode       = false;
    IPAddress _ip;
    char      _hostname[33];

    // Cached NVS config (for the web UI to display current settings).
    char      _cfgSsid[33] = {0};
    char      _cfgHost[33] = {0};
    bool      _cfgWifiEn   = false;
    bool      _cfgHasPass  = false;
    bool      _cfgApMode   = false;
    char      _cfgApSsid[33] = {0};
    bool      _cfgApHasPass = false;

    // Live NVS config (for the cert/method status endpoint to read current
    // EAP method + key-passphrase state, which the CLI may change at runtime).
    const NetConfig *_cfgLive = nullptr;

    void *_server = nullptr;     // AsyncWebServer* (opaque to avoid header leak)
    void  _routes();
};

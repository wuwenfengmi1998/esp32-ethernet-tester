#pragma once

#include <Arduino.h>
#include <functional>
#include "net_config.h"

// =============================================================================
// Wi-Fi manager + web control interface (HTTP/HTTPS with optional basic auth).
// =============================================================================

#define WEB_AUTH_NVS_NS  "webauth"

class WebControl {
public:
    using StatusFn  = std::function<String()>;
    using CommandFn = std::function<void(const String &)>;
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

    // Stop / restart the web server (Wi-Fi stays connected).
    void stopServer();
    void startServer();
    bool isServerRunning() const { return _serverRunning; }

    // Drive queued command execution. Call from loop().
    void loop();

    bool isConnected() const { return _staConnected; }
    IPAddress ip()     const { return _ip; }

    // Authentication management
    void setAuthCredentials(const char *user, const char *pass);
    void clearAuth();
    bool isAuthEnabled() const { return _authEnabled; }

    // HTTPS management
    void enableHttps(bool enable);
    bool isHttpsEnabled() const { return _httpsEnabled; }

private:
    StatusFn  _statusFn;
    CommandFn _cmdFn;
    ConfigFn  _cfgFn;

    bool      _staConnected = false;
    bool      _apMode       = false;
    IPAddress _ip;
    char      _hostname[33];

    // Auth state
    bool      _authEnabled = false;
    char      _authUser[33] = {0};
    char      _authPass[65] = {0};

    // HTTPS state
    bool      _httpsEnabled = false;
    void     *_httpsHandle = nullptr;   // httpd_handle_t

    // Cached NVS config
    char      _cfgSsid[33] = {0};
    char      _cfgHost[33] = {0};
    bool      _cfgWifiEn   = false;
    bool      _cfgHasPass  = false;
    bool      _cfgApMode   = false;
    char      _cfgApSsid[33] = {0};
    bool      _cfgApHasPass = false;

    const NetConfig *_cfgLive = nullptr;

    void *_server = nullptr;     // AsyncWebServer*
    bool  _serverRunning = false;
    void  _routes();
    void  _loadAuth();
    void  _applyAuth();
    void  _startHttps();
    void  _stopHttps();
};

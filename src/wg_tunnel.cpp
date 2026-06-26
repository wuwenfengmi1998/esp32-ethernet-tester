#include "wg_tunnel.h"
#include "../include/config.h"
#include "weblog.h"
#include <WireGuard-ESP32.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiServer.h>
#include <Preferences.h>
#include <time.h>

#define Serial Out

// =============================================================================
// Statics
// =============================================================================
static WireGuard _wg;
static WgConfig  _cfg;
static bool      _active  = false;
static bool      _cfgValid = false;

// TCP CLI server
static WiFiServer *_tcpSrv = nullptr;
static WiFiClient  _tcpClient;
static String      _tcpLineBuf;

// Forward declaration (implemented in main.cpp or cli.cpp)
extern void wgRunCliCommand(const String &line, String &output);

// =============================================================================
// NVS persistence
// =============================================================================
bool wgLoadConfig(WgConfig &cfg)
{
    Preferences prefs;
    prefs.begin(WG_NVS_NS, true);
    cfg.enabled = prefs.getBool("enabled", false);
    cfg.webOff  = prefs.getBool("webOff", false);
    String lip = prefs.getString("localIp", "");
    String pk  = prefs.getString("privKey", "");
    String pub = prefs.getString("peerPub", "");
    String ep  = prefs.getString("endpoint", "");
    cfg.endpointPort = prefs.getUShort("port", 51820);
    String psk = prefs.getString("psk", "");
    prefs.end();

    strlcpy(cfg.localIp, lip.c_str(), sizeof(cfg.localIp));
    strlcpy(cfg.privateKey, pk.c_str(), sizeof(cfg.privateKey));
    strlcpy(cfg.peerPubKey, pub.c_str(), sizeof(cfg.peerPubKey));
    strlcpy(cfg.endpoint, ep.c_str(), sizeof(cfg.endpoint));
    strlcpy(cfg.presharedKey, psk.c_str(), sizeof(cfg.presharedKey));

    _cfg = cfg;
    _cfgValid = (cfg.localIp[0] && cfg.privateKey[0] && cfg.peerPubKey[0] && cfg.endpoint[0]);
    return _cfgValid;
}

void wgSaveConfig(const WgConfig &cfg)
{
    Preferences prefs;
    prefs.begin(WG_NVS_NS, false);
    prefs.putBool("enabled", cfg.enabled);
    prefs.putBool("webOff", cfg.webOff);
    prefs.putString("localIp", cfg.localIp);
    prefs.putString("privKey", cfg.privateKey);
    prefs.putString("peerPub", cfg.peerPubKey);
    prefs.putString("endpoint", cfg.endpoint);
    prefs.putUShort("port", cfg.endpointPort);
    prefs.putString("psk", cfg.presharedKey);
    prefs.end();
    _cfg = cfg;
    _cfgValid = (cfg.localIp[0] && cfg.privateKey[0] && cfg.peerPubKey[0] && cfg.endpoint[0]);
}

void wgClearConfig()
{
    Preferences prefs;
    prefs.begin(WG_NVS_NS, false);
    prefs.clear();
    prefs.end();
    memset(&_cfg, 0, sizeof(_cfg));
    _cfgValid = false;
}

// =============================================================================
// Tunnel control
// =============================================================================
bool wgStart()
{
    if (_active) {
        Serial.println("[WG] Tunnel already active.");
        return true;
    }
    if (!_cfgValid) {
        Serial.println("[WG] No valid config. Use 'wg set' to configure.");
        return false;
    }
    if (!WiFi.isConnected()) {
        Serial.println("[WG] Wi-Fi not connected. Tunnel requires Wi-Fi.");
        return false;
    }

    // Ensure time is synced (WireGuard needs valid timestamps)
    struct tm tm;
    if (!getLocalTime(&tm, 500)) {
        Serial.println("[WG] Syncing time via NTP...");
        configTime(0, 0, "pool.ntp.org", "time.google.com");
        int tries = 0;
        while (!getLocalTime(&tm, 1000) && tries < 10) { tries++; delay(500); }
        if (!getLocalTime(&tm, 500)) {
            Serial.println("[WG] NTP sync failed. Tunnel requires valid time.");
            return false;
        }
    }

    IPAddress localIp;
    if (!localIp.fromString(_cfg.localIp)) {
        Serial.printf("[WG] Invalid local IP: %s\r\n", _cfg.localIp);
        return false;
    }

    Serial.printf("[WG] Starting tunnel: %s -> %s:%u\r\n",
                  _cfg.localIp, _cfg.endpoint, _cfg.endpointPort);

    bool ok = _wg.begin(localIp, _cfg.privateKey, _cfg.endpoint,
                         _cfg.peerPubKey, _cfg.endpointPort);
    if (!ok) {
        Serial.println("[WG] Failed to start WireGuard interface.");
        return false;
    }
    _active = true;
    Serial.printf("[WG] Tunnel UP. CLI available on %s:%d\r\n",
                  _cfg.localIp, WG_TCP_PORT);
    return true;
}

void wgStop()
{
    if (!_active) return;
    _wg.end();
    _active = false;
    if (_tcpClient) _tcpClient.stop();
    Serial.println("[WG] Tunnel stopped.");
}

bool wgIsActive()
{
    return _active;
}

const WgConfig &wgGetConfig()
{
    return _cfg;
}

// =============================================================================
// TCP CLI listener (telnet-style, no auth, single client)
// =============================================================================
void wgTcpListenerStart()
{
    if (_tcpSrv) return;
    _tcpSrv = new WiFiServer(WG_TCP_PORT);
    _tcpSrv->begin();
    _tcpSrv->setNoDelay(true);
}

void wgTcpListenerTick()
{
    if (!_tcpSrv || !_active) return;

    // Accept new client (one at a time)
    if (!_tcpClient || !_tcpClient.connected()) {
        WiFiClient newClient = _tcpSrv->accept();
        if (newClient) {
            _tcpClient = newClient;
            _tcpLineBuf = "";
            _tcpClient.println("=== Ethernet Tester CLI (WireGuard) ===");
            _tcpClient.print("> ");
        }
    }

    if (!_tcpClient || !_tcpClient.connected()) return;

    // Read available data
    while (_tcpClient.available()) {
        char c = _tcpClient.read();
        if (c == '\r') continue;
        if (c == '\n') {
            _tcpLineBuf.trim();
            if (_tcpLineBuf.length() > 0) {
                if (_tcpLineBuf.equalsIgnoreCase("exit") ||
                    _tcpLineBuf.equalsIgnoreCase("quit")) {
                    _tcpClient.println("Bye.");
                    _tcpClient.stop();
                    _tcpLineBuf = "";
                    return;
                }
                // Execute command and capture output
                String output;
                wgRunCliCommand(_tcpLineBuf, output);
                _tcpClient.print(output);
            }
            _tcpClient.print("> ");
            _tcpLineBuf = "";
        } else if (_tcpLineBuf.length() < 200) {
            _tcpLineBuf += c;
        }
    }
}

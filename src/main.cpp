#include <Arduino.h>
#include "../include/config.h"
#include "w5500_raw.h"
#include "packet.h"
#include "error_inject.h"
#include "rfc2544.h"
#include "ip_stack.h"
#include "dhcp_test.h"
#include "net_config.h"
#include "net_probe.h"
#include "wifi_web.h"
#include "cert_store.h"
#include "pcap.h"
#include "cli.h"
#include "wg_tunnel.h"
#include "weblog.h"
#include <WiFi.h>

// =============================================================================
// Global state
// =============================================================================
static uint8_t srcMac[6] = TESTER_MAC_DEF;
static uint8_t dstMac[6] = BROADCAST_MAC;

static NetConfig   netCfg;

static W5500Raw    eth(PIN_W5500_CS, PIN_W5500_RST);
static ErrorInject inj(eth, srcMac, dstMac);
static RFC2544     rfc(eth, srcMac, dstMac);
static IpStack     ipStack(eth, srcMac);
static DhcpTest    dhcp(ipStack, srcMac);
static CLI         serialCli(eth, inj, rfc, ipStack, dhcp, netCfg, srcMac, dstMac);
WebControl         web;

// The Waveshare ESP32-S3-POE-ETH has no plain status LED (the onboard LED is a
// WS2812 RGB on GPIO21). GPIO2 is left free here as a generic status output.
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

// =============================================================================
// WireGuard TCP CLI bridge — executes a command and returns captured output
// =============================================================================
void wgRunCliCommand(const String &line, String &output)
{
    Out.beginCapture();
    serialCli.runCommand(line);
    Out.snapshot(output);
    Out.endCapture();
}

// =============================================================================
// setup
// =============================================================================
void setup()
{
    Serial.begin(CLI_BAUD);
    while (!Serial && millis() < 3000) {}

    netConfigLoad(netCfg);

    // Mount the certificate store (LittleFS) used by the EAP-TLS supplicant.
    certStoreBegin();

    // Initialise TF (micro-SD) card for PCAP storage (optional).
    pcapSdInit();

    Serial.println("\r\nInitialising W5500...");

    if (!eth.begin(srcMac)) {
        Serial.println("ERROR: W5500 initialisation failed!");
        Serial.println("Check SPI wiring and RST/CS pins.");
        // Blink built-in LED to signal fault (non-fatal — keep trying)
        pinMode(LED_BUILTIN, OUTPUT);
        while (true) {
            digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
            delay(200);
        }
    }

    Serial.println("W5500 OK.");

    // Report initial link state
    if (eth.isLinked()) {
        uint8_t phy = eth.phyCfgr();
        Serial.printf("Link UP  %s %s-duplex\r\n",
                      (phy & PHYCFGR_SPD) ? "100 Mbps" : "10 Mbps",
                      (phy & PHYCFGR_DPX) ? "full" : "half");
    } else {
        Serial.println("Link DOWN (connect cable to CX6300).");
    }

    // Apply a static IP immediately if configured (DHCP can be run on demand).
    if (!netCfg.useDhcp && netCfg.staticIp) {
        ipStack.setAddress(netCfg.staticIp, netCfg.staticMask, netCfg.staticGw);
        Serial.println("IP: static address applied from NVS.");
    }

    // Wi-Fi + web control interface (auto-connects from NVS or starts AP).
    web.setStatusProvider([]() { return serialCli.statusJson(); });
    web.setCommandHandler([](const String &c) { serialCli.runCommand(c); });
    web.setConfigHandler([](const String &ssid, const String &pass,
                            const String &host, bool wifiEn,
                            bool apMode, const String &apSsid,
                            const String &apPass) {
        if (ssid.length()) strncpy(netCfg.wifiSsid, ssid.c_str(), sizeof(netCfg.wifiSsid) - 1);
        if (pass.length()) strncpy(netCfg.wifiPass, pass.c_str(), sizeof(netCfg.wifiPass) - 1);
        if (host.length()) strncpy(netCfg.hostname, host.c_str(), sizeof(netCfg.hostname) - 1);
        if (apSsid.length()) strncpy(netCfg.apSsid, apSsid.c_str(), sizeof(netCfg.apSsid) - 1);
        if (apPass.length()) strncpy(netCfg.apPass, apPass.c_str(), sizeof(netCfg.apPass) - 1);
        netCfg.wifiEnabled = wifiEn;
        netCfg.apMode      = apMode;
        netConfigSave(netCfg);
    });
    web.begin(netCfg);

    // WireGuard VPN tunnel (auto-start if configured + Wi-Fi is connected)
    WgConfig wgCfg;
    if (wgLoadConfig(wgCfg) && wgCfg.enabled) {
        // Delay start until Wi-Fi connects (handled in loop)
    }

    serialCli.begin();
}

// =============================================================================
// loop
// =============================================================================
void loop()
{
    serialCli.process();          // Read serial input, dispatch commands
    inj.tick();                   // Drive background storm / continuous injection
    serialCli.loopbackTick();     // Reflect frames if loopback mode is on
    serialCli.advertiseTick();    // Transmit LLDP/CDP advertisements if enabled
    web.loop();                   // Execute queued web commands
    wgTcpListenerTick();          // Service WireGuard TCP CLI clients

    // Auto-start WireGuard tunnel once Wi-Fi connects
    static bool _wgAutoStarted = false;
    if (!_wgAutoStarted && !wgIsActive() && wgGetConfig().enabled && WiFi.isConnected()) {
        if (wgStart()) {
            wgTcpListenerStart();
            // Stop web server if webOff is configured
            if (wgGetConfig().webOff) {
                web.stopServer();
            }
        }
        _wgAutoStarted = true;
    }
}

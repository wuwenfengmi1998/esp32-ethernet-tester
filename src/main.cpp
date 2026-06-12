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
#include "cli.h"

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
static WebControl  web;

// GPIO 2 is the commonly used status LED on ESP-WROOM32 dev boards
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

// =============================================================================
// setup
// =============================================================================
void setup()
{
    Serial.begin(CLI_BAUD);
    while (!Serial && millis() < 3000) {}

    netConfigLoad(netCfg);

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
                            const String &host, bool wifiEn) {
        if (ssid.length()) strncpy(netCfg.wifiSsid, ssid.c_str(), sizeof(netCfg.wifiSsid) - 1);
        if (pass.length()) strncpy(netCfg.wifiPass, pass.c_str(), sizeof(netCfg.wifiPass) - 1);
        if (host.length()) strncpy(netCfg.hostname, host.c_str(), sizeof(netCfg.hostname) - 1);
        netCfg.wifiEnabled = wifiEn;
        netConfigSave(netCfg);
    });
    web.begin(netCfg);

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
}

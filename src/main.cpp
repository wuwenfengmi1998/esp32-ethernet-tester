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
#include "scripting.h"
#include "weblog.h"
#include "display.h"
#include "battery.h"
#include "net_util.h"
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

// =============================================================================
// Power latch / button + status LED
// =============================================================================
static bool powerLatched = false;   // true once POWER_EN self-hold is engaged

static void powerInit()
{
    digitalWrite(PIN_POWER_EN, LOW);        // set level before OUTPUT: no glitch
    pinMode(PIN_POWER_EN, OUTPUT);
    pinMode(PIN_POWER_BUTTON, INPUT_PULLUP);

    digitalWrite(PIN_STATUS_LED, HIGH);     // active-low: start dark
    pinMode(PIN_STATUS_LED, OUTPUT);
}

// When the button is what powers the board, require a POWER_ON_HOLD_MS hold to
// latch POWER_EN high. If the button is not pressed (USB/external power), boot
// normally without latching. A release before the hold simply lets the board
// lose power on battery, or continues booting on external power.
static void powerOnLatch()
{
    if (digitalRead(PIN_POWER_BUTTON) != LOW) return;

    uint32_t pressStart = millis();
    while (digitalRead(PIN_POWER_BUTTON) == LOW) {
        if (millis() - pressStart >= POWER_ON_HOLD_MS) {
            digitalWrite(PIN_POWER_EN, HIGH);
            powerLatched = true;
            break;
        }
        delay(5);
    }
}

// Release the power latch after blanking the display. Shared by the
// power-button long press and the low-battery cut-off.
static void powerOff(const char *reason)
{
    displayShutdown();                  // stop refresh, blank + panel off
    digitalWrite(PIN_POWER_EN, LOW);
    digitalWrite(PIN_STATUS_LED, HIGH); // active-low: LED off as we power down
    powerLatched = false;
    Serial.printf("Powering off (%s)...\r\n", reason);
}

// Polled from loop(): blinks the status LED while powered on, and a
// POWER_OFF_HOLD_MS press releases the latch. The press that latched power on
// is ignored until it is released.
static void powerTick()
{
    static bool armed = false;      // false until the boot press is released
    static bool wasDown = false;
    static uint32_t pressStart = 0;
    static uint32_t blinkLast = 0;

    if (!powerLatched) {
        digitalWrite(PIN_STATUS_LED, HIGH);     // off in power-down state
        return;
    }

    if (millis() - blinkLast >= LED_BLINK_MS) {
        blinkLast = millis();
        digitalWrite(PIN_STATUS_LED, !digitalRead(PIN_STATUS_LED));
    }

    bool down = (digitalRead(PIN_POWER_BUTTON) == LOW);
    if (!down) {
        armed   = true;             // release seen: next press may power off
        wasDown = false;
        return;
    }
    if (!armed) return;             // still the initial hold that powered us on

    if (!wasDown) {
        pressStart = millis();
        wasDown = true;
    } else if (millis() - pressStart >= POWER_OFF_HOLD_MS) {
        powerOff("button hold");
    }
}

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
    // Power latch: release POWER_EN immediately, then latch it high if the
    // user holds the power button long enough.
    powerInit();
    powerOnLatch();

    Serial.begin(CLI_BAUD);
    while (!Serial && millis() < 3000) {}

    netConfigLoad(netCfg);

    // Mount the certificate store (LittleFS) used by the EAP-TLS supplicant.
    certStoreBegin();

    // Initialise TF (micro-SD) card for PCAP storage (optional).
    pcapSdInit();

    // Battery monitor (ADC + charge detect) and optional I2C status display.
    batteryInit();
    displayBegin();

    Serial.println("\r\nInitialising W5500...");

    if (!eth.begin(srcMac)) {
        Serial.println("ERROR: W5500 initialisation failed!");
        Serial.println("Check SPI wiring and RST/CS pins.");
        // Blink status LED to signal fault (non-fatal — keep trying)
        pinMode(PIN_STATUS_LED, OUTPUT);
        while (true) {
            digitalWrite(PIN_STATUS_LED, !digitalRead(PIN_STATUS_LED));
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

    // Status display: live page sourced from the same state as the web UI.
    displaySetStatusProvider([](DisplayStatus &st) {
        uint8_t phy = eth.phyCfgr();
        st.linkUp     = (phy & PHYCFGR_LNK) != 0;
        st.speed100   = (phy & PHYCFGR_SPD) != 0;
        st.fullDuplex = (phy & PHYCFGR_DPX) != 0;
        ipToStr(ipStack.ip(), st.ip);
        strncpy(st.host, netCfg.hostname, sizeof(st.host) - 1);
        st.uptimeSec  = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        st.heapKb     = (uint16_t)(ESP.getFreeHeap() / 1024);
        st.wifiUp     = WiFi.isConnected();
        if (st.wifiUp) {
            IPAddress wip = WiFi.localIP();
            snprintf(st.wifiIp, sizeof(st.wifiIp), "%u.%u.%u.%u",
                     (unsigned)wip[0], (unsigned)wip[1],
                     (unsigned)wip[2], (unsigned)wip[3]);
        }
        st.sdPresent  = pcapSdAvailable();
        st.charging   = batteryCharging();
        st.batteryMv  = (uint16_t)batteryVoltageMv();
        st.batteryPct = batteryPercent();
    });
    displayShowStatus();

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

    // Scripting engine: give it the CLI command runner
    scriptSetCommandHandler([](const String &c) { serialCli.runCommand(c); });
    cronInit();

    serialCli.begin();
}

// =============================================================================
// loop
// =============================================================================
void loop()
{
    powerTick();                  // Long-press power button to power off
    batteryTick();                // 1 Hz battery sample + low-voltage debounce
    if (powerLatched && batteryLow()) {
        powerOff("battery low");  // Protect the cell: ~3.3 V and not charging
    }
    serialCli.process();          // Read serial input, dispatch commands
    inj.tick();                   // Drive background storm / continuous injection
    serialCli.loopbackTick();     // Reflect frames if loopback mode is on
    serialCli.advertiseTick();    // Transmit LLDP/CDP advertisements if enabled
    web.loop();                   // Execute queued web commands
    cronTick();                   // Check cron scheduler
    wgTcpListenerTick();          // Service WireGuard TCP CLI clients
    displayTick();                // Refresh status page display (if present)

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

#include "net_config.h"
#include <Preferences.h>
#include <string.h>

static const char *NVS_NS = "tester";

void netConfigDefaults(NetConfig &cfg)
{
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.hostname, "esp32-tester", sizeof(cfg.hostname) - 1);
    cfg.wifiEnabled = false;
    cfg.apMode      = false;
    strncpy(cfg.apSsid, "ESP32-Tester", sizeof(cfg.apSsid) - 1);
    cfg.apPass[0]   = '\0';           // open network by default
    cfg.dot1xUser[0] = '\0';
    cfg.dot1xPass[0] = '\0';
    cfg.dot1xMethod  = 0;             // EAP-MD5 by default
    cfg.dot1xKeyPass[0] = '\0';
    cfg.useDhcp     = true;
    cfg.staticIp    = 0;
    cfg.staticMask  = 0xFFFFFF00UL;   // 255.255.255.0
    cfg.staticGw    = 0;
    cfg.authorizedMode = false;       // disruptive tests disabled until armed
}

void netConfigLoad(NetConfig &cfg)
{
    netConfigDefaults(cfg);

    Preferences p;
    if (!p.begin(NVS_NS, true)) {     // read-only
        return;                       // namespace absent: keep defaults
    }

    p.getString("ssid", cfg.wifiSsid, sizeof(cfg.wifiSsid));
    p.getString("pass", cfg.wifiPass, sizeof(cfg.wifiPass));
    if (p.isKey("host"))
        p.getString("host", cfg.hostname, sizeof(cfg.hostname));

    cfg.wifiEnabled = p.getBool("wifiEn", cfg.wifiEnabled);
    cfg.apMode      = p.getBool("apMode", cfg.apMode);
    if (p.isKey("apssid"))
        p.getString("apssid", cfg.apSsid, sizeof(cfg.apSsid));
    if (p.isKey("appass"))
        p.getString("appass", cfg.apPass, sizeof(cfg.apPass));
    if (p.isKey("d1xuser"))
        p.getString("d1xuser", cfg.dot1xUser, sizeof(cfg.dot1xUser));
    if (p.isKey("d1xpass"))
        p.getString("d1xpass", cfg.dot1xPass, sizeof(cfg.dot1xPass));
    cfg.dot1xMethod = (uint8_t)p.getUChar("d1xmeth", cfg.dot1xMethod);
    if (p.isKey("d1xkeypw"))
        p.getString("d1xkeypw", cfg.dot1xKeyPass, sizeof(cfg.dot1xKeyPass));
    if (p.isKey("d1xtgt"))
        p.getBytes("d1xtgt", cfg.dot1xTarget, 6);
    cfg.dot1xTargetIp = p.getUInt("d1xtgtip", cfg.dot1xTargetIp);
    cfg.useDhcp     = p.getBool("dhcp",   cfg.useDhcp);
    cfg.staticIp    = p.getUInt("ip",     cfg.staticIp);
    cfg.staticMask  = p.getUInt("mask",   cfg.staticMask);
    cfg.staticGw    = p.getUInt("gw",     cfg.staticGw);
    cfg.authorizedMode = p.getBool("authz", cfg.authorizedMode);
    cfg.randomMacDefault = p.getBool("rmacdf", cfg.randomMacDefault);

    p.end();
}

void netConfigSave(const NetConfig &cfg)
{
    Preferences p;
    if (!p.begin(NVS_NS, false)) {    // read-write
        return;
    }

    p.putString("ssid", cfg.wifiSsid);
    p.putString("pass", cfg.wifiPass);
    p.putString("host", cfg.hostname);
    p.putBool("wifiEn",  cfg.wifiEnabled);
    p.putBool("apMode",  cfg.apMode);
    p.putString("apssid", cfg.apSsid);
    p.putString("appass", cfg.apPass);
    p.putString("d1xuser", cfg.dot1xUser);
    p.putString("d1xpass", cfg.dot1xPass);
    p.putUChar("d1xmeth", cfg.dot1xMethod);
    p.putString("d1xkeypw", cfg.dot1xKeyPass);
    p.putBytes("d1xtgt", cfg.dot1xTarget, 6);
    p.putUInt("d1xtgtip", cfg.dot1xTargetIp);
    p.putBool("dhcp",    cfg.useDhcp);
    p.putUInt("ip",      cfg.staticIp);
    p.putUInt("mask",    cfg.staticMask);
    p.putUInt("gw",      cfg.staticGw);
    p.putBool("authz",   cfg.authorizedMode);
    p.putBool("rmacdf",  cfg.randomMacDefault);

    p.end();
}

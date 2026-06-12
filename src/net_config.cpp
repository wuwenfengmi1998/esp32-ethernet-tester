#include "net_config.h"
#include <Preferences.h>
#include <string.h>

static const char *NVS_NS = "tester";

void netConfigDefaults(NetConfig &cfg)
{
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.hostname, "esp32-tester", sizeof(cfg.hostname) - 1);
    cfg.wifiEnabled = false;
    cfg.useDhcp     = true;
    cfg.staticIp    = 0;
    cfg.staticMask  = 0xFFFFFF00UL;   // 255.255.255.0
    cfg.staticGw    = 0;
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
    cfg.useDhcp     = p.getBool("dhcp",   cfg.useDhcp);
    cfg.staticIp    = p.getUInt("ip",     cfg.staticIp);
    cfg.staticMask  = p.getUInt("mask",   cfg.staticMask);
    cfg.staticGw    = p.getUInt("gw",     cfg.staticGw);

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
    p.putBool("dhcp",    cfg.useDhcp);
    p.putUInt("ip",      cfg.staticIp);
    p.putUInt("mask",    cfg.staticMask);
    p.putUInt("gw",      cfg.staticGw);

    p.end();
}

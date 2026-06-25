#include "linkdiag.h"
#include "weblog.h"

#define Serial Out

void linkInfo(W5500Raw &eth)
{
    uint8_t phy = eth.phyCfgr();
    bool link = phy & PHYCFGR_LNK;
    bool spd  = phy & PHYCFGR_SPD;
    bool fdx  = phy & PHYCFGR_DPX;
    Serial.println("\r\nPhysical link diagnostics:");
    Serial.printf("  Link    : %s\r\n", link ? "UP" : "DOWN");
    Serial.printf("  Speed   : %s\r\n", spd ? "100 Mbps" : "10 Mbps");
    Serial.printf("  Duplex  : %s\r\n", fdx ? "Full" : "Half");
    Serial.printf("  PHYCFGR : 0x%02X\r\n", phy);
    if (link && !fdx)
        Serial.println("  NOTE: half-duplex -> possible duplex mismatch / collisions.");
    if (link && !spd)
        Serial.println("  NOTE: 10 Mbps -> check cabling / negotiation if 100 expected.");
}

void linkMonitor(W5500Raw &eth, uint32_t seconds)
{
    Serial.printf("\r\nMonitoring link for %lu s (any key aborts)...\r\n", (unsigned long)seconds);
    uint8_t last = eth.phyCfgr();
    bool lastLink = last & PHYCFGR_LNK;
    Serial.printf("  t=0  link %s, %s, %s\r\n", lastLink ? "UP" : "DOWN",
                  (last & PHYCFGR_SPD) ? "100M" : "10M", (last & PHYCFGR_DPX) ? "FD" : "HD");
    uint32_t start = millis();
    uint32_t deadline = start + seconds * 1000UL;
    uint32_t flaps = 0;
    while ((int32_t)(deadline - millis()) > 0) {
        uint8_t phy = eth.phyCfgr();
        bool link = phy & PHYCFGR_LNK;
        if (link != lastLink || (phy & (PHYCFGR_SPD | PHYCFGR_DPX)) != (last & (PHYCFGR_SPD | PHYCFGR_DPX))) {
            uint32_t t = (millis() - start);
            Serial.printf("  t=%lu.%03lus  link %s, %s, %s\r\n",
                          (unsigned long)(t / 1000), (unsigned long)(t % 1000),
                          link ? "UP" : "DOWN",
                          (phy & PHYCFGR_SPD) ? "100M" : "10M",
                          (phy & PHYCFGR_DPX) ? "FD" : "HD");
            if (link != lastLink) flaps++;
            lastLink = link; last = phy;
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        delay(20);
    }
    Serial.printf("Done. %lu link transition(s) observed.\r\n", (unsigned long)flaps);
}

#include "pcap.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <LittleFS.h>
#include <string.h>

#define Serial Out

// PCAP little-endian writers.
static inline void le32(uint8_t *p, uint32_t v)
{
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static inline void le16(uint8_t *p, uint16_t v)
{
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
}

uint32_t pcapCapture(W5500Raw &eth, uint32_t seconds, uint32_t maxFrames)
{
    File fp = LittleFS.open(PCAP_PATH, "w");
    if (!fp) { Serial.println("PCAP: cannot open capture file (LittleFS full?)."); return 0; }

    // Global header (24 bytes), network type 1 = Ethernet.
    uint8_t gh[24];
    le32(gh + 0, 0xA1B2C3D4UL);    // magic
    le16(gh + 4, 2); le16(gh + 6, 4);   // version 2.4
    le32(gh + 8, 0);               // thiszone
    le32(gh + 12, 0);              // sigfigs
    le32(gh + 16, ETH_MAX_LEN);    // snaplen
    le32(gh + 20, 1);              // LINKTYPE_ETHERNET
    fp.write(gh, 24);

    Serial.printf("\r\nCapturing to %s", PCAP_PATH);
    if (seconds)   Serial.printf(" for %lu s", (unsigned long)seconds);
    if (maxFrames) Serial.printf(", max %lu frames", (unsigned long)maxFrames);
    Serial.println(" (any key stops)...");

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = seconds ? (millis() + seconds * 1000UL) : 0;
    uint32_t n = 0, bytes = 24;
    uint32_t t0 = millis();

    while (true) {
        if (deadline && (int32_t)(deadline - millis()) <= 0) break;
        if (maxFrames && n >= maxFrames) break;
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len >= 14) {
            uint32_t ms = millis() - t0;
            uint8_t rh[16];
            le32(rh + 0, ms / 1000);
            le32(rh + 4, (ms % 1000) * 1000);   // usec
            le32(rh + 8, len);                  // incl_len
            le32(rh + 12, len);                 // orig_len
            fp.write(rh, 16);
            fp.write(buf, len);
            bytes += 16 + len;
            n++;
            if ((n & 0x3F) == 0) Serial.printf("  %lu frames (%lu bytes)...\r\n",
                                               (unsigned long)n, (unsigned long)bytes);
        } else {
            delay(1);
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
    }
    fp.close();
    Serial.printf("Capture done: %lu frame(s), %lu bytes saved to %s.\r\n",
                  (unsigned long)n, (unsigned long)bytes, PCAP_PATH);
    Serial.println("Download from the web UI (PCAP card) and open in Wireshark.");
    return n;
}

uint32_t pcapSize()
{
    if (!LittleFS.exists(PCAP_PATH)) return 0;
    File fp = LittleFS.open(PCAP_PATH, "r");
    if (!fp) return 0;
    uint32_t s = fp.size();
    fp.close();
    return s;
}

void pcapDelete()
{
    if (LittleFS.exists(PCAP_PATH)) LittleFS.remove(PCAP_PATH);
}

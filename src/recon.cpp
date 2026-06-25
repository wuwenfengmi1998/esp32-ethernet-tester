#include "recon.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <string.h>

#define Serial Out

// ---- Passive topology sniff ----
void reconPassive(W5500Raw &eth, uint32_t seconds)
{
    Serial.printf("\r\nPassive recon for %lu s (any key aborts)...\r\n", (unsigned long)seconds);
    struct Host { uint8_t mac[6]; uint32_t ip; uint32_t frames; };
    static Host hosts[32];
    uint8_t nHosts = 0;
    uint32_t cArp = 0, cDhcp = 0, cMdns = 0, cLlmnr = 0, cNbns = 0, cCdp = 0, cLldp = 0, cOther = 0;

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + seconds * 1000UL;
    uint32_t total = 0;

    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len < 14) { delay(1); continue; }
        total++;
        const uint8_t *sa = buf + 6;
        uint16_t et = get16(buf + 12);
        uint32_t srcIp = 0;

        if (et == 0x88CC) cLldp++;
        else if (et == ETHERTYPE_ARP) { cArp++; srcIp = get32(buf + 28); }
        else if (et == ETHERTYPE_IPV4 && len >= 34) {
            const uint8_t *ipw = buf + 14;
            srcIp = get32(ipw + 12);
            uint8_t ihl = (ipw[0] & 0x0F) * 4;
            uint8_t proto = ipw[9];
            if (proto == 17 && len >= 14 + ihl + 8) {
                const uint8_t *u = ipw + ihl;
                uint16_t dport = get16(u + 2);
                if (dport == 67 || dport == 68) cDhcp++;
                else if (dport == 5353) cMdns++;
                else if (dport == 5355) cLlmnr++;
                else if (dport == 137 || dport == 138) cNbns++;
                else cOther++;
            } else cOther++;
        } else if (len >= 22 && buf[14] == 0xAA && buf[20] == 0x20 && buf[21] == 0x00) {
            cCdp++;
        } else cOther++;

        // Track host by MAC (skip broadcast/multicast sources, which shouldn't occur).
        if (!(sa[0] & 0x01)) {
            int idx = -1;
            for (int i = 0; i < nHosts; i++) if (memcmp(hosts[i].mac, sa, 6) == 0) { idx = i; break; }
            if (idx < 0 && nHosts < 32) { idx = nHosts++; memcpy(hosts[idx].mac, sa, 6);
                hosts[idx].ip = 0; hosts[idx].frames = 0; }
            if (idx >= 0) { hosts[idx].frames++; if (srcIp && srcIp != 0xFFFFFFFF) hosts[idx].ip = srcIp; }
        }

        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
    }

    Serial.printf("\r\nObserved %lu frame(s). Protocol counts:\r\n", (unsigned long)total);
    Serial.printf("  ARP %lu  DHCP %lu  mDNS %lu  LLMNR %lu  NetBIOS %lu  CDP %lu  LLDP %lu  other %lu\r\n",
                  (unsigned long)cArp, (unsigned long)cDhcp, (unsigned long)cMdns,
                  (unsigned long)cLlmnr, (unsigned long)cNbns, (unsigned long)cCdp,
                  (unsigned long)cLldp, (unsigned long)cOther);
    Serial.printf("\r\nHosts seen (%u):\r\n", nHosts);
    for (int i = 0; i < nHosts; i++) {
        char ips[16]; ipToStr(hosts[i].ip, ips);
        Serial.printf("  %02X:%02X:%02X:%02X:%02X:%02X  %-15s  %lu frame(s)\r\n",
                      hosts[i].mac[0], hosts[i].mac[1], hosts[i].mac[2],
                      hosts[i].mac[3], hosts[i].mac[4], hosts[i].mac[5],
                      hosts[i].ip ? ips : "(unknown)", (unsigned long)hosts[i].frames);
    }
}

// ---- Active ping sweep ----
uint32_t reconSweep(W5500Raw &eth, IpStack &ip, uint32_t startIp, uint32_t endIp)
{
    (void)eth;
    if (endIp < startIp || (endIp - startIp) > 1024) {
        Serial.println("Range invalid or too large (max 1024 hosts)."); return 0;
    }
    char a[16], b[16]; ipToStr(startIp, a); ipToStr(endIp, b);
    Serial.printf("\r\nPing sweep %s - %s (any key aborts)...\r\n", a, b);
    uint32_t up = 0;
    for (uint32_t t = startIp; ; t++) {
        uint32_t rtt = 0;
        if (ip.ping(t, 300, &rtt)) {
            char ips[16]; ipToStr(t, ips);
            Serial.printf("  %-15s  up   %.2f ms\r\n", ips, rtt / 1000.0);
            up++;
        }
        if (Serial.available()) { while (Serial.available()) Serial.read();
            Serial.println("Aborted."); break; }
        if (t == endIp) break;
    }
    Serial.printf("Sweep complete: %lu host(s) up.\r\n", (unsigned long)up);
    return up;
}

// ---- Traceroute ----
// Build IP+ICMP echo with a specific TTL; returns frame length.
static uint16_t buildIcmpEcho(uint8_t *f, const uint8_t dstMac[6], const uint8_t srcMac[6],
                              uint32_t srcIp, uint32_t dstIp, uint8_t ttl,
                              uint16_t id, uint16_t seq)
{
    memcpy(f, dstMac, 6); memcpy(f + 6, srcMac, 6); put16(f + 12, ETHERTYPE_IPV4);
    uint8_t *ipw = f + 14;
    uint16_t icmpLen = 8;
    ipw[0] = 0x45; ipw[1] = 0;
    put16(ipw + 2, 20 + icmpLen);
    put16(ipw + 4, id);
    put16(ipw + 6, 0);
    ipw[8] = ttl; ipw[9] = 1;          // proto ICMP
    put16(ipw + 10, 0);
    put32(ipw + 12, srcIp); put32(ipw + 16, dstIp);
    put16(ipw + 10, inetChecksum(ipw, 20));
    uint8_t *ic = ipw + 20;
    ic[0] = 8; ic[1] = 0;              // echo request
    put16(ic + 2, 0);
    put16(ic + 4, id); put16(ic + 6, seq);
    put16(ic + 2, inetChecksum(ic, icmpLen));
    uint16_t flen = 14 + 20 + icmpLen;
    if (flen < 60) { memset(f + flen, 0, 60 - flen); flen = 60; }
    return flen;
}

void reconTrace(W5500Raw &eth, IpStack &ip, uint32_t target, uint8_t maxHops)
{
    uint32_t srcIp = ip.ip();
    if (srcIp == 0) { Serial.println("No local IP. Run DHCP or set static."); return; }
    uint8_t dstMac[6]; bool needArp = false;
    ip.destMacFor(target, dstMac, &needArp);
    if (needArp) {
        uint32_t nh = (((target ^ srcIp) & ip.mask()) != 0) ? ip.gw() : target;
        if (!ip.arpResolve(nh, dstMac, 1500)) { Serial.println("Next-hop ARP failed."); return; }
    }
    char ts[16]; ipToStr(target, ts);
    Serial.printf("\r\nTraceroute to %s, max %u hops:\r\n", ts, maxHops);

    uint16_t id = 0x6543;
    static uint8_t buf[ETH_MAX_LEN + 4];
    for (uint8_t ttl = 1; ttl <= maxHops; ttl++) {
        uint8_t f[60];
        uint32_t t0 = micros();
        uint16_t flen = buildIcmpEcho(f, dstMac, ip.mac(), srcIp, target, ttl, id, ttl);
        eth.sendFrame(f, flen);

        uint32_t fromIp = 0; int kind = -1;   // 0=echo reply (done), 11=time exceeded
        uint32_t deadline = millis() + 1500;
        while ((int32_t)(deadline - millis()) > 0) {
            uint16_t len = eth.recvFrame(buf, sizeof(buf));
            if (len < 42 || get16(buf + 12) != ETHERTYPE_IPV4) { delay(1); continue; }
            const uint8_t *ipw = buf + 14;
            if (ipw[9] != 1) continue;        // ICMP only
            uint8_t ihl = (ipw[0] & 0x0F) * 4;
            const uint8_t *ic = ipw + ihl;
            uint8_t type = ic[0];
            if (type == 0) {                  // echo reply -> reached target
                fromIp = get32(ipw + 12); kind = 0; break;
            } else if (type == 11) {          // time exceeded -> intermediate hop
                fromIp = get32(ipw + 12); kind = 11; break;
            }
        }
        uint32_t rtt = micros() - t0;
        if (kind < 0) {
            Serial.printf(" %2u   *  (timeout)\r\n", ttl);
        } else {
            char hs[16]; ipToStr(fromIp, hs);
            Serial.printf(" %2u   %-15s  %.2f ms\r\n", ttl, hs, rtt / 1000.0);
            if (kind == 0) { Serial.println("Reached target."); break; }
        }
        if (Serial.available()) { while (Serial.available()) Serial.read();
            Serial.println("Aborted."); break; }
    }
}

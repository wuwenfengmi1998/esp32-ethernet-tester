#include "dhcpv6.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <string.h>
#include <esp_random.h>

#define Serial Out

#define ETHERTYPE_IPV6 0x86DD
#define IPPROTO_UDP    17

// DHCPv6 message types
#define D6_SOLICIT   1
#define D6_ADVERTISE 2
#define D6_REQUEST   3
#define D6_REPLY     7
// DHCPv6 options
#define D6O_CLIENTID 1
#define D6O_SERVERID 2
#define D6O_IA_NA    3
#define D6O_IAADDR   5
#define D6O_ORO      6
#define D6O_ELAPSED  8
#define D6O_STATUS   13
#define D6O_DNS      23

// ---- helpers ----------------------------------------------------------------
static void linkLocal(const uint8_t mac[6], uint8_t ip6[16])
{
    memset(ip6, 0, 16);
    ip6[0] = 0xFE; ip6[1] = 0x80;
    ip6[8]  = mac[0] ^ 0x02;
    ip6[9]  = mac[1];
    ip6[10] = mac[2];
    ip6[11] = 0xFF; ip6[12] = 0xFE;
    ip6[13] = mac[3]; ip6[14] = mac[4]; ip6[15] = mac[5];
}

static void ip6ToStr(const uint8_t *a, char *out)
{
    char *p = out;
    for (int i = 0; i < 16; i += 2) { if (i) *p++ = ':'; p += sprintf(p, "%x", get16(a + i)); }
    *p = '\0';
}

static uint16_t udp6Checksum(const uint8_t *src, const uint8_t *dst,
                             const uint8_t *udp, uint32_t len)
{
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) sum += get16(src + i);
    for (int i = 0; i < 16; i += 2) sum += get16(dst + i);
    sum += (len >> 16) & 0xFFFF;
    sum += len & 0xFFFF;
    sum += IPPROTO_UDP;
    uint16_t c = inetChecksum(udp, len, sum);
    return c ? c : 0xFFFF;
}

// Build + send an IPv6/UDP datagram. Returns true on success.
static bool sendUdp6(W5500Raw &eth, const uint8_t srcMac[6], const uint8_t dstMac[6],
                     const uint8_t srcIp[16], const uint8_t dstIp[16],
                     uint16_t sport, uint16_t dport,
                     const uint8_t *payload, uint16_t plen)
{
    static uint8_t f[ETH_MAX_LEN + 4];
    memset(f, 0, 14 + 40 + 8);
    memcpy(f, dstMac, 6);
    memcpy(f + 6, srcMac, 6);
    put16(f + 12, ETHERTYPE_IPV6);

    uint8_t *ip = f + 14;
    ip[0] = 0x60;                       // version 6
    uint16_t udpLen = 8 + plen;
    put16(ip + 4, udpLen);              // payload length
    ip[6] = IPPROTO_UDP;                // next header
    ip[7] = 255;                        // hop limit
    memcpy(ip + 8, srcIp, 16);
    memcpy(ip + 24, dstIp, 16);

    uint8_t *udp = ip + 40;
    put16(udp + 0, sport);
    put16(udp + 2, dport);
    put16(udp + 4, udpLen);
    put16(udp + 6, 0);
    if (payload && plen) memcpy(udp + 8, payload, plen);
    put16(udp + 6, udp6Checksum(srcIp, dstIp, udp, udpLen));

    uint16_t frameLen = 14 + 40 + udpLen;
    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;
    return eth.sendFrame(f, frameLen);
}

static int putOpt(uint8_t *p, uint16_t code, const uint8_t *data, uint16_t len)
{
    put16(p, code); put16(p + 2, len);
    if (data && len) memcpy(p + 4, data, len);
    return 4 + len;
}

// Find a DHCPv6 option in [opts,opts+len). Returns pointer to option value and
// sets *olen, or nullptr if absent.
static const uint8_t *findOpt(const uint8_t *opts, int len, uint16_t code, uint16_t *olen)
{
    int i = 0;
    while (i + 4 <= len) {
        uint16_t c = get16(opts + i), l = get16(opts + i + 2);
        if (i + 4 + l > len) break;
        if (c == code) { if (olen) *olen = l; return opts + i + 4; }
        i += 4 + l;
    }
    return nullptr;
}

// All_DHCP_Relay_Agents_and_Servers ff02::1:2 + mapped MAC 33:33:00:01:00:02.
static const uint8_t kAllServers[16] = { 0xFF,0x02,0,0,0,0,0,0, 0,0,0,0,0,1,0,2 };
static const uint8_t kAllServersMac[6] = { 0x33,0x33,0x00,0x01,0x00,0x02 };

// =============================================================================
// Client probe
// =============================================================================
bool dhcpv6Probe(W5500Raw &eth, const uint8_t srcMac[6], uint32_t seconds)
{
    uint8_t srcIp[16]; linkLocal(srcMac, srcIp);
    uint8_t duid[10] = { 0x00,0x03, 0x00,0x01, srcMac[0],srcMac[1],srcMac[2],srcMac[3],srcMac[4],srcMac[5] };
    uint8_t xid[3]; esp_fill_random(xid, 3);

    Serial.println("\r\nDHCPv6 SOLICIT (any key aborts)...");

    // Build SOLICIT.
    uint8_t sol[128]; int o = 0;
    sol[o++] = D6_SOLICIT; sol[o++] = xid[0]; sol[o++] = xid[1]; sol[o++] = xid[2];
    o += putOpt(sol + o, D6O_CLIENTID, duid, sizeof(duid));
    uint8_t iana[12]; memset(iana, 0, 12);
    put32(iana, 0x12345678);                       // IAID
    o += putOpt(sol + o, D6O_IA_NA, iana, sizeof(iana));
    uint8_t elapsed[2] = { 0, 0 };
    o += putOpt(sol + o, D6O_ELAPSED, elapsed, 2);
    uint8_t oro[2]; put16(oro, D6O_DNS);
    o += putOpt(sol + o, D6O_ORO, oro, 2);

    sendUdp6(eth, srcMac, kAllServersMac, srcIp, kAllServers, 546, 547, sol, o);

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + seconds * 1000UL;
    bool sawServer = false;
    bool requested = false;
    uint8_t serverId[130]; uint16_t serverIdLen = 0;
    uint8_t iaAddr[16]; bool haveAddr = false;

    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len >= 14 + 40 + 8 && get16(buf + 12) == ETHERTYPE_IPV6) {
            const uint8_t *ip = buf + 14;
            if (ip[6] == IPPROTO_UDP) {
                const uint8_t *udp = ip + 40;
                uint16_t dport = get16(udp + 2);
                if (dport == 546) {
                    const uint8_t *d6 = udp + 8;
                    int d6len = (int)get16(udp + 4) - 8;
                    if (d6len > 4) {
                        uint8_t mtype = d6[0];
                        const uint8_t *opts = d6 + 4;
                        int olen = d6len - 4;
                        char ssrc[40]; ip6ToStr(ip + 8, ssrc);

                        if (mtype == D6_ADVERTISE || mtype == D6_REPLY) {
                            sawServer = true;
                            Serial.printf("\r\n<- DHCPv6 %s from %s\r\n",
                                          mtype == D6_ADVERTISE ? "ADVERTISE" : "REPLY", ssrc);
                            uint16_t l;
                            const uint8_t *sid = findOpt(opts, olen, D6O_SERVERID, &l);
                            if (sid && l <= sizeof(serverId)) {
                                memcpy(serverId, sid, l); serverIdLen = l;
                                Serial.printf("   server DUID : %u bytes\r\n", l);
                            }
                            uint16_t il;
                            const uint8_t *iana2 = findOpt(opts, olen, D6O_IA_NA, &il);
                            if (iana2 && il > 12) {
                                uint16_t al;
                                const uint8_t *ad = findOpt(iana2 + 12, il - 12, D6O_IAADDR, &al);
                                if (ad && al >= 16) {
                                    memcpy(iaAddr, ad, 16); haveAddr = true;
                                    char a[40]; ip6ToStr(iaAddr, a);
                                    Serial.printf("   offered addr: %s\r\n", a);
                                }
                            }
                            uint16_t dl;
                            const uint8_t *dns = findOpt(opts, olen, D6O_DNS, &dl);
                            for (uint16_t k = 0; dns && k + 16 <= dl; k += 16) {
                                char a[40]; ip6ToStr(dns + k, a);
                                Serial.printf("   DNS server  : %s\r\n", a);
                            }

                            if (mtype == D6_ADVERTISE && !requested && serverIdLen && haveAddr) {
                                // Send REQUEST echoing server id + IA address.
                                uint8_t req[256]; int r = 0;
                                req[r++] = D6_REQUEST; req[r++] = xid[0]; req[r++] = xid[1]; req[r++] = xid[2];
                                r += putOpt(req + r, D6O_CLIENTID, duid, sizeof(duid));
                                r += putOpt(req + r, D6O_SERVERID, serverId, serverIdLen);
                                uint8_t iab[12 + 4 + 24]; memset(iab, 0, sizeof(iab));
                                put32(iab, 0x12345678);
                                int sub = putOpt(iab + 12, D6O_IAADDR, nullptr, 24);
                                memcpy(iab + 12 + 4, iaAddr, 16);   // addr + zero lifetimes
                                r += putOpt(req + r, D6O_IA_NA, iab, 12 + sub);
                                uint8_t el[2] = {0,0};
                                r += putOpt(req + r, D6O_ELAPSED, el, 2);
                                sendUdp6(eth, srcMac, kAllServersMac, srcIp, kAllServers, 546, 547, req, r);
                                Serial.println("   -> DHCPv6 REQUEST sent");
                                requested = true;
                            } else if (mtype == D6_REPLY) {
                                Serial.println("=> DHCPv6 lease CONFIRMED (server present, stateful DHCPv6 active).");
                                return true;
                            }
                        }
                    }
                }
            }
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        delay(1);
    }

    if (sawServer) Serial.println("\r\n=> DHCPv6 server present (no final REPLY captured).");
    else           Serial.println("\r\n=> No DHCPv6 server responded (stateful DHCPv6 absent or filtered).");
    return sawServer;
}

// =============================================================================
// Rogue server
// =============================================================================
uint32_t dhcpv6Rogue(W5500Raw &eth, const uint8_t srcMac[6],
                     const uint8_t prefix16[16], const uint8_t dns16[16],
                     uint32_t seconds)
{
    uint8_t srcIp[16]; linkLocal(srcMac, srcIp);
    uint8_t myDuid[10] = { 0x00,0x03, 0x00,0x01, srcMac[0],srcMac[1],srcMac[2],srcMac[3],srcMac[4],srcMac[5] };

    char pfx[40], dnsS[40]; ip6ToStr(prefix16, pfx); ip6ToStr(dns16, dnsS);
    Serial.printf("\r\nRogue DHCPv6 server: pool %s::/64, DNS %s, for %lu s\r\n",
                  pfx, dnsS, (unsigned long)seconds);
    Serial.println("Answers SOLICIT/REQUEST. Tests DHCPv6 guard. Any key aborts.");

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + seconds * 1000UL;
    uint32_t leases = 0;
    uint8_t  next = 0x10;

    while ((int32_t)(deadline - millis()) > 0) {
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len < 14 + 40 + 8 || get16(buf + 12) != ETHERTYPE_IPV6) { delay(1); continue; }

        const uint8_t *ip = buf + 14;
        if (ip[6] != IPPROTO_UDP) continue;
        const uint8_t *udp = ip + 40;
        if (get16(udp + 2) != 547) continue;              // server port
        const uint8_t *d6 = udp + 8;
        int d6len = (int)get16(udp + 4) - 8;
        if (d6len < 4) continue;

        uint8_t mtype = d6[0];
        if (mtype != D6_SOLICIT && mtype != D6_REQUEST) continue;
        const uint8_t *opts = d6 + 4;
        int olen = d6len - 4;

        uint16_t cidLen;
        const uint8_t *cid = findOpt(opts, olen, D6O_CLIENTID, &cidLen);
        if (!cid) continue;

        // Client link-local + MAC from the request.
        uint8_t cliMac[6]; memcpy(cliMac, buf + 6, 6);
        const uint8_t *cliIp = ip + 8;

        // Offered address = prefix with last byte = lease counter.
        uint8_t addr[16]; memcpy(addr, prefix16, 16); addr[15] = next;

        // Build IA address sub-option (addr + preferred/valid lifetimes).
        uint8_t iaaddr[24];
        memcpy(iaaddr, addr, 16);
        put32(iaaddr + 16, 3600);     // preferred
        put32(iaaddr + 20, 7200);     // valid
        // IA_NA = IAID(4) T1(4) T2(4) + IAADDR option.
        uint8_t iana[12 + 4 + 24];
        put32(iana, 0x12345678); put32(iana + 4, 1800); put32(iana + 8, 2880);
        int sub = putOpt(iana + 12, D6O_IAADDR, iaaddr, 24);

        uint8_t out[300]; int r = 0;
        out[r++] = (mtype == D6_SOLICIT) ? D6_ADVERTISE : D6_REPLY;
        out[r++] = d6[1]; out[r++] = d6[2]; out[r++] = d6[3];   // echo xid
        r += putOpt(out + r, D6O_CLIENTID, cid, cidLen);
        r += putOpt(out + r, D6O_SERVERID, myDuid, sizeof(myDuid));
        r += putOpt(out + r, D6O_IA_NA, iana, 12 + sub);
        r += putOpt(out + r, D6O_DNS, dns16, 16);

        sendUdp6(eth, srcMac, cliMac, srcIp, cliIp, 547, 546, out, r);

        char a[40]; ip6ToStr(addr, a);
        Serial.printf("-> %s to %02X:%02X:%02X:%02X:%02X:%02X  addr %s\r\n",
                      (mtype == D6_SOLICIT) ? "ADVERTISE" : "REPLY",
                      cliMac[0], cliMac[1], cliMac[2], cliMac[3], cliMac[4], cliMac[5], a);
        if (mtype == D6_REQUEST) { leases++; next++; }
    }
    Serial.printf("\r\nRogue DHCPv6 stopped. %lu lease(s) granted.\r\n", (unsigned long)leases);
    return leases;
}

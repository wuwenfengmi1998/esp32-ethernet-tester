#include "dhcp_test.h"
#include "../include/config.h"
#include "weblog.h"
#include <esp_random.h>
#include <string.h>

#define Serial Out

// DHCP / BOOTP constants
#define DHCP_SPORT      68
#define DHCP_DPORT      67
#define DHCP_MAGIC      0x63825363UL
#define BOOTP_REQUEST   1

// Message types (option 53)
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_DECLINE    4
#define DHCP_ACK        5
#define DHCP_NAK        6
#define DHCP_RELEASE    7

static inline void wput32(uint8_t *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF;
    p[2] = (v >>  8) & 0xFF; p[3] =  v        & 0xFF;
}
static inline uint32_t wrd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void ipToStr(uint32_t ip, char *out)
{
    sprintf(out, "%u.%u.%u.%u",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

// =============================================================================
// Construction
// =============================================================================
DhcpTest::DhcpTest(IpStack &ip, const uint8_t mac[6]) : _ip(ip)
{
    memcpy(_mac, mac, 6);
}

// =============================================================================
// Message builder
// =============================================================================
uint16_t DhcpTest::_build(uint8_t *buf, uint8_t msgType, const uint8_t chaddr[6],
                          uint32_t xid, uint32_t ciaddr,
                          uint32_t requestIp, uint32_t serverId, uint32_t leaseReq,
                          bool goodMagic, bool truncate)
{
    memset(buf, 0, 300);
    buf[0] = BOOTP_REQUEST;       // op
    buf[1] = 1;                   // htype = Ethernet
    buf[2] = 6;                   // hlen
    buf[3] = 0;                   // hops
    wput32(buf + 4, xid);
    buf[10] = 0x80;               // flags: broadcast (so replies reach us)
    wput32(buf + 12, ciaddr);     // ciaddr
    memcpy(buf + 28, chaddr, 6);  // chaddr

    // Magic cookie (corrupted when goodMagic == false)
    wput32(buf + 236, goodMagic ? DHCP_MAGIC : 0xDEADBEEFUL);

    uint16_t o = 240;
    buf[o++] = 53; buf[o++] = 1; buf[o++] = msgType;          // message type

    if (truncate) {
        // Deliberately omit the End option and cut the packet short.
        return o;
    }

    if (requestIp) { buf[o++] = 50; buf[o++] = 4; wput32(buf + o, requestIp); o += 4; }
    if (serverId)  { buf[o++] = 54; buf[o++] = 4; wput32(buf + o, serverId);  o += 4; }
    if (leaseReq)  { buf[o++] = 51; buf[o++] = 4; wput32(buf + o, leaseReq);  o += 4; }

    // Parameter request list
    buf[o++] = 55; buf[o++] = 4; buf[o++] = 1; buf[o++] = 3; buf[o++] = 6; buf[o++] = 51;

    buf[o++] = 255;               // end

    if (o < 300) o = 300;         // pad to BOOTP minimum
    return o;
}

// =============================================================================
// Reply parser
// =============================================================================
uint8_t DhcpTest::_parse(const uint8_t *msg, uint16_t len, uint32_t xid, DhcpLease &out)
{
    memset(&out, 0, sizeof(out));
    if (len < 240) return 0;
    if (wrd32(msg + 4) != xid) return 0;             // xid mismatch
    if (wrd32(msg + 236) != DHCP_MAGIC) return 0;    // bad cookie

    out.offeredIp = wrd32(msg + 16);                 // yiaddr

    uint8_t msgType = 0;
    uint16_t o = 240;
    while (o < len) {
        uint8_t opt = msg[o++];
        if (opt == 255) break;                       // end
        if (opt == 0)   continue;                    // pad
        if (o >= len)   break;
        uint8_t l = msg[o++];
        if (o + l > len) break;
        const uint8_t *v = msg + o;
        switch (opt) {
            case 53: msgType      = v[0];        break;
            case 54: out.serverId = wrd32(v);    break;
            case 1:  out.mask     = wrd32(v);    break;
            case 3:  out.gateway  = wrd32(v);    break;
            case 6:  out.dns      = wrd32(v);    break;
            case 51: out.leaseSecs= wrd32(v);    break;
            default: break;
        }
        o += l;
    }
    out.valid = (msgType == DHCP_OFFER || msgType == DHCP_ACK);
    return msgType;
}

// =============================================================================
// Full DORA exchange
// =============================================================================
bool DhcpTest::discover(DhcpLease &out, bool applyToStack, uint32_t timeoutMs)
{
    static uint8_t pkt[512];
    static uint8_t rx[600];
    uint32_t xid = esp_random();

    // --- DISCOVER ---
    uint16_t len = _build(pkt, DHCP_DISCOVER, _mac, xid, 0, 0, 0, 0);
    Serial.println("DHCP: sending DISCOVER...");
    if (!_ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len)) {
        Serial.println("DHCP: TX failed (link down?).");
        return false;
    }

    uint32_t srcIp; uint16_t srcPort, rlen;
    uint8_t  mt = 0;
    DhcpLease offer;
    uint32_t deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0) {
        if (_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx),
                        deadline - millis())) {
            mt = _parse(rx, rlen, xid, offer);
            if (mt == DHCP_OFFER) break;
        } else break;
    }
    if (mt != DHCP_OFFER) {
        Serial.println("DHCP: no OFFER received (server down or no DHCP on segment).");
        return false;
    }

    char a[16], b[16], c[16], d[16];
    ipToStr(offer.offeredIp, a); ipToStr(offer.serverId, b);
    ipToStr(offer.mask, c);      ipToStr(offer.gateway, d);
    Serial.printf("DHCP: OFFER %s from server %s (mask %s, gw %s, lease %lus)\r\n",
                  a, b, c, d, (unsigned long)offer.leaseSecs);

    // --- REQUEST ---
    len = _build(pkt, DHCP_REQUEST, _mac, xid, 0, offer.offeredIp, offer.serverId, 0);
    Serial.println("DHCP: sending REQUEST...");
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);

    deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0) {
        if (_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx),
                        deadline - millis())) {
            mt = _parse(rx, rlen, xid, out);
            if (mt == DHCP_ACK || mt == DHCP_NAK) break;
        } else break;
    }

    if (mt == DHCP_ACK) {
        ipToStr(out.offeredIp, a);
        Serial.printf("DHCP: ACK -> bound %s (lease %lus)\r\n",
                      a, (unsigned long)out.leaseSecs);
        if (applyToStack) {
            _ip.setAddress(out.offeredIp,
                           out.mask ? out.mask : 0xFFFFFF00UL,
                           out.gateway);
            Serial.println("DHCP: address applied to IP stack.");
        }
        return true;
    }
    Serial.println(mt == DHCP_NAK ? "DHCP: NAK (request refused)."
                                  : "DHCP: no ACK received.");
    return false;
}

// =============================================================================
// detectServer
// =============================================================================
bool DhcpTest::detectServer(uint32_t timeoutMs)
{
    static uint8_t pkt[512];
    static uint8_t rx[600];
    uint32_t xid = esp_random();
    uint16_t len = _build(pkt, DHCP_DISCOVER, _mac, xid, 0, 0, 0, 0);

    Serial.println("DHCP: probing for server (DISCOVER)...");
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);

    uint32_t srcIp; uint16_t srcPort, rlen; DhcpLease o;
    uint32_t deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0) {
        if (_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx),
                        deadline - millis())) {
            if (_parse(rx, rlen, xid, o) == DHCP_OFFER) {
                char a[16], b[16];
                ipToStr(o.offeredIp, a); ipToStr(o.serverId, b);
                Serial.printf("DHCP: server ALIVE -> %s offered %s\r\n", b, a);
                return true;
            }
        } else break;
    }
    Serial.println("DHCP: NO server responded (server-down condition).");
    return false;
}

// =============================================================================
// floodDiscover (pool exhaustion / starvation)
// =============================================================================
void DhcpTest::floodDiscover(uint32_t count, uint32_t perMsTimeout)
{
    static uint8_t pkt[512];
    static uint8_t rx[600];
    uint32_t offers = 0;

    Serial.printf("DHCP: starvation test, %lu DISCOVERs with unique MACs...\r\n",
                  (unsigned long)count);

    for (uint32_t i = 0; i < count; i++) {
        uint8_t cm[6];
        uint32_t r1 = esp_random(), r2 = esp_random();
        cm[0] = 0x02;                         // locally administered, unicast
        cm[1] = r1; cm[2] = r1 >> 8; cm[3] = r1 >> 16;
        cm[4] = r2; cm[5] = r2 >> 8;

        uint32_t xid = esp_random();
        uint16_t len = _build(pkt, DHCP_DISCOVER, cm, xid, 0, 0, 0, 0);
        _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);

        uint32_t srcIp; uint16_t srcPort, rlen; DhcpLease o;
        if (_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx), perMsTimeout)) {
            if (_parse(rx, rlen, xid, o) == DHCP_OFFER) offers++;
        }
        if ((i & 0x1F) == 0x1F) {
            Serial.printf("  sent %lu, offers %lu\r\n",
                          (unsigned long)(i + 1), (unsigned long)offers);
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
    }
    Serial.printf("DHCP: starvation done. Offers received: %lu / %lu.\r\n",
                  (unsigned long)offers, (unsigned long)count);
    if (offers == 0)
        Serial.println("  (no offers -> pool likely exhausted or rate-limited).");
}

// =============================================================================
// declineTest (simulate address conflict)
// =============================================================================
void DhcpTest::declineTest(uint32_t timeoutMs)
{
    static uint8_t pkt[512];
    static uint8_t rx[600];
    uint32_t xid = esp_random();

    uint16_t len = _build(pkt, DHCP_DISCOVER, _mac, xid, 0, 0, 0, 0);
    Serial.println("DHCP decline-test: DISCOVER...");
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);

    uint32_t srcIp; uint16_t srcPort, rlen; DhcpLease o;
    if (!_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx), timeoutMs) ||
        _parse(rx, rlen, xid, o) != DHCP_OFFER) {
        Serial.println("DHCP decline-test: no OFFER, aborting.");
        return;
    }
    char a[16]; ipToStr(o.offeredIp, a);
    Serial.printf("DHCP decline-test: got OFFER %s, sending DECLINE...\r\n", a);

    len = _build(pkt, DHCP_DECLINE, _mac, xid, 0, o.offeredIp, o.serverId, 0);
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);
    Serial.println("DHCP decline-test: DECLINE sent (server should mark address conflicted).");
}

// =============================================================================
// nakTest (request bogus IP)
// =============================================================================
void DhcpTest::nakTest(uint32_t bogusIp, uint32_t timeoutMs)
{
    static uint8_t pkt[512];
    static uint8_t rx[600];
    uint32_t xid = esp_random();
    char a[16]; ipToStr(bogusIp, a);

    Serial.printf("DHCP nak-test: REQUEST bogus IP %s...\r\n", a);
    uint16_t len = _build(pkt, DHCP_REQUEST, _mac, xid, 0, bogusIp, 0, 0);
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);

    uint32_t srcIp; uint16_t srcPort, rlen; DhcpLease o;
    uint32_t deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0) {
        if (_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx),
                        deadline - millis())) {
            uint8_t mt = _parse(rx, rlen, xid, o);
            if (mt == DHCP_NAK) { Serial.println("DHCP nak-test: NAK received (correct)."); return; }
            if (mt == DHCP_ACK) { Serial.println("DHCP nak-test: server ACKed bogus IP (server misbehaving!)."); return; }
        } else break;
    }
    Serial.println("DHCP nak-test: no response (server silently dropped request).");
}

// =============================================================================
// malformedTest
// =============================================================================
void DhcpTest::malformedTest(uint32_t timeoutMs)
{
    static uint8_t pkt[512];
    static uint8_t rx[600];
    uint32_t xid = esp_random();

    Serial.println("DHCP malformed-test: DISCOVER with bad magic cookie + truncated options...");
    uint16_t len = _build(pkt, DHCP_DISCOVER, _mac, xid, 0, 0, 0, 0,
                          /*goodMagic=*/false, /*truncate=*/true);
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);

    uint32_t srcIp; uint16_t srcPort, rlen; DhcpLease o;
    if (_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx), timeoutMs) &&
        _parse(rx, rlen, xid, o) == DHCP_OFFER) {
        Serial.println("DHCP malformed-test: server OFFERED on malformed packet (non-compliant!).");
    } else {
        Serial.println("DHCP malformed-test: server correctly ignored malformed packet.");
    }
}

// =============================================================================
// renewTest (short lease + unicast renew)
// =============================================================================
void DhcpTest::renewTest(uint32_t leaseSecs, uint32_t timeoutMs)
{
    static uint8_t pkt[512];
    static uint8_t rx[600];
    uint32_t xid = esp_random();

    // DISCOVER with a short requested lease (option 51)
    Serial.printf("DHCP renew-test: DISCOVER requesting %lus lease...\r\n",
                  (unsigned long)leaseSecs);
    uint16_t len = _build(pkt, DHCP_DISCOVER, _mac, xid, 0, 0, 0, leaseSecs);
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);

    uint32_t srcIp; uint16_t srcPort, rlen; DhcpLease o;
    if (!_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx), timeoutMs) ||
        _parse(rx, rlen, xid, o) != DHCP_OFFER) {
        Serial.println("DHCP renew-test: no OFFER, aborting.");
        return;
    }

    // REQUEST the offered address
    len = _build(pkt, DHCP_REQUEST, _mac, xid, 0, o.offeredIp, o.serverId, leaseSecs);
    _ip.sendUDP(0, 0xFFFFFFFFUL, DHCP_SPORT, DHCP_DPORT, pkt, len);
    if (!_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx), timeoutMs) ||
        _parse(rx, rlen, xid, o) != DHCP_ACK) {
        Serial.println("DHCP renew-test: no ACK, aborting.");
        return;
    }
    char a[16]; ipToStr(o.offeredIp, a);
    Serial.printf("DHCP renew-test: bound %s (lease %lus). Renewing via unicast...\r\n",
                  a, (unsigned long)o.leaseSecs);

    // Apply address so the unicast renew has a valid source IP
    _ip.setAddress(o.offeredIp, o.mask ? o.mask : 0xFFFFFF00UL, o.gateway);

    // RENEW: unicast REQUEST to the server with ciaddr set (RFC 2131 §4.3.6)
    uint32_t xid2 = esp_random();
    len = _build(pkt, DHCP_REQUEST, _mac, xid2, o.offeredIp, 0, 0, leaseSecs);
    if (!_ip.sendUDP(o.offeredIp, o.serverId, DHCP_SPORT, DHCP_DPORT, pkt, len)) {
        Serial.println("DHCP renew-test: unicast renew TX failed (ARP for server failed).");
        return;
    }
    DhcpLease r;
    if (_ip.recvUDP(DHCP_SPORT, &srcIp, &srcPort, rx, &rlen, sizeof(rx), timeoutMs) &&
        _parse(rx, rlen, xid2, r) == DHCP_ACK) {
        Serial.printf("DHCP renew-test: RENEW ACK (lease %lus). OK.\r\n",
                      (unsigned long)r.leaseSecs);
    } else {
        Serial.println("DHCP renew-test: no renew ACK (server may require rebind/broadcast).");
    }
}

#include "ip_stack.h"
#include "../include/config.h"
#include <esp_timer.h>
#include <string.h>

// =============================================================================
// Byte-order helpers (network = big-endian)
// =============================================================================
static inline void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
static inline void put32(uint8_t *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xFF; p[1] = (v >> 16) & 0xFF;
    p[2] = (v >>  8) & 0xFF; p[3] =  v        & 0xFF;
}
static inline uint16_t rd16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static inline uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

// Internet checksum (RFC 1071) over an arbitrary byte buffer.
static uint16_t inetChecksum(const uint8_t *data, uint16_t len, uint32_t seed = 0)
{
    uint32_t sum = seed;
    uint16_t i   = 0;
    while (i + 1 < len) { sum += rd16(data + i); i += 2; }
    if (len & 1) sum += (uint16_t)data[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

// =============================================================================
// Construction
// =============================================================================
IpStack::IpStack(W5500Raw &eth, const uint8_t mac[6]) : _eth(eth)
{
    memcpy(_mac, mac, 6);
    memset(_arp, 0, sizeof(_arp));
}

void IpStack::setAddress(uint32_t ip, uint32_t mask, uint32_t gw)
{
    _ip = ip; _mask = mask; _gw = gw;
}

// =============================================================================
// ARP cache
// =============================================================================
void IpStack::_cacheArp(uint32_t ip, const uint8_t mac[6])
{
    // Update existing entry if present
    for (uint8_t i = 0; i < ARP_CACHE; i++) {
        if (_arp[i].valid && _arp[i].ip == ip) {
            memcpy(_arp[i].mac, mac, 6);
            return;
        }
    }
    // Insert into first free slot, else evict slot 0
    for (uint8_t i = 0; i < ARP_CACHE; i++) {
        if (!_arp[i].valid) {
            _arp[i].ip = ip; memcpy(_arp[i].mac, mac, 6); _arp[i].valid = true;
            return;
        }
    }
    _arp[0].ip = ip; memcpy(_arp[0].mac, mac, 6); _arp[0].valid = true;
}

bool IpStack::_lookupArp(uint32_t ip, uint8_t macOut[6])
{
    for (uint8_t i = 0; i < ARP_CACHE; i++) {
        if (_arp[i].valid && _arp[i].ip == ip) {
            memcpy(macOut, _arp[i].mac, 6);
            return true;
        }
    }
    return false;
}

// =============================================================================
// ARP TX
// =============================================================================
void IpStack::_sendArpRequest(uint32_t targetIp)
{
    uint8_t f[42];
    static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    memcpy(f,     bcast, 6);
    memcpy(f + 6, _mac,  6);
    put16(f + 12, ETHERTYPE_ARP);

    uint8_t *a = f + 14;
    put16(a,      1);                 // htype = Ethernet
    put16(a + 2,  ETHERTYPE_IPV4);    // ptype = IPv4
    a[4] = 6; a[5] = 4;               // hlen, plen
    put16(a + 6,  1);                 // oper = request
    memcpy(a + 8,  _mac, 6);          // sender MAC
    put32(a + 14, _ip);               // sender IP
    memset(a + 18, 0, 6);             // target MAC unknown
    put32(a + 24, targetIp);          // target IP

    _eth.sendFrame(f, 42);
}

void IpStack::_sendArpReply(uint32_t targetIp, const uint8_t targetMac[6])
{
    uint8_t f[42];
    memcpy(f,     targetMac, 6);
    memcpy(f + 6, _mac,      6);
    put16(f + 12, ETHERTYPE_ARP);

    uint8_t *a = f + 14;
    put16(a,      1);
    put16(a + 2,  ETHERTYPE_IPV4);
    a[4] = 6; a[5] = 4;
    put16(a + 6,  2);                 // oper = reply
    memcpy(a + 8,  _mac, 6);
    put32(a + 14, _ip);
    memcpy(a + 18, targetMac, 6);
    put32(a + 24, targetIp);

    _eth.sendFrame(f, 42);
}

// =============================================================================
// Destination MAC resolution
// =============================================================================
void IpStack::destMacFor(uint32_t dstIp, uint8_t macOut[6], bool *needArp)
{
    if (needArp) *needArp = false;

    if (dstIp == 0xFFFFFFFFUL) {                       // limited broadcast
        memset(macOut, 0xFF, 6);
        return;
    }
    if ((dstIp >> 28) == 0xE) {                        // 224.0.0.0/4 multicast
        macOut[0] = 0x01; macOut[1] = 0x00; macOut[2] = 0x5E;
        macOut[3] = (dstIp >> 16) & 0x7F;
        macOut[4] = (dstIp >>  8) & 0xFF;
        macOut[5] =  dstIp        & 0xFF;
        return;
    }
    // subnet-directed broadcast
    if (_mask && (dstIp == ((_ip & _mask) | (~_mask)))) {
        memset(macOut, 0xFF, 6);
        return;
    }
    if (needArp) *needArp = true;                      // unicast: caller resolves
}

bool IpStack::arpResolve(uint32_t ip, uint8_t macOut[6], uint32_t timeoutMs)
{
    if (_lookupArp(ip, macOut)) return true;

    uint32_t deadline = millis() + timeoutMs;
    for (uint8_t attempt = 0; attempt < 3 && (int32_t)(deadline - millis()) > 0; attempt++) {
        _sendArpRequest(ip);
        uint32_t wait = millis() + (timeoutMs / 3 + 1);
        while ((int32_t)(wait - millis()) > 0) {
            poll(4);
            if (_lookupArp(ip, macOut)) return true;
            delay(1);
        }
    }
    return false;
}

// =============================================================================
// IP/UDP build + send
// =============================================================================
uint16_t IpStack::_buildIp(uint8_t *buf, const uint8_t dstMac[6],
                           uint32_t srcIp, uint32_t dstIp, uint8_t proto,
                           const uint8_t *l4, uint16_t l4Len)
{
    memcpy(buf,     dstMac, 6);
    memcpy(buf + 6, _mac,   6);
    put16(buf + 12, ETHERTYPE_IPV4);

    uint8_t *ip = buf + 14;
    uint16_t totalLen = 20 + l4Len;
    ip[0] = 0x45;                     // version 4, IHL 5
    ip[1] = 0x00;                     // DSCP/ECN
    put16(ip + 2, totalLen);
    put16(ip + 4, 0);                 // identification
    put16(ip + 6, 0x4000);            // flags: Don't Fragment
    ip[8]  = 64;                      // TTL
    ip[9]  = proto;
    put16(ip + 10, 0);                // checksum placeholder
    put32(ip + 12, srcIp);
    put32(ip + 16, dstIp);
    put16(ip + 10, inetChecksum(ip, 20));

    memcpy(ip + 20, l4, l4Len);
    return 14 + totalLen;
}

bool IpStack::sendUDP(uint32_t srcIp, uint32_t dstIp,
                      uint16_t srcPort, uint16_t dstPort,
                      const uint8_t *payload, uint16_t len)
{
    uint8_t dstMac[6];
    bool needArp = false;
    destMacFor(dstIp, dstMac, &needArp);
    if (needArp) {
        uint32_t target = ((dstIp & _mask) == (_ip & _mask)) ? dstIp : _gw;
        if (target == 0 || !arpResolve(target, dstMac, 1000)) return false;
    }

    // UDP header + payload
    static uint8_t udp[ETH_MAX_LEN];
    uint16_t udpLen = 8 + len;
    put16(udp,     srcPort);
    put16(udp + 2, dstPort);
    put16(udp + 4, udpLen);
    put16(udp + 6, 0);                // checksum (filled below)
    if (len) memcpy(udp + 8, payload, len);

    // UDP checksum with IPv4 pseudo-header
    uint8_t pseudo[12];
    put32(pseudo,     srcIp);
    put32(pseudo + 4, dstIp);
    pseudo[8] = 0; pseudo[9] = 17;    // zero, proto = UDP
    put16(pseudo + 10, udpLen);
    uint32_t seed = 0;
    for (uint8_t i = 0; i < 12; i += 2) seed += rd16(pseudo + i);
    uint16_t ck = inetChecksum(udp, udpLen, seed);
    if (ck == 0) ck = 0xFFFF;         // 0 means "no checksum"; use all-ones
    put16(udp + 6, ck);

    static uint8_t frame[ETH_MAX_LEN];
    uint16_t flen = _buildIp(frame, dstMac, srcIp, dstIp, 17, udp, udpLen);
    return _eth.sendFrame(frame, flen);
}

// =============================================================================
// Frame reception / dispatch
// =============================================================================
bool IpStack::_handleFrame(const uint8_t *frame, uint16_t len)
{
    if (len < ETH_HDR_LEN) return false;
    uint16_t etherType = rd16(frame + 12);

    // ---- ARP ----
    if (etherType == ETHERTYPE_ARP && len >= 42) {
        const uint8_t *a = frame + 14;
        uint16_t oper = rd16(a + 6);
        uint32_t spa  = rd32(a + 14);
        uint32_t tpa  = rd32(a + 24);
        _cacheArp(spa, a + 8);                  // learn sender
        if (oper == 1 && _ip && tpa == _ip) {   // request for us
            _sendArpReply(spa, a + 8);
        }
        return true;
    }

    // ---- IPv4 ----
    if (etherType == ETHERTYPE_IPV4 && len >= 34) {
        const uint8_t *ip = frame + 14;
        uint8_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20) return true;
        uint8_t  proto = ip[9];
        uint32_t srcIp = rd32(ip + 12);
        uint32_t dstIp = rd32(ip + 16);
        const uint8_t *l4 = ip + ihl;
        uint16_t ipTotal = rd16(ip + 2);
        if (ipTotal < ihl || 14 + ipTotal > len) return true;
        uint16_t l4Len = ipTotal - ihl;

        if (proto == 1 && l4Len >= 8) {          // ICMP
            uint8_t type = l4[0];
            if (type == 8 && _ip && dstIp == _ip) {           // echo request -> reply
                static uint8_t reply[ETH_MAX_LEN];
                static uint8_t icmp[ETH_MAX_LEN];
                memcpy(icmp, l4, l4Len);
                icmp[0] = 0;                      // echo reply
                put16(icmp + 2, 0);
                put16(icmp + 2, inetChecksum(icmp, l4Len));
                _cacheArp(srcIp, frame + 6);
                uint16_t flen = _buildIp(reply, frame + 6, _ip, srcIp, 1, icmp, l4Len);
                _eth.sendFrame(reply, flen);
            } else if (type == 0) {               // echo reply
                _icmpRx.have   = true;
                _icmpRx.fromIp = srcIp;
                _icmpRx.id     = rd16(l4 + 4);
                _icmpRx.seq    = rd16(l4 + 6);
            }
            return true;
        }

        if (proto == 17 && l4Len >= 8) {          // UDP
            uint16_t srcPort = rd16(l4);
            uint16_t dstPort = rd16(l4 + 2);
            uint16_t udpLen  = rd16(l4 + 4);
            if (udpLen < 8 || udpLen > l4Len) udpLen = l4Len;
            uint16_t plen    = udpLen - 8;
            if (_udpRx.buf && !_udpRx.have && dstPort == _udpRx.wantPort) {
                uint16_t cp = (plen > _udpRx.maxLen) ? _udpRx.maxLen : plen;
                memcpy(_udpRx.buf, l4 + 8, cp);
                _udpRx.len     = cp;
                _udpRx.srcIp   = srcIp;
                _udpRx.srcPort = srcPort;
                _udpRx.have    = true;
            }
            return true;
        }
    }
    return false;
}

void IpStack::poll(uint8_t maxFrames)
{
    static uint8_t buf[ETH_MAX_LEN + 4];
    for (uint8_t i = 0; i < maxFrames; i++) {
        uint16_t len = _eth.recvFrame(buf, sizeof(buf));
        if (len < ETH_HDR_LEN) break;
        _handleFrame(buf, len);
    }
}

bool IpStack::recvUDP(uint16_t wantDstPort,
                      uint32_t *srcIp, uint16_t *srcPort,
                      uint8_t *buf, uint16_t *len, uint16_t maxLen,
                      uint32_t timeoutMs)
{
    _udpRx.have     = false;
    _udpRx.wantPort = wantDstPort;
    _udpRx.buf      = buf;
    _udpRx.maxLen   = maxLen;

    uint32_t deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0) {
        poll(8);
        if (_udpRx.have) {
            if (srcIp)   *srcIp   = _udpRx.srcIp;
            if (srcPort) *srcPort = _udpRx.srcPort;
            if (len)     *len     = _udpRx.len;
            _udpRx.buf = nullptr;
            return true;
        }
        delay(1);
    }
    _udpRx.buf = nullptr;
    return false;
}

// =============================================================================
// ICMP echo (ping)
// =============================================================================
bool IpStack::ping(uint32_t dstIp, uint32_t timeoutMs, uint32_t *rttUs)
{
    uint8_t dstMac[6];
    bool needArp = false;
    destMacFor(dstIp, dstMac, &needArp);
    if (needArp) {
        uint32_t target = ((dstIp & _mask) == (_ip & _mask)) ? dstIp : _gw;
        if (target == 0 || !arpResolve(target, dstMac, timeoutMs)) return false;
    }

    uint16_t seq = ++_icmpSeq;
    uint8_t icmp[40];
    memset(icmp, 0, sizeof(icmp));
    icmp[0] = 8;                      // echo request
    icmp[1] = 0;
    put16(icmp + 4, _icmpId);
    put16(icmp + 6, seq);
    for (uint8_t i = 8; i < sizeof(icmp); i++) icmp[i] = (uint8_t)i;
    put16(icmp + 2, inetChecksum(icmp, sizeof(icmp)));

    static uint8_t frame[ETH_MAX_LEN];
    uint16_t flen = _buildIp(frame, dstMac, _ip, dstIp, 1, icmp, sizeof(icmp));

    _icmpRx.have = false;
    uint64_t t0  = (uint64_t)esp_timer_get_time();
    if (!_eth.sendFrame(frame, flen)) return false;

    uint32_t deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0) {
        poll(8);
        if (_icmpRx.have && _icmpRx.id == _icmpId && _icmpRx.seq == seq) {
            if (rttUs) *rttUs = (uint32_t)((uint64_t)esp_timer_get_time() - t0);
            return true;
        }
        delay(1);
    }
    return false;
}

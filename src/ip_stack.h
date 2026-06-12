#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// Minimal IPv4 stack over the W5500 MACRAW driver.
//
// Implements just enough ARP / IP / UDP / ICMP to support DHCP server testing
// and mDNS-based reachability probing, while keeping the raw-frame design of
// the tester (the W5500 hardware TCP/IP stack is deliberately NOT used).
//
// All addresses passed to / returned from this API are host-byte-order uint32.
// =============================================================================

// Convenience: build a host-order IPv4 from octets.
static inline uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

// EtherTypes
#define ETHERTYPE_IPV4   0x0800
#define ETHERTYPE_ARP    0x0806

class IpStack {
public:
    IpStack(W5500Raw &eth, const uint8_t mac[6]);

    // Configure local addressing. Call after DHCP or for static config.
    void setAddress(uint32_t ip, uint32_t mask, uint32_t gw);
    void setMac(const uint8_t mac[6]) { memcpy(_mac, mac, 6); }

    uint32_t ip()   const { return _ip; }
    uint32_t mask() const { return _mask; }
    uint32_t gw()   const { return _gw; }
    const uint8_t *mac() const { return _mac; }

    // Send a UDP datagram. Destination MAC is resolved automatically:
    //  - 255.255.255.255            -> Ethernet broadcast
    //  - 224.0.0.0/4 (multicast)    -> IPv4 multicast MAC mapping
    //  - on-subnet unicast          -> ARP for the destination
    //  - off-subnet unicast         -> ARP for the gateway
    // srcIp lets DHCP send from 0.0.0.0 before it has an address.
    bool sendUDP(uint32_t srcIp, uint32_t dstIp,
                 uint16_t srcPort, uint16_t dstPort,
                 const uint8_t *payload, uint16_t len);

    // Receive the next UDP datagram destined to `wantDstPort`. While waiting,
    // ARP requests for our IP and ICMP echo requests are answered automatically.
    // Returns true on success and fills the out-params (buf truncated to maxLen).
    bool recvUDP(uint16_t wantDstPort,
                 uint32_t *srcIp, uint16_t *srcPort,
                 uint8_t *buf, uint16_t *len, uint16_t maxLen,
                 uint32_t timeoutMs);

    // Resolve `ip` to a MAC via ARP (uses cache). Returns true on success.
    bool arpResolve(uint32_t ip, uint8_t macOut[6], uint32_t timeoutMs = 1000);

    // ICMP echo (ping). Returns true if a reply arrived within timeout;
    // sets *rttUs to the round-trip time in microseconds when non-null.
    bool ping(uint32_t dstIp, uint32_t timeoutMs, uint32_t *rttUs = nullptr);

    // Service background traffic (answer ARP/ICMP) without blocking on UDP.
    // Call periodically when the stack is otherwise idle. Processes up to
    // `maxFrames` queued frames.
    void poll(uint8_t maxFrames = 8);

    // Map a host-order IPv4 to the destination Ethernet MAC per the rules above.
    void destMacFor(uint32_t dstIp, uint8_t macOut[6], bool *needArp);

private:
    W5500Raw &_eth;
    uint8_t   _mac[6];
    uint32_t  _ip   = 0;
    uint32_t  _mask = 0xFFFFFF00UL;
    uint32_t  _gw   = 0;

    // Small ARP cache
    struct ArpEntry { uint32_t ip; uint8_t mac[6]; bool valid; };
    static constexpr uint8_t ARP_CACHE = 8;
    ArpEntry _arp[ARP_CACHE];

    uint16_t _icmpId  = 0x4553;     // 'ES'
    uint16_t _icmpSeq = 0;

    // Internal frame handling
    bool _handleFrame(const uint8_t *frame, uint16_t len);
    void _sendArpRequest(uint32_t targetIp);
    void _sendArpReply(uint32_t targetIp, const uint8_t targetMac[6]);
    void _cacheArp(uint32_t ip, const uint8_t mac[6]);
    bool _lookupArp(uint32_t ip, uint8_t macOut[6]);

    // Build an Ethernet+IP+payload frame. Returns total length.
    uint16_t _buildIp(uint8_t *buf, const uint8_t dstMac[6],
                      uint32_t srcIp, uint32_t dstIp, uint8_t proto,
                      const uint8_t *l4, uint16_t l4Len);

    // Last received UDP capture (filled by _handleFrame during recvUDP).
    struct {
        bool     have;
        uint16_t wantPort;
        uint32_t srcIp;
        uint16_t srcPort;
        uint8_t *buf;
        uint16_t maxLen;
        uint16_t len;
    } _udpRx = {};

    // Last ICMP echo-reply capture.
    struct { bool have; uint32_t fromIp; uint16_t id; uint16_t seq; } _icmpRx = {};
};

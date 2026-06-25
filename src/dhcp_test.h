#pragma once

#include <Arduino.h>
#include "ip_stack.h"

// =============================================================================
// DHCP server testing over the minimal IP stack.
//
// Provides a normal DORA exchange to verify a DHCP server, plus a set of
// failure / abuse scenarios used to validate server robustness and policy.
// All output is printed to Serial; results are also returned where useful.
// =============================================================================

struct DhcpLease {
    bool     valid;
    uint32_t offeredIp;
    uint32_t serverId;
    uint32_t mask;
    uint32_t gateway;
    uint32_t dns;
    uint32_t leaseSecs;
};

class DhcpTest {
public:
    DhcpTest(IpStack &ip, const uint8_t mac[6]);

    // Full DORA exchange. On success fills `out` and (optionally) applies the
    // address to the IP stack. Returns true if an ACK was received.
    bool discover(DhcpLease &out, bool applyToStack = true, uint32_t timeoutMs = 4000);

    // --- Failure / simulation scenarios ---

    // Send a single DISCOVER and report whether ANY server offered an address
    // (server-down / no-server-on-segment detection).
    bool detectServer(uint32_t timeoutMs = 3000);

    // Flood `count` DISCOVERs each with a unique random client MAC/xid to
    // probe pool exhaustion / address starvation. Reports offers received.
    void floodDiscover(uint32_t count, uint32_t perMsTimeout = 200);

    // Obtain an OFFER then DECLINE it (simulate a detected address conflict).
    void declineTest(uint32_t timeoutMs = 4000);

    // REQUEST a bogus / out-of-pool IP and expect the server to reply NAK.
    void nakTest(uint32_t bogusIp, uint32_t timeoutMs = 4000);

    // Send a malformed DISCOVER (bad magic cookie + truncated options) and
    // confirm the server correctly ignores it (no offer).
    void malformedTest(uint32_t timeoutMs = 3000);

    // Request a short lease, then immediately renew via unicast to the server
    // to exercise renew/rebind handling.
    void renewTest(uint32_t leaseSecs = 60, uint32_t timeoutMs = 4000);

    // Act as a ROGUE DHCP server for `seconds`: answer DISCOVER with OFFER and
    // REQUEST with ACK, handing out addresses from `poolStart` upward with the
    // given mask/gateway/dns. Tests DHCP snooping / rogue-server protection.
    // (Authorized lab use only.) Returns the number of leases handed out.
    uint32_t rogueServer(uint32_t poolStart, uint32_t mask, uint32_t gateway,
                         uint32_t dns, uint32_t seconds);

private:
    IpStack &_ip;
    uint8_t  _mac[6];

    // Build a DHCP/BOOTP message. Returns total length.
    //   msgType  : 1=DISCOVER 3=REQUEST 4=DECLINE 7=RELEASE
    //   chaddr   : client hardware address (6 bytes)
    //   requestIp: option 50 (0 = omit)
    //   serverId : option 54 (0 = omit)
    //   leaseReq : option 51 (0 = omit)
    //   goodMagic: false to corrupt the magic cookie (malformed test)
    //   truncate : true to cut options short (malformed test)
    uint16_t _build(uint8_t *buf, uint8_t msgType, const uint8_t chaddr[6],
                    uint32_t xid, uint32_t ciaddr,
                    uint32_t requestIp, uint32_t serverId, uint32_t leaseReq,
                    bool goodMagic = true, bool truncate = false);

    // Parse a received DHCP reply. Returns the message type (0 on parse error)
    // and fills `out`.
    uint8_t _parse(const uint8_t *msg, uint16_t len, uint32_t xid, DhcpLease &out);
};

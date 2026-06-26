#include "snmp_recon.h"
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
#define SNMP_PORT       161

// ASN.1 / BER tag bytes
#define ASN_SEQUENCE    0x30
#define ASN_INTEGER     0x02
#define ASN_OCTET_STR   0x04
#define ASN_NULL        0x05
#define ASN_OID         0x06
#define SNMP_GET_REQ    0xA0
#define SNMP_GET_RESP   0xA2

// sysDescr.0 = 1.3.6.1.2.1.1.1.0
static const uint8_t OID_SYSDESCR[] = { 0x2B, 6, 1, 2, 1, 1, 1, 0 };

// Default community strings to try
static const char *DEFAULT_COMMUNITIES[] = {
    "public", "private", "community", "admin", "snmp", "monitor"
};
static const uint8_t DEFAULT_NUM_COMMUNITIES = 6;

// =============================================================================
// Static helpers
// =============================================================================

// Write ASN.1 length (short form only, max 127). Returns bytes written.
static uint16_t asnPutLen(uint8_t *p, uint8_t len)
{
    if (len < 128) { *p = len; return 1; }
    // Long form (1 byte length-of-length + 1 byte)
    p[0] = 0x81; p[1] = len; return 2;
}

// Build an SNMPv1 GET request for sysDescr.0. Returns total BER length.
static uint16_t buildSnmpGet(uint8_t *buf, uint16_t cap, const char *community,
                             uint32_t requestId)
{
    // We build from the inside out, but since sizes are small and predictable
    // we can compute them ahead.
    uint8_t commLen = (uint8_t)strlen(community);
    uint8_t oidLen = sizeof(OID_SYSDESCR);

    // VarBind: SEQUENCE { OID, NULL }
    uint8_t vbInnerLen = 2 + oidLen + 2; // OID TL + oidLen + NULL TL
    uint8_t vbLen = 2 + vbInnerLen;      // SEQUENCE TL + inner

    // VarBindList: SEQUENCE { VarBind }
    uint8_t vblLen = 2 + vbLen;

    // PDU: GET-REQUEST { requestId(INT), errorStatus(INT 0), errorIndex(INT 0), VarBindList }
    uint8_t ridEnc[6]; uint8_t ridLen;
    ridEnc[0] = ASN_INTEGER;
    if (requestId < 128) { ridEnc[1] = 1; ridEnc[2] = (uint8_t)requestId; ridLen = 3; }
    else { ridEnc[1] = 4; put32(ridEnc + 2, requestId); ridLen = 6; }

    uint8_t pduInnerLen = ridLen + 3 + 3 + 2 + vblLen; // reqId + err(3) + errIdx(3) + vbl
    uint8_t pduLen = 2 + pduInnerLen;

    // Message: SEQUENCE { version(INT 0), community(OCTET), PDU }
    uint8_t msgInnerLen = 3 + 2 + commLen + pduLen; // version(3) + community TL + comm + pdu
    uint8_t totalLen = 2 + msgInnerLen;

    if (totalLen > cap) return 0;

    uint8_t *p = buf;
    // Message SEQUENCE
    *p++ = ASN_SEQUENCE; *p++ = msgInnerLen;
    // Version: INTEGER 0 (SNMPv1)
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0;
    // Community: OCTET STRING
    *p++ = ASN_OCTET_STR; *p++ = commLen;
    memcpy(p, community, commLen); p += commLen;
    // PDU: GET-REQUEST
    *p++ = SNMP_GET_REQ; *p++ = pduInnerLen;
    // Request ID
    memcpy(p, ridEnc, ridLen); p += ridLen;
    // Error Status: INTEGER 0
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0;
    // Error Index: INTEGER 0
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0;
    // VarBindList
    *p++ = ASN_SEQUENCE; *p++ = vblLen - 2;
    // VarBind
    *p++ = ASN_SEQUENCE; *p++ = vbInnerLen;
    // OID
    *p++ = ASN_OID; *p++ = oidLen;
    memcpy(p, OID_SYSDESCR, oidLen); p += oidLen;
    // Value: NULL
    *p++ = ASN_NULL; *p++ = 0;

    return (uint16_t)(p - buf);
}

// Parse an SNMP GET-RESPONSE, extract the sysDescr string value.
// Returns true if parsed successfully; fills `desc` (null-terminated, max descCap-1).
static bool parseSnmpResponse(const uint8_t *snmp, uint16_t len,
                              char *desc, uint16_t descCap, uint32_t expectedReqId)
{
    if (len < 20 || snmp[0] != ASN_SEQUENCE) return false;
    // Walk the BER structure loosely: find GET-RESPONSE tag
    uint16_t pos = 2; // skip outer SEQUENCE TL
    // Skip version
    if (pos >= len || snmp[pos] != ASN_INTEGER) return false;
    pos += 2 + snmp[pos + 1];
    // Skip community
    if (pos >= len || snmp[pos] != ASN_OCTET_STR) return false;
    pos += 2 + snmp[pos + 1];
    // PDU should be GET-RESPONSE (0xA2)
    if (pos >= len || snmp[pos] != SNMP_GET_RESP) return false;
    pos += 2; // skip tag + length

    // Request ID
    if (pos >= len || snmp[pos] != ASN_INTEGER) return false;
    uint8_t ridLen = snmp[pos + 1];
    pos += 2;
    uint32_t rid = 0;
    for (uint8_t i = 0; i < ridLen && pos < len; i++) rid = (rid << 8) | snmp[pos++];
    if (rid != expectedReqId) return false;

    // Error status
    if (pos >= len || snmp[pos] != ASN_INTEGER) return false;
    pos += 2 + snmp[pos + 1];
    // Error index
    if (pos >= len || snmp[pos] != ASN_INTEGER) return false;
    pos += 2 + snmp[pos + 1];

    // VarBindList SEQUENCE
    if (pos >= len || snmp[pos] != ASN_SEQUENCE) return false;
    pos += 2;
    // VarBind SEQUENCE
    if (pos >= len || snmp[pos] != ASN_SEQUENCE) return false;
    pos += 2;
    // OID
    if (pos >= len || snmp[pos] != ASN_OID) return false;
    pos += 2 + snmp[pos + 1];
    // Value -- should be OCTET STRING for sysDescr
    if (pos >= len) return false;
    uint8_t valTag = snmp[pos];
    uint8_t valLen = snmp[pos + 1];
    pos += 2;
    if (pos + valLen > len) valLen = len - pos;

    if (valTag == ASN_OCTET_STR) {
        uint16_t copyLen = (valLen < descCap - 1) ? valLen : descCap - 1;
        memcpy(desc, snmp + pos, copyLen);
        desc[copyLen] = '\0';
    } else {
        snprintf(desc, descCap, "(type=0x%02X, len=%u)", valTag, valLen);
    }
    return true;
}

// Build UDP/IPv4 frame with SNMP payload, similar to dns_tool.
static uint16_t buildSnmpFrame(uint8_t *f, const uint8_t dstMac[6],
                               const uint8_t srcMac[6], uint32_t srcIp,
                               uint32_t dstIp, const uint8_t *snmpPayload,
                               uint16_t snmpLen)
{
    uint16_t srcPort = 1024 + (esp_random() % 60000);
    // Ethernet
    memcpy(f, dstMac, 6);
    memcpy(f + 6, srcMac, 6);
    put16(f + 12, ETHERTYPE_IPV4);
    // IPv4
    uint8_t *ip = f + 14;
    uint16_t totalLen = 20 + 8 + snmpLen;
    ip[0] = 0x45; ip[1] = 0;
    put16(ip + 2, totalLen);
    put16(ip + 4, (uint16_t)(esp_random() & 0xFFFF));
    put16(ip + 6, 0x4000);
    ip[8] = 64; ip[9] = IPPROTO_UDP;
    put16(ip + 10, 0);
    put32(ip + 12, srcIp);
    put32(ip + 16, dstIp);
    put16(ip + 10, inetChecksum(ip, 20));
    // UDP
    uint8_t *udp = ip + 20;
    put16(udp, srcPort);
    put16(udp + 2, SNMP_PORT);
    put16(udp + 4, 8 + snmpLen);
    put16(udp + 6, 0);
    // Payload
    memcpy(udp + 8, snmpPayload, snmpLen);

    uint16_t frameLen = 14 + totalLen;
    if (frameLen < 60) frameLen = 60;
    return frameLen;
}

// ARP-resolve a target IP. Returns true if resolved (fills dstMac).
static bool arpResolve(W5500Raw &eth, const uint8_t srcMac[6], uint32_t srcIp,
                       uint32_t target, uint8_t dstMac[6], uint32_t timeoutMs)
{
    uint8_t arp[42];
    memcpy(arp, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(arp + 6, srcMac, 6);
    put16(arp + 12, 0x0806);
    put16(arp + 14, 1); put16(arp + 16, 0x0800);
    arp[18] = 6; arp[19] = 4;
    put16(arp + 20, 1);
    memcpy(arp + 22, srcMac, 6);
    put32(arp + 28, srcIp);
    memset(arp + 32, 0, 6);
    put32(arp + 38, target);
    eth.sendFrame(arp, 42);

    uint32_t t0 = millis();
    while (millis() - t0 < timeoutMs) {
        uint8_t rxbuf[64];
        uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
        if (len >= 42 && get16(rxbuf + 12) == 0x0806 && get16(rxbuf + 20) == 2) {
            if (get32(rxbuf + 28) == target) {
                memcpy(dstMac, rxbuf + 22, 6);
                return true;
            }
        }
        delay(1);
    }
    return false;
}

// =============================================================================
// snmpProbe -- probe a single host with community strings
// =============================================================================
bool snmpProbe(W5500Raw &eth, IpStack &ip, uint32_t target,
               const char *communities[], uint8_t numCommunities,
               uint32_t timeoutMs)
{
    if (ip.ip() == 0) {
        Serial.println("[snmp] No IP configured. Run 'ip dhcp' or 'ip static' first.");
        return false;
    }

    const char **comms = communities;
    uint8_t nComms = numCommunities;
    if (!comms || nComms == 0) {
        comms = DEFAULT_COMMUNITIES;
        nComms = DEFAULT_NUM_COMMUNITIES;
    }

    char tS[16]; ipToStr(target, tS);
    Serial.printf("[snmp] Probing %s with %u community strings...\r\n", tS, nComms);

    // ARP-resolve the target (or gateway if off-link)
    uint8_t dstMac[6];
    uint32_t nexthop = ((ip.ip() ^ target) & ip.mask()) == 0 ? target : ip.gw();
    if (!arpResolve(eth, ip.mac(), ip.ip(), nexthop, dstMac, 2000)) {
        memset(dstMac, 0xFF, 6); // fallback broadcast
    }

    bool found = false;
    for (uint8_t c = 0; c < nComms; c++) {
        uint32_t reqId = esp_random();
        uint8_t snmpBuf[128];
        uint16_t snmpLen = buildSnmpGet(snmpBuf, sizeof(snmpBuf), comms[c], reqId);
        if (snmpLen == 0) continue;

        uint8_t frame[256];
        uint16_t frameLen = buildSnmpFrame(frame, dstMac, ip.mac(), ip.ip(),
                                           target, snmpBuf, snmpLen);
        eth.sendFrame(frame, frameLen);

        // Wait for response
        uint32_t t0 = millis();
        while (millis() - t0 < timeoutMs) {
            uint8_t rxbuf[512];
            uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
            if (len < 14 + 20 + 8 + 20) { delay(1); continue; }
            if (get16(rxbuf + 12) != ETHERTYPE_IPV4) continue;
            uint8_t *ipH = rxbuf + 14;
            if (ipH[9] != IPPROTO_UDP) continue;
            uint8_t *udp = ipH + (ipH[0] & 0x0F) * 4;
            if (get16(udp) != SNMP_PORT) continue;

            uint8_t *snmpResp = udp + 8;
            uint16_t respLen = len - (snmpResp - rxbuf);

            char desc[256];
            if (parseSnmpResponse(snmpResp, respLen, desc, sizeof(desc), reqId)) {
                Serial.printf("[snmp] %s community='%s' -- sysDescr: %s\r\n",
                              tS, comms[c], desc);
                found = true;
                goto next_comm; // found one, try remaining too
            }
        }
        next_comm:;
    }

    if (!found) Serial.printf("[snmp] %s -- no response to any community.\r\n", tS);
    return found;
}

// =============================================================================
// snmpSweep -- probe an IP range
// =============================================================================
uint32_t snmpSweep(W5500Raw &eth, IpStack &ip, uint32_t startIp, uint32_t endIp,
                   const char *community, uint32_t timeoutMs)
{
    if (ip.ip() == 0) {
        Serial.println("[snmp] No IP configured.");
        return 0;
    }
    if (startIp > endIp) { uint32_t t = startIp; startIp = endIp; endIp = t; }
    uint32_t range = endIp - startIp + 1;
    if (range > 1024) {
        Serial.println("[snmp] Range too large (max 1024 hosts).");
        return 0;
    }

    char sS[16], eS[16];
    ipToStr(startIp, sS); ipToStr(endIp, eS);
    Serial.printf("[snmp] Sweeping %s - %s community='%s' (%lu hosts)\r\n",
                  sS, eS, community, (unsigned long)range);

    uint32_t found = 0;
    const char *comms[] = { community };
    for (uint32_t t = startIp; t <= endIp; t++) {
        if (Serial.available()) { Serial.read(); Serial.println("[snmp] Aborted."); break; }
        if (snmpProbe(eth, ip, t, comms, 1, timeoutMs)) found++;
    }

    Serial.printf("[snmp] Sweep done. %lu responsive hosts.\r\n", (unsigned long)found);
    return found;
}

// =============================================================================
// snmpWriteTest -- test write access via sysContact.0
// =============================================================================

// sysContact.0 = 1.3.6.1.2.1.1.4.0
static const uint8_t OID_SYSCONTACT[] = { 0x2B, 6, 1, 2, 1, 1, 4, 0 };

#define SNMP_SET_REQ    0xA3

// Build an SNMPv1 GET request for sysContact.0
static uint16_t buildSnmpGetContact(uint8_t *buf, uint16_t cap, const char *community,
                                    uint32_t requestId)
{
    uint8_t commLen = (uint8_t)strlen(community);
    uint8_t oidLen = sizeof(OID_SYSCONTACT);
    uint8_t vbInnerLen = 2 + oidLen + 2;
    uint8_t vbLen = 2 + vbInnerLen;
    uint8_t vblLen = 2 + vbLen;

    uint8_t ridEnc[6]; uint8_t ridLen;
    ridEnc[0] = ASN_INTEGER;
    if (requestId < 128) { ridEnc[1] = 1; ridEnc[2] = (uint8_t)requestId; ridLen = 3; }
    else { ridEnc[1] = 4; put32(ridEnc + 2, requestId); ridLen = 6; }

    uint8_t pduInnerLen = ridLen + 3 + 3 + 2 + vblLen;
    uint8_t pduLen = 2 + pduInnerLen;
    uint8_t msgInnerLen = 3 + 2 + commLen + pduLen;
    uint8_t totalLen = 2 + msgInnerLen;
    if (totalLen > cap) return 0;

    uint8_t *p = buf;
    *p++ = ASN_SEQUENCE; *p++ = msgInnerLen;
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0; // version
    *p++ = ASN_OCTET_STR; *p++ = commLen;
    memcpy(p, community, commLen); p += commLen;
    *p++ = SNMP_GET_REQ; *p++ = pduInnerLen;
    memcpy(p, ridEnc, ridLen); p += ridLen;
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0; // error status
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0; // error index
    *p++ = ASN_SEQUENCE; *p++ = vblLen - 2;
    *p++ = ASN_SEQUENCE; *p++ = vbInnerLen;
    *p++ = ASN_OID; *p++ = oidLen;
    memcpy(p, OID_SYSCONTACT, oidLen); p += oidLen;
    *p++ = ASN_NULL; *p++ = 0;
    return (uint16_t)(p - buf);
}

// Build an SNMPv1 SET request for sysContact.0 with an OCTET STRING value
static uint16_t buildSnmpSetContact(uint8_t *buf, uint16_t cap, const char *community,
                                    uint32_t requestId, const char *value)
{
    uint8_t commLen = (uint8_t)strlen(community);
    uint8_t valLen = (uint8_t)strlen(value);
    uint8_t oidLen = sizeof(OID_SYSCONTACT);

    uint8_t vbInnerLen = 2 + oidLen + 2 + valLen; // OID TL + oid + OCTET_STR TL + val
    uint8_t vbLen = 2 + vbInnerLen;
    uint8_t vblLen = 2 + vbLen;

    uint8_t ridEnc[6]; uint8_t ridLen;
    ridEnc[0] = ASN_INTEGER;
    if (requestId < 128) { ridEnc[1] = 1; ridEnc[2] = (uint8_t)requestId; ridLen = 3; }
    else { ridEnc[1] = 4; put32(ridEnc + 2, requestId); ridLen = 6; }

    uint8_t pduInnerLen = ridLen + 3 + 3 + 2 + vblLen;
    uint8_t pduLen = 2 + pduInnerLen;
    uint8_t msgInnerLen = 3 + 2 + commLen + pduLen;
    uint8_t totalLen = 2 + msgInnerLen;
    if (totalLen > cap) return 0;

    uint8_t *p = buf;
    *p++ = ASN_SEQUENCE; *p++ = msgInnerLen;
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0; // version
    *p++ = ASN_OCTET_STR; *p++ = commLen;
    memcpy(p, community, commLen); p += commLen;
    *p++ = SNMP_SET_REQ; *p++ = pduInnerLen;
    memcpy(p, ridEnc, ridLen); p += ridLen;
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0; // error status
    *p++ = ASN_INTEGER; *p++ = 1; *p++ = 0; // error index
    *p++ = ASN_SEQUENCE; *p++ = vblLen - 2;
    *p++ = ASN_SEQUENCE; *p++ = vbInnerLen;
    *p++ = ASN_OID; *p++ = oidLen;
    memcpy(p, OID_SYSCONTACT, oidLen); p += oidLen;
    *p++ = ASN_OCTET_STR; *p++ = valLen;
    memcpy(p, value, valLen); p += valLen;
    return (uint16_t)(p - buf);
}

// Send SNMP frame and wait for GET-RESPONSE, extract string value
static bool snmpGetString(W5500Raw &eth, IpStack &ip, uint32_t target,
                          const uint8_t dstMac[6], const char *community,
                          uint8_t *snmpBuf, uint16_t snmpLen, uint32_t reqId,
                          char *result, uint16_t resultCap, uint32_t timeoutMs)
{
    uint8_t frame[256];
    uint16_t frameLen = buildSnmpFrame(frame, dstMac, ip.mac(), ip.ip(),
                                       target, snmpBuf, snmpLen);
    eth.sendFrame(frame, frameLen);

    uint32_t t0 = millis();
    while (millis() - t0 < timeoutMs) {
        uint8_t rxbuf[512];
        uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
        if (len < 14 + 20 + 8 + 20) { delay(1); continue; }
        if (get16(rxbuf + 12) != ETHERTYPE_IPV4) continue;
        uint8_t *ipH = rxbuf + 14;
        if (ipH[9] != IPPROTO_UDP) continue;
        uint8_t *udp = ipH + (ipH[0] & 0x0F) * 4;
        if (get16(udp) != SNMP_PORT) continue;

        uint8_t *snmpResp = udp + 8;
        uint16_t respLen = len - (snmpResp - rxbuf);
        if (parseSnmpResponse(snmpResp, respLen, result, resultCap, reqId))
            return true;
    }
    return false;
}

// Send SNMP SET and check response for errorStatus == 0
static bool snmpSetAndVerify(W5500Raw &eth, IpStack &ip, uint32_t target,
                             const uint8_t dstMac[6], const char *community,
                             uint32_t requestId, const char *value,
                             uint32_t timeoutMs)
{
    uint8_t snmpBuf[192];
    uint16_t snmpLen = buildSnmpSetContact(snmpBuf, sizeof(snmpBuf), community,
                                           requestId, value);
    if (snmpLen == 0) return false;

    uint8_t frame[300];
    uint16_t frameLen = buildSnmpFrame(frame, dstMac, ip.mac(), ip.ip(),
                                       target, snmpBuf, snmpLen);
    eth.sendFrame(frame, frameLen);

    // Wait for GET-RESPONSE with errorStatus == 0
    uint32_t t0 = millis();
    while (millis() - t0 < timeoutMs) {
        uint8_t rxbuf[512];
        uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
        if (len < 14 + 20 + 8 + 20) { delay(1); continue; }
        if (get16(rxbuf + 12) != ETHERTYPE_IPV4) continue;
        uint8_t *ipH = rxbuf + 14;
        if (ipH[9] != IPPROTO_UDP) continue;
        uint8_t *udp = ipH + (ipH[0] & 0x0F) * 4;
        if (get16(udp) != SNMP_PORT) continue;

        uint8_t *resp = udp + 8;
        uint16_t respLen = len - (resp - rxbuf);
        // Minimal parse: check it's a GET-RESPONSE and errorStatus == 0
        if (respLen < 20 || resp[0] != ASN_SEQUENCE) continue;
        // Walk to PDU
        uint16_t pos = 2;
        if (pos >= respLen || resp[pos] != ASN_INTEGER) continue;
        pos += 2 + resp[pos + 1]; // skip version
        if (pos >= respLen || resp[pos] != ASN_OCTET_STR) continue;
        pos += 2 + resp[pos + 1]; // skip community
        if (pos >= respLen || resp[pos] != SNMP_GET_RESP) continue;
        pos += 2; // skip PDU tag+len
        // Request ID
        if (pos >= respLen || resp[pos] != ASN_INTEGER) continue;
        uint8_t ridLen = resp[pos + 1]; pos += 2;
        uint32_t rid = 0;
        for (uint8_t i = 0; i < ridLen && pos < respLen; i++) rid = (rid << 8) | resp[pos++];
        if (rid != requestId) continue;
        // Error status
        if (pos >= respLen || resp[pos] != ASN_INTEGER) continue;
        uint8_t esLen = resp[pos + 1]; pos += 2;
        uint8_t errStatus = 0;
        for (uint8_t i = 0; i < esLen && pos < respLen; i++) errStatus = resp[pos++];
        return (errStatus == 0);
    }
    return false;
}

bool snmpWriteTest(W5500Raw &eth, IpStack &ip, uint32_t target,
                   const char *writeCommunity, uint32_t timeoutMs)
{
    if (ip.ip() == 0) {
        Serial.println("[snmp] No IP configured.");
        return false;
    }

    char tS[16]; ipToStr(target, tS);
    Serial.printf("[snmp] Write-test %s community='%s' (using sysContact.0)\r\n",
                  tS, writeCommunity);

    // ARP-resolve
    uint8_t dstMac[6];
    uint32_t nexthop = ((ip.ip() ^ target) & ip.mask()) == 0 ? target : ip.gw();
    if (!arpResolve(eth, ip.mac(), ip.ip(), nexthop, dstMac, 2000)) {
        memset(dstMac, 0xFF, 6);
    }

    // Step 1: GET sysContact.0 to save original value
    char original[128] = {0};
    {
        uint32_t reqId = esp_random();
        uint8_t snmpBuf[128];
        uint16_t snmpLen = buildSnmpGetContact(snmpBuf, sizeof(snmpBuf),
                                               writeCommunity, reqId);
        if (snmpLen == 0) { Serial.println("[snmp] Failed to build GET."); return false; }

        if (!snmpGetString(eth, ip, target, dstMac, writeCommunity,
                           snmpBuf, snmpLen, reqId, original, sizeof(original), timeoutMs)) {
            Serial.printf("[snmp] %s -- no response to GET sysContact.0 (community may be wrong).\r\n", tS);
            return false;
        }
    }
    Serial.printf("[snmp] Original sysContact.0: \"%s\"\r\n", original);

    // Step 2: SET sysContact.0 to a test marker
    static const char *TEST_VALUE = "SNMP-WRITE-TEST-ESP32";
    {
        uint32_t reqId = esp_random();
        if (!snmpSetAndVerify(eth, ip, target, dstMac, writeCommunity,
                              reqId, TEST_VALUE, timeoutMs)) {
            Serial.printf("[snmp] %s -- SET failed (read-only community or access denied).\r\n", tS);
            return false;
        }
    }
    Serial.printf("[snmp] SET succeeded -- write access CONFIRMED with community='%s'\r\n",
                  writeCommunity);

    // Step 3: Verify the write by reading back
    {
        char readback[128] = {0};
        uint32_t reqId = esp_random();
        uint8_t snmpBuf[128];
        uint16_t snmpLen = buildSnmpGetContact(snmpBuf, sizeof(snmpBuf),
                                               writeCommunity, reqId);
        if (snmpLen && snmpGetString(eth, ip, target, dstMac, writeCommunity,
                                     snmpBuf, snmpLen, reqId, readback, sizeof(readback), timeoutMs)) {
            if (strcmp(readback, TEST_VALUE) == 0)
                Serial.println("[snmp] Readback verified: write is effective.");
            else
                Serial.printf("[snmp] Readback mismatch: got \"%s\"\r\n", readback);
        }
    }

    // Step 4: Restore original value
    {
        uint32_t reqId = esp_random();
        if (snmpSetAndVerify(eth, ip, target, dstMac, writeCommunity,
                             reqId, original, timeoutMs)) {
            Serial.printf("[snmp] Restored sysContact.0 to: \"%s\"\r\n", original);
        } else {
            Serial.printf("[snmp] WARNING: failed to restore sysContact.0!\r\n");
        }
    }

    return true;
}

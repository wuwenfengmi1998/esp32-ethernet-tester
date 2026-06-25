#include "discovery.h"
#include "../include/config.h"
#include "weblog.h"
#include <string.h>

#define Serial Out

// =============================================================================
// Constants
// =============================================================================
#define LLDP_ETHERTYPE   0x88CC

// =============================================================================
// Small helpers
// =============================================================================
static inline uint16_t rdU16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void printMac(const uint8_t *m)
{
    Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X",
                  m[0], m[1], m[2], m[3], m[4], m[5]);
}

// Print a byte range as text; non-printable bytes are shown as '.'
static void printText(const uint8_t *p, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++) {
        char c = (char)p[i];
        Serial.print((c >= 0x20 && c < 0x7F) ? c : '.');
    }
}

// =============================================================================
// LLDP decoding
// =============================================================================
// Chassis ID subtype 4 == MAC; Port ID subtype 3 == MAC. Print as MAC when the
// subtype/length matches, otherwise as text.
static void printLldpId(uint8_t subtype, const uint8_t *v, uint16_t len, bool isChassis)
{
    bool macSubtype = isChassis ? (subtype == 4) : (subtype == 3);
    if (macSubtype && len == 6) {
        printMac(v);
    } else {
        printText(v, len);
    }
}

// Management Address TLV (type 8) layout:
//   [0]      address string length (= subtype + address bytes)
//   [1]      address subtype (1 = IPv4, 2 = IPv6)
//   [2..]    address bytes
static void decodeLldpMgmt(const uint8_t *v, uint16_t len)
{
    if (len < 2) return;
    uint8_t addrLen = v[0];                 // includes the 1-byte subtype
    if (addrLen < 1 || (uint16_t)addrLen + 1 > len) return;
    uint8_t        subtype = v[1];
    const uint8_t *addr    = v + 2;
    uint8_t        alen    = addrLen - 1;

    Serial.print("  Mgmt Addr  : ");
    if (subtype == 1 && alen == 4) {        // IPv4
        Serial.printf("%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else {
        for (uint8_t i = 0; i < alen; i++) Serial.printf("%02X", addr[i]);
    }
    Serial.println();
}

// Organisationally-specific TLV (type 127). Decode IEEE 802.1 (OUI 00:80:C2)
// Port VLAN ID, which is the most useful field for a tester.
static void decodeLldpOrg(const uint8_t *v, uint16_t len)
{
    if (len < 4) return;
    if (v[0] == 0x00 && v[1] == 0x80 && v[2] == 0xC2) {     // IEEE 802.1
        uint8_t subtype = v[3];
        if (subtype == 1 && len >= 6) {                     // Port VLAN ID
            Serial.printf("  Port VLAN  : %u\r\n", rdU16(v + 4));
        }
    }
}

static void decodeLLDP(const uint8_t *p, uint16_t len)
{
    Serial.println("--- LLDP neighbour ---");
    uint16_t i = 0;
    while (i + 2 <= len) {
        uint16_t hdr  = rdU16(p + i);
        uint8_t  type = (hdr >> 9) & 0x7F;
        uint16_t tlen = hdr & 0x1FF;
        i += 2;
        if (type == 0) break;               // End-of-LLDPDU
        if (i + tlen > len) break;           // truncated
        const uint8_t *v = p + i;

        switch (type) {
            case 1:                          // Chassis ID
                Serial.print("  Chassis ID : ");
                if (tlen >= 1) printLldpId(v[0], v + 1, tlen - 1, true);
                Serial.println();
                break;
            case 2:                          // Port ID
                Serial.print("  Port ID    : ");
                if (tlen >= 1) printLldpId(v[0], v + 1, tlen - 1, false);
                Serial.println();
                break;
            case 3:                          // TTL
                if (tlen >= 2) Serial.printf("  TTL        : %u s\r\n", rdU16(v));
                break;
            case 4:                          // Port description
                Serial.print("  Port Desc  : "); printText(v, tlen); Serial.println();
                break;
            case 5:                          // System name
                Serial.print("  System Name: "); printText(v, tlen); Serial.println();
                break;
            case 6:                          // System description
                Serial.print("  System Desc: "); printText(v, tlen); Serial.println();
                break;
            case 7:                          // Capabilities
                if (tlen >= 4)
                    Serial.printf("  Caps       : 0x%04X / enabled 0x%04X\r\n",
                                  rdU16(v), rdU16(v + 2));
                break;
            case 8:                          // Management address
                decodeLldpMgmt(v, tlen);
                break;
            case 127:                        // Organisation-specific
                decodeLldpOrg(v, tlen);
                break;
            default:
                break;
        }
        i += tlen;
    }
}

// =============================================================================
// CDP decoding
// =============================================================================
// Addresses TLV (0x0002): 4-byte count, then per address:
//   protocol type(1), protocol length(1), protocol(plen),
//   address length(2), address(alen).  IPv4 => alen == 4.
static void decodeCdpAddresses(const uint8_t *v, uint16_t len)
{
    if (len < 4) return;
    uint32_t n = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) |
                 ((uint32_t)v[2] <<  8) |  (uint32_t)v[3];
    uint16_t i = 4;
    for (uint32_t a = 0; a < n && i + 2 <= len; a++) {
        uint8_t plen = v[i + 1];
        i += 2 + plen;                       // skip protocol type + length + protocol
        if (i + 2 > len) break;
        uint16_t alen = rdU16(v + i);
        i += 2;
        if (i + alen > len) break;
        if (alen == 4) {
            Serial.printf("  Mgmt Addr  : %u.%u.%u.%u\r\n",
                          v[i], v[i + 1], v[i + 2], v[i + 3]);
        }
        i += alen;
    }
}

// p points at the CDP header: version(1), TTL(1), checksum(2), then TLVs.
static void decodeCDP(const uint8_t *p, uint16_t len)
{
    if (len < 4) return;
    Serial.println("--- CDP neighbour ---");
    Serial.printf("  CDP Ver/TTL: v%u / %u s\r\n", p[0], p[1]);

    uint16_t i = 4;                          // skip version, ttl, checksum
    while (i + 4 <= len) {
        uint16_t type   = rdU16(p + i);
        uint16_t tlvLen = rdU16(p + i + 2);
        if (tlvLen < 4 || i + tlvLen > len) break;
        const uint8_t *v    = p + i + 4;
        uint16_t       vlen = tlvLen - 4;

        switch (type) {
            case 0x0001: Serial.print("  Device ID  : "); printText(v, vlen); Serial.println(); break;
            case 0x0002: decodeCdpAddresses(v, vlen); break;
            case 0x0003: Serial.print("  Port ID    : "); printText(v, vlen); Serial.println(); break;
            case 0x0004:
                if (vlen >= 4)
                    Serial.printf("  Caps       : 0x%02X%02X%02X%02X\r\n",
                                  v[0], v[1], v[2], v[3]);
                break;
            case 0x0005: Serial.print("  Version    : "); printText(v, vlen); Serial.println(); break;
            case 0x0006: Serial.print("  Platform   : "); printText(v, vlen); Serial.println(); break;
            case 0x000A:                     // Native VLAN
                if (vlen >= 2) Serial.printf("  Native VLAN: %u\r\n", rdU16(v));
                break;
            default:
                break;
        }
        i += tlvLen;
    }
}

// =============================================================================
// Public API
// =============================================================================
bool discoveryDecode(const uint8_t *frame, uint16_t len)
{
    if (len < ETH_HDR_LEN) return false;
    uint16_t ethType = rdU16(frame + 12);

    // LLDP: EtherType II 0x88CC
    if (ethType == LLDP_ETHERTYPE) {
        Serial.print("\r\nFrom "); printMac(frame + 6); Serial.println();
        decodeLLDP(frame + ETH_HDR_LEN, len - ETH_HDR_LEN);
        return true;
    }

    // CDP: 802.3 length field (<= 1500) + LLC/SNAP AA AA 03 00 00 0C 20 00
    if (ethType <= 1500 && len >= 26) {
        const uint8_t *llc = frame + 14;
        if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
            llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x0C &&
            llc[6] == 0x20 && llc[7] == 0x00) {
            Serial.print("\r\nFrom "); printMac(frame + 6); Serial.println();
            decodeCDP(frame + 22, len - 22);
            return true;
        }
    }

    return false;
}

uint32_t discoveryListen(W5500Raw &eth, uint32_t seconds)
{
    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t found    = 0;
    uint32_t deadline = millis() + seconds * 1000UL;

    Serial.printf("\r\nListening for LLDP/CDP for %lu s (press any key to stop)...\r\n",
                  (unsigned long)seconds);

    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len >= ETH_HDR_LEN) {
            if (discoveryDecode(buf, len)) found++;
        }
        if (Serial.available()) {
            while (Serial.available()) Serial.read();   // drain abort key
            break;
        }
        delay(1);
    }

    Serial.printf("\r\nDiscovery done. %lu neighbour PDU(s) decoded.\r\n",
                  (unsigned long)found);
    return found;
}

// =============================================================================
// Advertisement (transmit)
// =============================================================================
static const uint8_t LLDP_MULTICAST[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E };
static const uint8_t CDP_MULTICAST[6]  = { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC };

void discoveryAdvertInit(DiscoveryAdvert &a)
{
    memset(&a, 0, sizeof(a));
    strncpy(a.sysName,  "ESP32-Tester",          sizeof(a.sysName)  - 1);
    strncpy(a.portId,   "esp32/0",               sizeof(a.portId)   - 1);
    snprintf(a.platform, sizeof(a.platform), "Ethernet Tester v%s", FW_VERSION);
    a.lldpEnabled = false;
    a.cdpEnabled  = false;
    a.mgmtIp      = 0;
    a.vlan        = 0;
    a.ttl         = 120;
    a.intervalMs  = 30000;      // 30 s
}

// ---- LLDP TLV writer: header = (type << 9) | length ----
static uint16_t lldpTlv(uint8_t *p, uint8_t type, const uint8_t *val, uint16_t len)
{
    uint16_t hdr = ((uint16_t)type << 9) | (len & 0x01FF);
    p[0] = hdr >> 8;
    p[1] = hdr & 0xFF;
    if (len) memcpy(p + 2, val, len);
    return 2 + len;
}

uint16_t buildLLDP(uint8_t *buf, const uint8_t src[6], const DiscoveryAdvert &a)
{
    memcpy(buf,     LLDP_MULTICAST, 6);
    memcpy(buf + 6, src,            6);
    buf[12] = (LLDP_ETHERTYPE >> 8) & 0xFF;
    buf[13] =  LLDP_ETHERTYPE       & 0xFF;

    uint16_t i = ETH_HDR_LEN;
    uint8_t  t[80];

    // Chassis ID (type 1), subtype 4 = MAC address
    t[0] = 4;
    memcpy(t + 1, src, 6);
    i += lldpTlv(buf + i, 1, t, 7);

    // Port ID (type 2), subtype 7 = locally assigned
    {
        uint16_t n = strnlen(a.portId, sizeof(a.portId));
        t[0] = 7;
        memcpy(t + 1, a.portId, n);
        i += lldpTlv(buf + i, 2, t, 1 + n);
    }

    // Time To Live (type 3)
    t[0] = a.ttl >> 8;
    t[1] = a.ttl & 0xFF;
    i += lldpTlv(buf + i, 3, t, 2);

    // System Name (type 5)
    if (a.sysName[0])
        i += lldpTlv(buf + i, 5, (const uint8_t *)a.sysName,
                     strnlen(a.sysName, sizeof(a.sysName)));

    // System Description (type 6)
    if (a.platform[0])
        i += lldpTlv(buf + i, 6, (const uint8_t *)a.platform,
                     strnlen(a.platform, sizeof(a.platform)));

    // System Capabilities (type 7): Station Only (bit 7 = 0x0080), both
    // available and enabled.
    {
        const uint16_t cap = 0x0080;
        t[0] = cap >> 8; t[1] = cap & 0xFF;
        t[2] = cap >> 8; t[3] = cap & 0xFF;
        i += lldpTlv(buf + i, 7, t, 4);
    }

    // Management Address (type 8), IPv4
    if (a.mgmtIp) {
        t[0]  = 5;                          // addr string len = subtype(1) + IPv4(4)
        t[1]  = 1;                          // subtype 1 = IPv4
        t[2]  = (a.mgmtIp >> 24) & 0xFF;
        t[3]  = (a.mgmtIp >> 16) & 0xFF;
        t[4]  = (a.mgmtIp >>  8) & 0xFF;
        t[5]  =  a.mgmtIp        & 0xFF;
        t[6]  = 2;                          // interface subtype = ifIndex
        t[7]  = 0; t[8] = 0; t[9] = 0; t[10] = 1;   // interface number
        t[11] = 0;                          // OID string length
        i += lldpTlv(buf + i, 8, t, 12);
    }

    // Organisation-specific (type 127): IEEE 802.1 Port VLAN ID
    if (a.vlan) {
        t[0] = 0x00; t[1] = 0x80; t[2] = 0xC2;      // IEEE 802.1 OUI
        t[3] = 1;                                   // subtype 1 = Port VLAN ID
        t[4] = a.vlan >> 8; t[5] = a.vlan & 0xFF;
        i += lldpTlv(buf + i, 127, t, 6);
    }

    // End of LLDPDU (type 0, length 0)
    buf[i++] = 0;
    buf[i++] = 0;

    while (i < ETH_MIN_LEN) buf[i++] = 0;   // pad to minimum frame size
    return i;
}

// ---- CDP TLV writer: type(2), length(2, incl. header), value ----
static uint16_t cdpTlv(uint8_t *p, uint16_t type, const uint8_t *val, uint16_t len)
{
    uint16_t tlen = 4 + len;
    p[0] = type >> 8;   p[1] = type & 0xFF;
    p[2] = tlen >> 8;   p[3] = tlen & 0xFF;
    if (len) memcpy(p + 4, val, len);
    return tlen;
}

// CDP uses an IP-style 16-bit one's-complement checksum, with Cisco's quirk:
// a trailing odd byte is sign-extended into a 16-bit word.
static uint16_t cdpChecksum(const uint8_t *data, uint16_t len)
{
    uint32_t sum = 0;
    uint16_t i   = 0;
    while (i + 1 < len) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
        i   += 2;
    }
    if (len & 1) {
        uint16_t last = data[len - 1];
        if (last & 0x80) last |= 0xFF00;    // sign-extend
        sum += last;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t buildCDP(uint8_t *buf, const uint8_t src[6], const DiscoveryAdvert &a)
{
    memcpy(buf,     CDP_MULTICAST, 6);
    memcpy(buf + 6, src,           6);
    // [12..13] 802.3 length field — filled in once the payload size is known.

    // LLC/SNAP header: DSAP/SSAP/Ctrl = AA AA 03, OUI 00 00 0C, PID 0x2000 (CDP)
    uint8_t *snap = buf + ETH_HDR_LEN;
    snap[0] = 0xAA; snap[1] = 0xAA; snap[2] = 0x03;
    snap[3] = 0x00; snap[4] = 0x00; snap[5] = 0x0C;
    snap[6] = 0x20; snap[7] = 0x00;

    uint8_t *cdp = buf + 22;
    uint16_t c   = 0;
    cdp[c++] = 2;                                   // CDP version
    cdp[c++] = (a.ttl > 255) ? 255 : (uint8_t)a.ttl; // TTL (seconds)
    cdp[c++] = 0; cdp[c++] = 0;                     // checksum placeholder

    // Device ID (0x0001)
    if (a.sysName[0])
        c += cdpTlv(cdp + c, 0x0001, (const uint8_t *)a.sysName,
                    strnlen(a.sysName, sizeof(a.sysName)));

    // Addresses (0x0002): one IPv4 management address
    if (a.mgmtIp) {
        uint8_t v[13];
        v[0] = 0; v[1] = 0; v[2] = 0; v[3] = 1;     // number of addresses
        v[4] = 1;                                   // protocol type = NLPID
        v[5] = 1;                                   // protocol length
        v[6] = 0xCC;                                // protocol = IP
        v[7] = 0; v[8] = 4;                         // address length
        v[9]  = (a.mgmtIp >> 24) & 0xFF;
        v[10] = (a.mgmtIp >> 16) & 0xFF;
        v[11] = (a.mgmtIp >>  8) & 0xFF;
        v[12] =  a.mgmtIp        & 0xFF;
        c += cdpTlv(cdp + c, 0x0002, v, sizeof(v));
    }

    // Port ID (0x0003)
    if (a.portId[0])
        c += cdpTlv(cdp + c, 0x0003, (const uint8_t *)a.portId,
                    strnlen(a.portId, sizeof(a.portId)));

    // Capabilities (0x0004): Host (0x00000010)
    {
        const uint8_t cap[4] = { 0x00, 0x00, 0x00, 0x10 };
        c += cdpTlv(cdp + c, 0x0004, cap, 4);
    }

    // Software Version (0x0005) and Platform (0x0006)
    if (a.platform[0]) {
        uint16_t n = strnlen(a.platform, sizeof(a.platform));
        c += cdpTlv(cdp + c, 0x0005, (const uint8_t *)a.platform, n);
        c += cdpTlv(cdp + c, 0x0006, (const uint8_t *)a.platform, n);
    }

    // Native VLAN (0x000A)
    if (a.vlan) {
        uint8_t v[2] = { (uint8_t)(a.vlan >> 8), (uint8_t)(a.vlan & 0xFF) };
        c += cdpTlv(cdp + c, 0x000A, v, 2);
    }

    // Checksum over the CDP payload (with the field zeroed)
    uint16_t ck = cdpChecksum(cdp, c);
    cdp[2] = ck >> 8;
    cdp[3] = ck & 0xFF;

    // 802.3 length field = LLC/SNAP (8) + CDP payload
    uint16_t payload = 8 + c;
    buf[12] = payload >> 8;
    buf[13] = payload & 0xFF;

    uint16_t total = 22 + c;
    while (total < ETH_MIN_LEN) buf[total++] = 0;   // pad to minimum frame size
    return total;
}

void discoveryAdvertTick(W5500Raw &eth, const uint8_t src[6], DiscoveryAdvert &a)
{
    static uint8_t  txbuf[ETH_MAX_LEN];
    static uint32_t lastLldp = 0;
    static uint32_t lastCdp  = 0;
    uint32_t now = millis();

    if (a.lldpEnabled && (uint32_t)(now - lastLldp) >= a.intervalMs) {
        lastLldp = now;
        uint16_t len = buildLLDP(txbuf, src, a);
        eth.sendFrame(txbuf, len);
    }
    if (a.cdpEnabled && (uint32_t)(now - lastCdp) >= a.intervalMs) {
        lastCdp = now;
        uint16_t len = buildCDP(txbuf, src, a);
        eth.sendFrame(txbuf, len);
    }
}

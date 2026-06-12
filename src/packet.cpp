#include "packet.h"
#include "../include/config.h"
#include <esp_random.h>

// =============================================================================
// Internal helpers
// =============================================================================
static void writeU16BE(uint8_t *p, uint16_t v)
{
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

static void writeU32BE(uint8_t *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >>  8) & 0xFF;
    p[3] =  v & 0xFF;
}

static void writeU64BE(uint8_t *p, uint64_t v)
{
    writeU32BE(p,     (uint32_t)(v >> 32));
    writeU32BE(p + 4, (uint32_t)(v & 0xFFFFFFFFUL));
}

static uint64_t readU64BE(const uint8_t *p)
{
    uint64_t hi = ((uint64_t)p[0] << 24) | ((uint64_t)p[1] << 16) |
                  ((uint64_t)p[2] <<  8) |  (uint64_t)p[3];
    uint64_t lo = ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                  ((uint64_t)p[6] <<  8) |  (uint64_t)p[7];
    return (hi << 32) | lo;
}

// =============================================================================
// fillPattern
// =============================================================================
void fillPattern(uint8_t *buf, uint16_t len, PayloadPattern pattern)
{
    switch (pattern) {
        case PayloadPattern::ZEROS:
            memset(buf, 0x00, len);
            break;
        case PayloadPattern::ONES:
            memset(buf, 0xFF, len);
            break;
        case PayloadPattern::ALT:
            for (uint16_t i = 0; i < len; i++)
                buf[i] = (i & 1) ? 0x55 : 0xAA;
            break;
        case PayloadPattern::INCR:
            for (uint16_t i = 0; i < len; i++)
                buf[i] = i & 0xFF;
            break;
        case PayloadPattern::RANDOM:
            for (uint16_t i = 0; i < len; i += 4) {
                uint32_t r = esp_random();
                uint16_t rem = (len - i < 4) ? (len - i) : 4;
                memcpy(buf + i, &r, rem);
            }
            break;
    }
}

// =============================================================================
// buildFrame
// =============================================================================
uint16_t buildFrame(uint8_t       *buf,
                    const uint8_t  dst[6],
                    const uint8_t  src[6],
                    uint16_t       etherType,
                    const uint8_t *payload,
                    uint16_t       payloadLen)
{
    memcpy(buf,     dst, 6);
    memcpy(buf + 6, src, 6);
    writeU16BE(buf + 12, etherType);
    if (payloadLen > 0 && payload != nullptr)
        memcpy(buf + ETH_HDR_LEN, payload, payloadLen);
    return ETH_HDR_LEN + payloadLen;
}

// =============================================================================
// buildTestFrame
// frameLen: total frame bytes WITHOUT FCS (min 14 for header-only, normal min 60)
// =============================================================================
uint16_t buildTestFrame(uint8_t       *buf,
                        const uint8_t  dst[6],
                        const uint8_t  src[6],
                        uint16_t       frameLen,
                        PayloadPattern pattern)
{
    memcpy(buf,     dst, 6);
    memcpy(buf + 6, src, 6);
    writeU16BE(buf + 12, ETHERTYPE_TEST);

    uint16_t payLen = (frameLen > ETH_HDR_LEN) ? (frameLen - ETH_HDR_LEN) : 0;
    if (payLen > 0)
        fillPattern(buf + ETH_HDR_LEN, payLen, pattern);

    return ETH_HDR_LEN + payLen;
}

// =============================================================================
// buildProbeFrame
// Payload layout (from ETH_HDR_LEN):
//   [0..3]  PROBE_MAGIC (uint32_t big-endian)
//   [4..11] timestamp µs (uint64_t big-endian)
//   [12..]  0xAB padding
// =============================================================================
uint16_t buildProbeFrame(uint8_t       *buf,
                         const uint8_t  dst[6],
                         const uint8_t  src[6],
                         uint16_t       frameLen,
                         uint64_t       timestampUs)
{
    memcpy(buf,     dst, 6);
    memcpy(buf + 6, src, 6);
    writeU16BE(buf + 12, ETHERTYPE_TEST);

    uint8_t *pay = buf + ETH_HDR_LEN;
    uint16_t payLen = (frameLen > ETH_HDR_LEN) ? (frameLen - ETH_HDR_LEN) : 0;

    if (payLen >= 12) {
        writeU32BE(pay,     PROBE_MAGIC);
        writeU64BE(pay + 4, timestampUs);
        if (payLen > 12)
            memset(pay + 12, 0xAB, payLen - 12);
    } else {
        memset(pay, 0xAB, payLen);
    }

    return ETH_HDR_LEN + payLen;
}

// =============================================================================
// extractProbeTimestamp
// =============================================================================
bool extractProbeTimestamp(const uint8_t *frame, uint16_t len, uint64_t *tsOut)
{
    if (len < ETH_HDR_LEN + 12) return false;

    const uint8_t *pay = frame + ETH_HDR_LEN;

    uint32_t magic = ((uint32_t)pay[0] << 24) | ((uint32_t)pay[1] << 16) |
                     ((uint32_t)pay[2] <<  8) |  (uint32_t)pay[3];
    if (magic != PROBE_MAGIC) return false;

    if (tsOut) *tsOut = readU64BE(pay + 4);
    return true;
}

// =============================================================================
// buildPauseFrame
// Destination: 01:80:C2:00:00:01 (802.3x PAUSE multicast)
// EtherType: 0x8808
// =============================================================================
uint16_t buildPauseFrame(uint8_t *buf, const uint8_t src[6], uint16_t pauseQuanta)
{
    static const uint8_t pauseDst[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };
    memcpy(buf,     pauseDst, 6);
    memcpy(buf + 6, src, 6);
    writeU16BE(buf + 12, ETHERTYPE_PAUSE);

    // Control opcode (2 bytes) + pause time (2 bytes) + 42 bytes padding
    uint8_t *pay = buf + ETH_HDR_LEN;
    writeU16BE(pay,     PAUSE_OPCODE);
    writeU16BE(pay + 2, pauseQuanta);
    memset(pay + 4, 0x00, 42);  // pad to 60-byte minimum frame

    return 60;  // 14 header + 46 payload = 60 bytes without FCS
}

// =============================================================================
// MAC address helpers
// =============================================================================
void macToStr(const uint8_t mac[6], char *out)
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool strToMac(const char *str, uint8_t mac[6])
{
    unsigned int b[6] = {};
    int n = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
                   &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]);
    if (n != 6) return false;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)b[i];
    return true;
}

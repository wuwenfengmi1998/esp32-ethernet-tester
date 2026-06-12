#include "error_inject.h"
#include "../include/config.h"
#include "weblog.h"
#include <esp_timer.h>

#define Serial Out

// =============================================================================
// Construction
// =============================================================================
ErrorInject::ErrorInject(W5500Raw &eth,
                         const uint8_t srcMac[6],
                         const uint8_t dstMac[6])
    : _eth(eth)
{
    memcpy(_src, srcMac, 6);
    memcpy(_dst, dstMac, 6);
}

// =============================================================================
// injectRunts
// NOTE: The W5500 MAC auto-pads frames shorter than 60 bytes up to the 60-byte
// minimum before appending FCS. These frames therefore leave the wire at the
// legal 64-byte minimum and the DUT will NOT count them as runts. This is a
// hardware limitation of the W5500 (no register disables TX padding in MACRAW).
// =============================================================================
void ErrorInject::injectRunts(uint32_t count)
{
    uint8_t buf[ETH_RUNT_LEN];
    uint16_t len = buildTestFrame(buf, _dst, _src, ETH_RUNT_LEN, PayloadPattern::INCR);

    Serial.printf("Injecting %lu runt frames (%u-byte payload)...\r\n", count, len);
    Serial.println("WARNING: W5500 auto-pads short frames to 64 bytes on wire;");
    Serial.println("         the DUT will NOT register these as runts (hardware limit).");
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu runt frames.\r\n", sent, count);
}

// =============================================================================
// injectGiants
// Frame exceeds 1518 bytes on wire.  CX6300 counts as oversized / giant.
// =============================================================================
void ErrorInject::injectGiants(uint32_t count)
{
    static uint8_t buf[ETH_GIANT_LEN];
    uint16_t len = buildTestFrame(buf, _dst, _src, ETH_GIANT_LEN, PayloadPattern::INCR);

    Serial.printf("Injecting %lu giant frames (%u bytes without FCS)...\r\n",
                  count, len);
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu giant frames.\r\n", sent, count);
}

// =============================================================================
// injectJumbo
// Valid oversized frame. The DUT counts these as Jumbos when jumbo frames are
// enabled on the port; otherwise they are dropped or counted as giants.
// =============================================================================
void ErrorInject::injectJumbo(uint32_t count, uint16_t frameLen)
{
    if (frameLen <= ETH_MAX_LEN) frameLen = ETH_MAX_LEN + 100;   // ensure oversized
    if (frameLen > ETH_JUMBO_LEN) frameLen = ETH_JUMBO_LEN;

    static uint8_t buf[ETH_JUMBO_LEN];
    uint16_t len = buildTestFrame(buf, _dst, _src, frameLen, PayloadPattern::INCR);

    Serial.printf("Injecting %lu jumbo frames (%u bytes without FCS)...\r\n",
                  count, len);
    Serial.println("NOTE: counted as Jumbos only if jumbo MTU is enabled on the DUT port.");
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu jumbo frames.\r\n", sent, count);
}

// =============================================================================
// injectBroadcast
// Valid frames to FF:FF:FF:FF:FF:FF. DUT increments its broadcast RX counter.
// =============================================================================
void ErrorInject::injectBroadcast(uint32_t count, uint16_t frameLen)
{
    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;
    if (frameLen > ETH_MAX_LEN) frameLen = ETH_MAX_LEN;

    static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    static uint8_t buf[ETH_MAX_LEN];
    uint16_t len = buildTestFrame(buf, bcast, _src, frameLen, PayloadPattern::INCR);

    Serial.printf("Injecting %lu broadcast frames (%u bytes)...\r\n", count, len);
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu broadcast frames.\r\n", sent, count);
}

// =============================================================================
// injectMulticast
// Valid frames to an IPv4 multicast MAC. DUT increments its multicast counter.
// =============================================================================
void ErrorInject::injectMulticast(uint32_t count, uint16_t frameLen)
{
    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;
    if (frameLen > ETH_MAX_LEN) frameLen = ETH_MAX_LEN;

    static const uint8_t mcast[6] = INJECT_MCAST_MAC;
    static uint8_t buf[ETH_MAX_LEN];
    uint16_t len = buildTestFrame(buf, mcast, _src, frameLen, PayloadPattern::INCR);

    Serial.printf("Injecting %lu multicast frames (%u bytes, DA %02X:%02X:%02X:%02X:%02X:%02X)...\r\n",
                  count, len, mcast[0], mcast[1], mcast[2], mcast[3], mcast[4], mcast[5]);
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu multicast frames.\r\n", sent, count);
}

// =============================================================================
// injectBadEthertype
// Uses EtherType 0x88B6 which is IEEE 802 locally assigned and not in use.
// The CX6300 will count these as input errors if strict EtherType checking
// is enabled; otherwise they pass through (useful for verifying ACLs).
// =============================================================================
void ErrorInject::injectBadEthertype(uint32_t count)
{
    uint8_t buf[ETH_MIN_LEN];
    uint8_t payload[ETH_MIN_LEN - ETH_HDR_LEN];
    fillPattern(payload, sizeof(payload), PayloadPattern::INCR);
    uint16_t len = buildFrame(buf, _dst, _src, 0x88B6, payload, sizeof(payload));

    Serial.printf("Injecting %lu frames with reserved EtherType 0x88B6...\r\n", count);
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu frames.\r\n", sent, count);
}

// =============================================================================
// injectPauseFrames
// 802.3x PAUSE frames to throttle the CX6300 transmitter on this port.
// Destination is the reserved PAUSE multicast 01:80:C2:00:00:01.
// =============================================================================
void ErrorInject::injectPauseFrames(uint32_t count, uint16_t quanta)
{
    uint8_t buf[60];
    uint16_t len = buildPauseFrame(buf, _src, quanta);

    Serial.printf("Injecting %lu PAUSE frames (quanta=%u, ~%.1f ms each)...\r\n",
                  count, quanta, quanta * 5.12f / 1000.0f);
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu PAUSE frames.\r\n", sent, count);
}

// =============================================================================
// injectPayloadPattern
// =============================================================================
void ErrorInject::injectPayloadPattern(PayloadPattern pattern,
                                       uint16_t frameLen,
                                       uint32_t count)
{
    // Clamp frameLen
    if (frameLen < ETH_HDR_LEN + 1)
        frameLen = ETH_MIN_LEN;
    if (frameLen > ETH_MAX_LEN)
        frameLen = ETH_MAX_LEN;

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint16_t len = buildTestFrame(buf, _dst, _src, frameLen, pattern);

    const char *pname[] = { "zeros", "ones", "alternating (0xAA/0x55)", "incrementing", "random" };
    Serial.printf("Injecting %lu frames, %u bytes, pattern: %s...\r\n",
                  count, len, pname[(uint8_t)pattern % 5]);

    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, len)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu frames.\r\n", sent, count);
}

// =============================================================================
// Storm control
// =============================================================================
void ErrorInject::startStorm(uint32_t rateHz)
{
    if (rateHz == 0) { stopStorm(); return; }
    if (rateHz > STORM_MAX_RATE_HZ) rateHz = STORM_MAX_RATE_HZ;

    _stormIntervalUs = 1000000UL / rateHz;
    _stormNextUs     = (uint64_t)esp_timer_get_time();
    _stormActive     = true;

    // Pre-build the storm frame (broadcast, ALT pattern, minimum size)
    static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    _stormBufLen = buildTestFrame(_stormBuf, bcast, _src, ETH_MIN_LEN, PayloadPattern::ALT);

    Serial.printf("Storm started: ~%lu fps, interval %lu µs.\r\n",
                  rateHz, _stormIntervalUs);
}

void ErrorInject::stopStorm()
{
    _stormActive = false;
    Serial.println("Storm stopped.");
}

void ErrorInject::tick()
{
    if (_stormActive) {
        uint64_t now = (uint64_t)esp_timer_get_time();
        if (now >= _stormNextUs) {
            _eth.sendFrame(_stormBuf, _stormBufLen);
            _stormNextUs += _stormIntervalUs;
        }
    }

    if (_contActive) {
        uint64_t now = (uint64_t)esp_timer_get_time();
        if (now >= _contNextUs) {
            _eth.sendFrame(_contBuf, _contBufLen);
            _contNextUs += _contIntervalUs;
        }
    }
}

// =============================================================================
// Continuous error injection
// =============================================================================
const char *ErrorInject::continuousName() const
{
    switch (_contType) {
        case ContType::GIANT:     return "giant";
        case ContType::JUMBO:     return "jumbo";
        case ContType::BADTYPE:   return "badtype";
        case ContType::BROADCAST: return "broadcast";
        case ContType::MULTICAST: return "multicast";
        case ContType::PAUSE:     return "pause";
        case ContType::PATTERN:   return "pattern";
    }
    return "?";
}

void ErrorInject::startContinuous(ContType type, uint32_t rateHz,
                                  uint16_t frameLen, PayloadPattern pattern)
{
    if (rateHz == 0) { stopContinuous(); return; }
    if (rateHz > STORM_MAX_RATE_HZ) rateHz = STORM_MAX_RATE_HZ;

    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;

    static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    static const uint8_t mcast[6] = INJECT_MCAST_MAC;

    switch (type) {
        case ContType::GIANT:
            _contBufLen = buildTestFrame(_contBuf, _dst, _src, ETH_GIANT_LEN, pattern);
            break;
        case ContType::JUMBO:
            if (frameLen <= ETH_MAX_LEN) frameLen = ETH_MAX_LEN + 100;
            if (frameLen > ETH_GIANT_LEN) frameLen = ETH_GIANT_LEN;
            _contBufLen = buildTestFrame(_contBuf, _dst, _src, frameLen, pattern);
            break;
        case ContType::BADTYPE: {
            uint8_t payload[ETH_MIN_LEN - ETH_HDR_LEN];
            fillPattern(payload, sizeof(payload), pattern);
            _contBufLen = buildFrame(_contBuf, _dst, _src, 0x88B6, payload, sizeof(payload));
            break;
        }
        case ContType::BROADCAST:
            if (frameLen > ETH_MAX_LEN) frameLen = ETH_MAX_LEN;
            _contBufLen = buildTestFrame(_contBuf, bcast, _src, frameLen, pattern);
            break;
        case ContType::MULTICAST:
            if (frameLen > ETH_MAX_LEN) frameLen = ETH_MAX_LEN;
            _contBufLen = buildTestFrame(_contBuf, mcast, _src, frameLen, pattern);
            break;
        case ContType::PAUSE:
            _contBufLen = buildPauseFrame(_contBuf, _src, 0xFFFF);
            break;
        case ContType::PATTERN:
            if (frameLen > ETH_MAX_LEN) frameLen = ETH_MAX_LEN;
            _contBufLen = buildTestFrame(_contBuf, _dst, _src, frameLen, pattern);
            break;
    }

    _contType       = type;
    _contIntervalUs = 1000000UL / rateHz;
    _contNextUs     = (uint64_t)esp_timer_get_time();
    _contActive     = true;

    Serial.printf("Continuous '%s' injection started: ~%lu fps, %u-byte frames.\r\n",
                  continuousName(), (unsigned long)rateHz, _contBufLen);
}

void ErrorInject::stopContinuous()
{
    if (_contActive) {
        _contActive = false;
        Serial.println("Continuous injection stopped.");
    }
}


#pragma once

#include <Arduino.h>

// =============================================================================
// Ethernet frame builder utilities
// All frames are built WITHOUT FCS (W5500 appends FCS automatically in MACRAW).
// =============================================================================

// Payload fill patterns used by test and injection functions
enum class PayloadPattern : uint8_t {
    ZEROS    = 0,   // 0x00 0x00 ...
    ONES     = 1,   // 0xFF 0xFF ...
    ALT      = 2,   // 0xAA 0x55 alternating (stress-tests signal integrity)
    INCR     = 3,   // 0x00 0x01 0x02 ... (incrementing byte)
    RANDOM   = 4,   // esp_random()-filled bytes
};

// Build a standard Ethernet frame into buf[].
// dst/src: 6-byte MAC addresses.
// etherType: big-endian EtherType.
// payload / payloadLen: payload bytes and length.
// Returns total frame length written (ETH_HDR_LEN + payloadLen).
uint16_t buildFrame(uint8_t       *buf,
                    const uint8_t  dst[6],
                    const uint8_t  src[6],
                    uint16_t       etherType,
                    const uint8_t *payload,
                    uint16_t       payloadLen);

// Build a frame with a generated payload of the given length and pattern.
// frameLen: desired total frame size WITHOUT FCS (e.g. 60 for 64-byte on wire).
// Returns total bytes written.
uint16_t buildTestFrame(uint8_t        *buf,
                        const uint8_t   dst[6],
                        const uint8_t   src[6],
                        uint16_t        frameLen,
                        PayloadPattern  pattern = PayloadPattern::INCR);

// Build an RFC 2544 latency probe frame.
// Embeds PROBE_MAGIC + 64-bit timestamp (µs) in the payload.
// frameLen: desired total frame size WITHOUT FCS.
uint16_t buildProbeFrame(uint8_t       *buf,
                         const uint8_t  dst[6],
                         const uint8_t  src[6],
                         uint16_t       frameLen,
                         uint64_t       timestampUs);

// Extract timestamp from a received probe frame.
// Returns true and sets *tsOut if the frame contains a valid probe magic number.
bool extractProbeTimestamp(const uint8_t *frame, uint16_t len, uint64_t *tsOut);

// Build an 802.3x PAUSE frame.
// pauseTime: pause quanta (each quantum = 512 bit times at link speed).
// buf must be at least 60 bytes.
uint16_t buildPauseFrame(uint8_t *buf, const uint8_t src[6], uint16_t pauseQuanta);

// Fill a buffer with the requested pattern.
void fillPattern(uint8_t *buf, uint16_t len, PayloadPattern pattern);

// Helpers
void macToStr(const uint8_t mac[6], char *out);   // "AA:BB:CC:DD:EE:FF\0"
bool strToMac(const char *str, uint8_t mac[6]);   // parse "AA:BB:CC:DD:EE:FF"

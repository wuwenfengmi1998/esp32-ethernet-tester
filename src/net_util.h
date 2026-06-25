#pragma once

#include <Arduino.h>

// =============================================================================
// Small shared networking helpers used by the L2/L3 test & assessment modules.
// All multi-byte values are big-endian (network order) on the wire.
// =============================================================================

// Write a 16-bit value big-endian.
static inline void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

// Write a 32-bit value big-endian.
static inline void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

static inline uint16_t get16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  p[3];
}

// One's-complement Internet checksum (RFC 1071). Pass a running `sum` to chain
// pseudo-header + data; finalise once. Returns the folded 16-bit value.
static inline uint16_t inetChecksum(const uint8_t *data, uint32_t len, uint32_t sum = 0)
{
    while (len > 1) { sum += ((uint32_t)data[0] << 8) | data[1]; data += 2; len -= 2; }
    if (len)        { sum += (uint32_t)data[0] << 8; }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

// Format a host-order IPv4 into "a.b.c.d" (buf >= 16 bytes).
static inline void ipToStr(uint32_t ip, char *out)
{
    sprintf(out, "%u.%u.%u.%u",
            (unsigned)((ip >> 24) & 0xFF), (unsigned)((ip >> 16) & 0xFF),
            (unsigned)((ip >> 8) & 0xFF),  (unsigned)(ip & 0xFF));
}

// Parse "a.b.c.d" into a host-order IPv4. Returns true on success.
static inline bool strToIp(const char *s, uint32_t *out)
{
    unsigned a, b, c, d;
    if (!s || sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *out = ((uint32_t)a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

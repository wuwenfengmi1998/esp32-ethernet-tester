#pragma once

#include <Arduino.h>
#include "../include/config.h"
#include "w5500_raw.h"
#include "packet.h"

// =============================================================================
// Error / Anomaly Injection
//
// Hardware note: The W5500 automatically calculates and appends the 4-byte FCS
// in MACRAW mode. True CRC error injection (corrupted FCS) therefore requires
// a hardware-level bit manipulator and is NOT possible through the W5500.
//
// What CAN be injected through the W5500 in MACRAW mode:
//   - Runt frames   (<64 bytes on wire): W5500 sends without padding
//   - Giant frames  (>1518 bytes): exceeds standard max frame size
//   - Bad EtherType: reserved/undefined EtherType values
//   - PAUSE frames  (802.3x): asserts flow control against the CX6300 port
//   - Broadcast storm: high-rate frames to flood the port
//   - Payload stress patterns: signal-integrity stress via alternating bit patterns
// =============================================================================

class ErrorInject {
public:
    ErrorInject(W5500Raw &eth,
                const uint8_t srcMac[6],
                const uint8_t dstMac[6]);

    // Continuous error type selector (for startContinuous()).
    enum class ContType : uint8_t {
        GIANT = 0,
        JUMBO,
        BADTYPE,
        BROADCAST,
        MULTICAST,
        PAUSE,
        PATTERN,
    };

    // Update source / destination MAC (e.g. after CLI `mac` command).
    void setSrcMac(const uint8_t mac[6]) { memcpy(_src, mac, 6); }
    void setDstMac(const uint8_t mac[6]) { memcpy(_dst, mac, 6); }

    // --- One-shot injectors ---

    // Send `count` runt frames (<64 bytes on wire).
    // WARNING: The W5500 MAC auto-pads any TX frame shorter than 60 bytes up to
    // the 60-byte minimum (then appends FCS), so frames leave the wire at the
    // legal 64-byte minimum. True runt injection is therefore NOT possible
    // through the W5500 and the DUT will not count these as runts.
    void injectRunts(uint32_t count = INJECT_DEFAULT_COUNT);

    // Send `count` giant frames (>1518 bytes on wire) with an invalid oversize
    // length. The DUT counts these as giants/oversized.
    void injectGiants(uint32_t count = INJECT_DEFAULT_COUNT);

    // Send `count` jumbo frames of `frameLen` bytes (valid, oversized). The DUT
    // counts these as Jumbos only if jumbo frames are enabled on the port;
    // otherwise they are dropped/counted as giants.
    void injectJumbo(uint32_t count = INJECT_DEFAULT_COUNT,
                     uint16_t frameLen = ETH_JUMBO_LEN);

    // Send `count` valid frames to the broadcast address (FF:FF:FF:FF:FF:FF).
    void injectBroadcast(uint32_t count = INJECT_DEFAULT_COUNT,
                         uint16_t frameLen = ETH_MIN_LEN);

    // Send `count` valid frames to an IPv4 multicast address (01:00:5E:00:00:01).
    void injectMulticast(uint32_t count = INJECT_DEFAULT_COUNT,
                         uint16_t frameLen = ETH_MIN_LEN);

    // Send `count` frames with a reserved/undefined EtherType (0x88B6).
    void injectBadEthertype(uint32_t count = INJECT_DEFAULT_COUNT);

    // Send `count` 802.3x PAUSE frames with the given quanta (0–65535).
    // Each quantum = 512 bit-times (~5.12 µs at 100 Mbps).
    void injectPauseFrames(uint32_t count = INJECT_DEFAULT_COUNT,
                           uint16_t quanta = 0xFFFF);

    // Send `count` frames filled with the given payload stress pattern.
    void injectPayloadPattern(PayloadPattern pattern,
                              uint16_t frameLen = ETH_MIN_LEN,
                              uint32_t count = INJECT_DEFAULT_COUNT);

    // --- Continuous / background storm control ---

    // Start a broadcast storm at approx. `rateHz` frames per second.
    // Actual rate is capped at STORM_MAX_RATE_HZ.
    // Call tick() repeatedly from loop() to sustain the storm.
    void startStorm(uint32_t rateHz);

    // Stop the broadcast storm.
    void stopStorm();

    bool isStormActive() const { return _stormActive; }

    // --- Continuous error injection ---
    // Continuously emit frames of the given error type at approx. `rateHz`
    // frames per second (capped at STORM_MAX_RATE_HZ). Driven by tick().
    // `frameLen` / `pattern` apply to PATTERN/JUMBO/BROADCAST/MULTICAST types.
    void startContinuous(ContType type, uint32_t rateHz,
                         uint16_t frameLen = ETH_MIN_LEN,
                         PayloadPattern pattern = PayloadPattern::INCR);

    // Stop continuous error injection.
    void stopContinuous();

    bool isContinuousActive() const { return _contActive; }
    const char *continuousName() const;

    // Call this from loop() to drive the background storm.
    void tick();

private:
    W5500Raw &_eth;
    uint8_t   _src[6];
    uint8_t   _dst[6];

    // Storm state
    bool     _stormActive   = false;
    uint32_t _stormIntervalUs = 0;
    uint64_t _stormNextUs     = 0;
    uint8_t  _stormBuf[ETH_MIN_LEN];
    uint16_t _stormBufLen   = 0;

    // Continuous-injection state
    bool     _contActive    = false;
    ContType _contType      = ContType::GIANT;
    uint32_t _contIntervalUs = 0;
    uint64_t _contNextUs     = 0;
    uint8_t  _contBuf[ETH_GIANT_LEN];
    uint16_t _contBufLen    = 0;
};

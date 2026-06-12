#pragma once

#include <Arduino.h>
#include "../include/config.h"
#include "w5500_raw.h"
#include "packet.h"

// =============================================================================
// RFC 2544 Benchmarking Test Suite
//
// Test topology requirements:
//   - Connect the ESP32+W5500 to an Aruba CX6300 port.
//   - For throughput, latency, frame-loss, and back-to-back tests the DUT
//     must reflect frames back to the tester.  Two options:
//
//     Option A — Port loopback (single cable):
//       Enable on CX6300:  interface 1/1/X → loopback
//
//     Option B — Cable loop (two cables):
//       Connect port A to the tester; connect port B back to port A via a
//       second cable.  The switch floods the broadcast frames back.
//
// Tests implemented (per RFC 2544):
//   1. Throughput      — max frame rate with zero frame loss (binary search)
//   2. Latency         — average round-trip delay at throughput rate
//   3. Frame Loss Rate — loss % across a range of offered loads
//   4. Back-to-Back    — maximum burst of back-to-back frames without loss
// =============================================================================

struct RFC2544Result {
    uint16_t frameSize;      // frame size tested (bytes, WITH FCS on wire)
    uint32_t throughputFps;  // max zero-loss rate (frames/sec)
    float    throughputMbps; // throughput in Mbps
    uint32_t latencyUsMin;   // minimum RTT (µs)
    uint32_t latencyUsMax;   // maximum RTT (µs)
    uint32_t latencyUsAvg;   // average RTT (µs)
    float    lossPercent;    // frame loss at throughput rate (should be 0)
    uint32_t backToBack;     // max burst frames without loss
};

class RFC2544 {
public:
    RFC2544(W5500Raw &eth,
            const uint8_t srcMac[6],
            const uint8_t dstMac[6]);

    void setSrcMac(const uint8_t mac[6]) { memcpy(_src, mac, 6); }
    void setDstMac(const uint8_t mac[6]) { memcpy(_dst, mac, 6); }

    // Run throughput test for one frame size.  Returns zero-loss fps.
    uint32_t testThroughput(uint16_t frameSizeWithFCS, uint16_t durationSec = RFC2544_TEST_SEC);

    // Run latency test at given offered load (fps).
    // Returns average RTT in µs, or 0 on failure.
    uint32_t testLatency(uint16_t frameSizeWithFCS, uint32_t offeredFps);

    // Run frame-loss-rate test across 100%, 50%, 10% offered loads.
    // Prints results to Serial.
    void testFrameLoss(uint16_t frameSizeWithFCS, uint16_t durationSec = RFC2544_TEST_SEC);

    // Run back-to-back burst test.
    // Returns maximum burst count without loss.
    uint32_t testBackToBack(uint16_t frameSizeWithFCS);

    // Run the full RFC 2544 suite across all mandated frame sizes.
    void runFullSuite();

    // Print a single result struct to Serial.
    static void printResult(const RFC2544Result &r);

private:
    W5500Raw &_eth;
    uint8_t   _src[6];
    uint8_t   _dst[6];

    // Send frames at targetFps for durationUs microseconds.
    // Returns: txCount, rxCount (received reflected frames).
    void _runLoad(uint16_t frameLen,        // WITHOUT FCS
                  uint32_t targetFps,
                  uint64_t durationUs,
                  uint32_t &txOut,
                  uint32_t &rxOut);

    // Flush the RX buffer (drain any queued frames with short timeout).
    void _flushRx(uint32_t timeoutMs = 200);

    // Calculate theoretical max fps for a given frame size (bytes with FCS)
    // at 100 Mbps full-duplex.
    static uint32_t _theoreticalFps(uint16_t frameSizeWithFCS);
};

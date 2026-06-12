#include "rfc2544.h"
#include "../include/config.h"
#include "weblog.h"
#include <esp_timer.h>

#define Serial Out

// =============================================================================
// Construction
// =============================================================================
RFC2544::RFC2544(W5500Raw &eth,
                 const uint8_t srcMac[6],
                 const uint8_t dstMac[6])
    : _eth(eth)
{
    memcpy(_src, srcMac, 6);
    memcpy(_dst, dstMac, 6);
}

// =============================================================================
// Theoretical frame rate at 100 Mbps
// Frame on wire = frameSize (incl. FCS) + 8 bytes preamble/SFD + 12 bytes IFG
// =============================================================================
uint32_t RFC2544::_theoreticalFps(uint16_t frameSizeWithFCS)
{
    uint32_t wireBits = (uint32_t)(frameSizeWithFCS + 20) * 8;
    return 100000000UL / wireBits;   // 100 Mbps
}

// =============================================================================
// Flush RX buffer
// =============================================================================
void RFC2544::_flushRx(uint32_t timeoutMs)
{
    static uint8_t tmp[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + timeoutMs;
    while (millis() < deadline) {
        if (_eth.recvFrame(tmp, sizeof(tmp)) == 0) break;
    }
}

// =============================================================================
// _runLoad — core TX/RX engine
// frameLen: frame size WITHOUT FCS (as supplied to sendFrame).
// =============================================================================
void RFC2544::_runLoad(uint16_t frameLen,
                       uint32_t targetFps,
                       uint64_t durationUs,
                       uint32_t &txOut,
                       uint32_t &rxOut)
{
    static uint8_t txBuf[ETH_GIANT_LEN];
    static uint8_t rxBuf[ETH_GIANT_LEN];

    buildTestFrame(txBuf, _dst, _src, frameLen, PayloadPattern::INCR);

    uint64_t intervalUs = (targetFps > 0) ? (1000000ULL / targetFps) : 0;
    uint64_t startUs    = (uint64_t)esp_timer_get_time();
    uint64_t nextSendUs = startUs;
    uint64_t endUs      = startUs + durationUs;

    txOut = 0;
    rxOut = 0;

    while ((uint64_t)esp_timer_get_time() < endUs) {
        uint64_t now = (uint64_t)esp_timer_get_time();

        // TX: send one frame if it's time
        if (intervalUs == 0 || now >= nextSendUs) {
            if (_eth.sendFrame(txBuf, frameLen)) {
                txOut++;
                if (intervalUs > 0) nextSendUs += intervalUs;
            }
        }

        // RX: drain received frames
        while (_eth.recvFrame(rxBuf, sizeof(rxBuf)) > 0) {
            rxOut++;
        }

        // Allow periodic abort check (press any key)
        if (Serial.available()) {
            Serial.read();   // consume char
            Serial.println("\r\n[Aborted by user]");
            break;
        }
    }

    // Drain remaining RX frames (allow up to 500 ms for in-flight frames)
    uint32_t drainDeadline = millis() + 500;
    while (millis() < drainDeadline) {
        if (_eth.recvFrame(rxBuf, sizeof(rxBuf)) > 0) rxOut++;
    }
}

// =============================================================================
// Throughput test — binary search for maximum zero-loss rate
// =============================================================================
uint32_t RFC2544::testThroughput(uint16_t frameSizeWithFCS, uint16_t durationSec)
{
    // frameLen for W5500 (without FCS)
    uint16_t frameLen = frameSizeWithFCS - 4;
    if (frameLen < ETH_HDR_LEN + 1) frameLen = ETH_MIN_LEN;

    uint32_t maxFps   = _theoreticalFps(frameSizeWithFCS);
    uint64_t durUs    = (uint64_t)durationSec * 1000000ULL;

    Serial.printf("\r\n--- Throughput: %u-byte frames (max %.0f fps) ---\r\n",
                  frameSizeWithFCS, (float)maxFps);

    uint32_t lo = 0, hi = maxFps;
    uint32_t bestFps = 0;

    for (int iter = 0; iter < RFC2544_SEARCH_N; iter++) {
        uint32_t mid = (lo + hi) / 2;
        if (mid == 0) break;

        uint32_t tx = 0, rx = 0;
        _flushRx(100);
        _runLoad(frameLen, mid, durUs, tx, rx);

        uint32_t loss = (tx > rx) ? (tx - rx) : 0;
        float    pct  = (tx > 0) ? (100.0f * loss / tx) : 100.0f;

        Serial.printf("  iter %2d: %6lu fps, tx=%lu rx=%lu loss=%.2f%%\r\n",
                      iter + 1, mid, tx, rx, pct);

        if (loss <= (uint32_t)RFC2544_LOSS_MAX) {
            bestFps = mid;
            lo = mid;
        } else {
            hi = mid;
        }
    }

    float mbps = (float)bestFps * (frameSizeWithFCS + 20) * 8 / 1e6f;
    Serial.printf("Throughput result: %lu fps  (%.2f Mbps)\r\n", bestFps, mbps);
    return bestFps;
}

// =============================================================================
// Latency test — RTT measurement using timestamped probe frames
// Requires DUT loopback to be active.
// =============================================================================
uint32_t RFC2544::testLatency(uint16_t frameSizeWithFCS, uint32_t offeredFps)
{
    uint16_t frameLen = frameSizeWithFCS - 4;
    if (frameLen < ETH_HDR_LEN + 12) frameLen = ETH_HDR_LEN + 12;

    Serial.printf("\r\n--- Latency: %u-byte frames at %lu fps ---\r\n",
                  frameSizeWithFCS, offeredFps);

    static uint8_t txBuf[ETH_MAX_LEN];
    static uint8_t rxBuf[ETH_MAX_LEN];

    uint32_t samples[LATENCY_SAMPLES] = {};
    uint32_t nSamples = 0;

    _flushRx(200);

    for (uint32_t i = 0; i < LATENCY_SAMPLES; i++) {
        uint64_t sendTs = (uint64_t)esp_timer_get_time();
        buildProbeFrame(txBuf, _dst, _src, frameLen, sendTs);

        if (!_eth.sendFrame(txBuf, frameLen)) continue;

        // Wait for probe frame to return (timeout 1 second)
        uint32_t deadline = millis() + 1000;
        bool got = false;
        while (millis() < deadline && !got) {
            uint16_t rlen = _eth.recvFrame(rxBuf, sizeof(rxBuf));
            if (rlen > 0) {
                uint64_t rxTs;
                if (extractProbeTimestamp(rxBuf, rlen, &rxTs)) {
                    uint64_t rtt = (uint64_t)esp_timer_get_time() - rxTs;
                    samples[nSamples++] = (uint32_t)rtt;
                    got = true;
                }
            }
        }

        // Inter-probe gap (keep offered load)
        if (offeredFps > 0) {
            uint32_t gapUs = 1000000UL / offeredFps;
            delayMicroseconds(gapUs);
        } else {
            delay(10);
        }
    }

    if (nSamples == 0) {
        Serial.println("No probe frames returned. Is DUT loopback active?");
        return 0;
    }

    uint32_t minRtt = UINT32_MAX, maxRtt = 0;
    uint64_t sumRtt = 0;
    for (uint32_t i = 0; i < nSamples; i++) {
        if (samples[i] < minRtt) minRtt = samples[i];
        if (samples[i] > maxRtt) maxRtt = samples[i];
        sumRtt += samples[i];
    }
    uint32_t avgRtt = (uint32_t)(sumRtt / nSamples);

    Serial.printf("Latency  samples=%lu  min=%lu µs  avg=%lu µs  max=%lu µs\r\n",
                  nSamples, minRtt, avgRtt, maxRtt);
    Serial.printf("  One-way (RTT/2):  min=%lu µs  avg=%lu µs  max=%lu µs\r\n",
                  minRtt / 2, avgRtt / 2, maxRtt / 2);
    return avgRtt;
}

// =============================================================================
// Frame Loss Rate test at 100%, 50%, 10% of line rate
// =============================================================================
void RFC2544::testFrameLoss(uint16_t frameSizeWithFCS, uint16_t durationSec)
{
    uint16_t frameLen = frameSizeWithFCS - 4;
    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;

    uint32_t maxFps = _theoreticalFps(frameSizeWithFCS);
    uint64_t durUs  = (uint64_t)durationSec * 1000000ULL;

    Serial.printf("\r\n--- Frame Loss Rate: %u-byte frames ---\r\n", frameSizeWithFCS);

    static const uint8_t loads[] = { 100, 50, 10 };
    for (uint8_t k = 0; k < 3; k++) {
        uint32_t fps = (uint32_t)((uint64_t)maxFps * loads[k] / 100);
        if (fps == 0) continue;

        uint32_t tx = 0, rx = 0;
        _flushRx(100);
        _runLoad(frameLen, fps, durUs, tx, rx);

        uint32_t loss = (tx > rx) ? (tx - rx) : 0;
        float    pct  = (tx > 0) ? (100.0f * loss / tx) : 100.0f;

        Serial.printf("  %3u%% load  (%6lu fps): tx=%lu rx=%lu loss=%lu (%.4f%%)\r\n",
                      loads[k], fps, tx, rx, loss, pct);
    }
}

// =============================================================================
// Back-to-Back burst test — binary search for largest burst without loss
// =============================================================================
uint32_t RFC2544::testBackToBack(uint16_t frameSizeWithFCS)
{
    uint16_t frameLen = frameSizeWithFCS - 4;
    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;

    Serial.printf("\r\n--- Back-to-Back: %u-byte frames ---\r\n", frameSizeWithFCS);

    static uint8_t txBuf[ETH_MAX_LEN];
    static uint8_t rxBuf[ETH_MAX_LEN];
    buildTestFrame(txBuf, _dst, _src, frameLen, PayloadPattern::INCR);

    uint32_t lo = 0, hi = 10000, bestBurst = 0;

    for (int iter = 0; iter < RFC2544_SEARCH_N; iter++) {
        uint32_t burst = (lo + hi) / 2;
        if (burst == 0) break;

        _flushRx(100);

        // Send burst as fast as possible
        uint32_t sent = 0;
        for (uint32_t i = 0; i < burst; i++) {
            if (_eth.sendFrame(txBuf, frameLen)) sent++;
        }

        // Wait to receive all frames (up to 2 seconds)
        uint32_t rx = 0;
        uint32_t deadline = millis() + 2000;
        while (millis() < deadline) {
            if (_eth.recvFrame(rxBuf, sizeof(rxBuf)) > 0) rx++;
        }

        uint32_t loss = (sent > rx) ? (sent - rx) : 0;
        Serial.printf("  iter %2d: burst=%lu sent=%lu rx=%lu loss=%lu\r\n",
                      iter + 1, burst, sent, rx, loss);

        if (loss == 0) { bestBurst = burst; lo = burst; }
        else           { hi = burst; }
    }

    Serial.printf("Back-to-back result: %lu frames\r\n", bestBurst);
    return bestBurst;
}

// =============================================================================
// Full RFC 2544 suite
// =============================================================================
void RFC2544::runFullSuite()
{
    Serial.println("\r\n========================================");
    Serial.println(" RFC 2544 Benchmark Suite");
    Serial.println("========================================");
    Serial.printf("Frame sizes: ");
    for (int i = 0; i < RFC2544_NUM_SIZES; i++)
        Serial.printf("%u%s", RFC2544_SIZES[i], (i < RFC2544_NUM_SIZES-1) ? ", " : "\r\n");
    Serial.printf("Test duration: %d sec/size\r\n", RFC2544_TEST_SEC);
    Serial.println("Press any key to abort a running test.\r\n");

    for (int i = 0; i < RFC2544_NUM_SIZES; i++) {
        uint16_t sz = RFC2544_SIZES[i];
        Serial.printf("\r\n=== Frame Size: %u bytes ===\r\n", sz);

        uint32_t tpFps  = testThroughput(sz, RFC2544_TEST_SEC);
        uint32_t latAvg = testLatency(sz, tpFps);
        testFrameLoss(sz, RFC2544_TEST_SEC);
        uint32_t btb    = testBackToBack(sz);

        float mbps = (float)tpFps * (sz + 20) * 8 / 1e6f;
        Serial.printf("\r\nSummary [%u bytes]: throughput=%lu fps (%.2f Mbps), "
                      "latency_avg=%lu µs, back-to-back=%lu frames\r\n",
                      sz, tpFps, mbps, latAvg, btb);
        Serial.println("----------------------------------------");
    }

    Serial.println("\r\n=== RFC 2544 Suite Complete ===");
}

// =============================================================================
// printResult (static helper)
// =============================================================================
void RFC2544::printResult(const RFC2544Result &r)
{
    Serial.printf("FrameSize=%u  TP=%lu fps (%.2f Mbps)  "
                  "Latency min/avg/max=%lu/%lu/%lu µs  "
                  "Loss=%.4f%%  BackToBack=%lu\r\n",
                  r.frameSize, r.throughputFps, r.throughputMbps,
                  r.latencyUsMin, r.latencyUsAvg, r.latencyUsMax,
                  r.lossPercent, r.backToBack);
}

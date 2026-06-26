#pragma once

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// =============================================================================
// TeeStream — captures serial output so it can be viewed over the web UI.
//
// All writes are forwarded to the real Serial port AND, while a capture is
// active, appended to a ring buffer in PSRAM. The ring keeps the most recent
// output so long-running commands never show "truncated".
//
// Usage: include this header in a .cpp and add `#define Serial Out` AFTER all
// #include lines. Existing `Serial.print*` calls then tee transparently.
// The buffer is guarded by a mutex so the async web-server task can snapshot it
// while the main loop is writing.
// =============================================================================
class TeeStream : public Stream {
public:
    static constexpr size_t CAP = 32768;  // 32 KB ring in PSRAM

    // ---- Stream input: forward to the real Serial ----
    int available() override { return _webAbort ? 1 : ::Serial.available(); }
    int read() override      { if (_webAbort) { _webAbort = false; return '\x03'; } return ::Serial.read(); }
    int peek() override      { return _webAbort ? '\x03' : ::Serial.peek(); }
    void flush() override    { ::Serial.flush(); }

    // ---- Web abort: inject a fake byte so Serial.available() checks trigger ----
    void requestAbort()      { _webAbort = true; }
    bool abortRequested() const { return _webAbort; }

    // ---- Print output: tee to Serial + capture buffer ----
    size_t write(uint8_t c) override;
    size_t write(const uint8_t *buf, size_t size) override;
    using Print::write;

    // ---- Capture control (called by the web orchestration) ----
    void beginCapture();                 // clear buffer and start capturing
    void endCapture();                   // stop capturing
    bool capturing() const { return _capturing; }

    // Copy the current capture buffer into `out` (thread-safe). Safe to call
    // while a capture is in progress to stream partial output.
    void snapshot(String &out);

private:
    void _ensureMutex();
    void _ensureBuf();

    SemaphoreHandle_t _mtx = nullptr;
    char   *_buf       = nullptr;   // PSRAM-allocated ring buffer
    size_t  _head      = 0;         // next write position (wraps)
    size_t  _count     = 0;         // total bytes stored (max CAP)
    bool    _capturing = false;
    volatile bool _webAbort = false; // set by web UI abort button
};

// Global tee instance.
extern TeeStream Out;

#pragma once

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// =============================================================================
// TeeStream — captures serial output so it can be viewed over the web UI.
//
// All writes are forwarded to the real Serial port AND, while a capture is
// active, appended to an in-memory buffer. Stream input (available/read/peek)
// is forwarded straight to Serial so the CLI continues to work unchanged.
//
// Usage: include this header in a .cpp and add `#define Serial Out` AFTER all
// #include lines. Existing `Serial.print*` calls then tee transparently.
// The buffer is guarded by a mutex so the async web-server task can snapshot it
// while the main loop is writing.
// =============================================================================
class TeeStream : public Stream {
public:
    static constexpr size_t CAP = 8192;

    // ---- Stream input: forward to the real Serial ----
    int available() override { return ::Serial.available(); }
    int read() override      { return ::Serial.read(); }
    int peek() override      { return ::Serial.peek(); }
    void flush() override    { ::Serial.flush(); }

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

    SemaphoreHandle_t _mtx = nullptr;
    char    _buf[CAP];
    size_t  _len       = 0;
    bool    _capturing = false;
    bool    _overflow  = false;
};

// Global tee instance.
extern TeeStream Out;

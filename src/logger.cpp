#include "logger.h"
#include "pcap.h"
#include <SD.h>
#include <time.h>

// =============================================================================
// State
// =============================================================================
static File    _logFile;
static bool    _active = false;
static char    _logPath[64] = {0};
static bool    _needTimestamp = true;        // next write starts a new line
static uint32_t _lastFlush = 0;

// =============================================================================
// Timestamp helper
// =============================================================================
static void _writeTimestamp()
{
    struct tm tm;
    char ts[26];
    if (getLocalTime(&tm, 0)) {
        snprintf(ts, sizeof(ts), "[%04d-%02d-%02d %02d:%02d:%02d] ",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    } else {
        uint32_t ms = millis();
        snprintf(ts, sizeof(ts), "[%lu.%03lu] ", ms / 1000, ms % 1000);
    }
    _logFile.write((const uint8_t *)ts, strlen(ts));
}

// =============================================================================
// Public API
// =============================================================================
bool logStart(const char *name)
{
    if (_active) logStop();
    if (!pcapSdAvailable()) {
        ::Serial.println("[LOG] SD card not available.");
        return false;
    }

    // Ensure /logs directory exists
    if (!SD.exists("/logs")) SD.mkdir("/logs");

    if (name && name[0]) {
        snprintf(_logPath, sizeof(_logPath), "/logs/%s.log", name);
    } else {
        // Auto-name with timestamp or millis
        struct tm tm;
        if (getLocalTime(&tm, 0)) {
            snprintf(_logPath, sizeof(_logPath), "/logs/%04d%02d%02d_%02d%02d%02d.log",
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        } else {
            snprintf(_logPath, sizeof(_logPath), "/logs/log_%lu.log", millis() / 1000);
        }
    }

    _logFile = SD.open(_logPath, FILE_APPEND);
    if (!_logFile) {
        ::Serial.printf("[LOG] Failed to open %s\r\n", _logPath);
        _logPath[0] = '\0';
        return false;
    }

    _active = true;
    _needTimestamp = true;
    _lastFlush = millis();

    // Write header
    _writeTimestamp();
    const char *hdr = "=== Log started ===\n";
    _logFile.write((const uint8_t *)hdr, strlen(hdr));
    _logFile.flush();

    ::Serial.printf("[LOG] Logging to %s\r\n", _logPath);
    return true;
}

void logStop()
{
    if (!_active) return;
    // Write footer
    _writeTimestamp();
    const char *ftr = "=== Log stopped ===\n";
    _logFile.write((const uint8_t *)ftr, strlen(ftr));
    _logFile.flush();
    _logFile.close();
    ::Serial.printf("[LOG] Closed %s\r\n", _logPath);
    _active = false;
}

bool logIsActive() { return _active; }

const char *logCurrentFile()
{
    return _active ? _logPath : "";
}

void logWrite(const uint8_t *buf, size_t len)
{
    if (!_active || !_logFile) return;

    for (size_t i = 0; i < len; i++) {
        if (_needTimestamp) {
            _writeTimestamp();
            _needTimestamp = false;
        }
        _logFile.write(buf[i]);
        if (buf[i] == '\n') {
            _needTimestamp = true;
        }
    }

    // Auto-flush every 2 seconds to limit SD wear
    if (millis() - _lastFlush > 2000) {
        _logFile.flush();
        _lastFlush = millis();
    }
}

void logFlush()
{
    if (_active && _logFile) _logFile.flush();
}

uint32_t logSize()
{
    if (_active && _logFile) return _logFile.size();
    return 0;
}

void logList()
{
    if (!pcapSdAvailable()) {
        ::Serial.println("[LOG] SD card not available.");
        return;
    }
    if (!SD.exists("/logs")) {
        ::Serial.println("  (no logs directory)");
        return;
    }
    File dir = SD.open("/logs");
    if (!dir || !dir.isDirectory()) {
        ::Serial.println("  (cannot open /logs)");
        return;
    }
    ::Serial.println("  Log files on SD:");
    uint32_t total = 0;
    int count = 0;
    File f = dir.openNextFile();
    while (f) {
        if (!f.isDirectory()) {
            ::Serial.printf("    %-30s %8u bytes\r\n", f.name(), (uint32_t)f.size());
            total += f.size();
            count++;
        }
        f = dir.openNextFile();
    }
    dir.close();
    if (count == 0) {
        ::Serial.println("    (empty)");
    } else {
        ::Serial.printf("  %d file(s), %u bytes total\r\n", count, total);
    }
}

bool logDelete(const char *filename)
{
    if (!pcapSdAvailable()) return false;
    char path[80];
    if (filename[0] == '/') {
        strlcpy(path, filename, sizeof(path));
    } else {
        snprintf(path, sizeof(path), "/logs/%s", filename);
    }
    return SD.remove(path);
}

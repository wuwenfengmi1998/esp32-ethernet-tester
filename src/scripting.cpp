#include "scripting.h"
#include "../include/config.h"
#include "logger.h"
#include "pcap.h"
#include "weblog.h"
#include <SD.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <time.h>

#define Serial Out

// =============================================================================
// Script engine state
// =============================================================================
static ScriptCmdFn _cmdFn = nullptr;
static bool        _scriptRunning = false;
static bool        _scriptAbort   = false;
static char        _scriptPath[64] = {0};

// Simple variable store (8 vars, 32 char name, 64 char value)
#define SCRIPT_MAX_VARS 8
static struct { char name[32]; char value[64]; } _vars[SCRIPT_MAX_VARS];
static int _varCount = 0;

void scriptSetCommandHandler(ScriptCmdFn fn) { _cmdFn = fn; }

// =============================================================================
// Variable helpers
// =============================================================================
static const char *_getVar(const char *name)
{
    for (int i = 0; i < _varCount; i++) {
        if (strcasecmp(_vars[i].name, name) == 0) return _vars[i].value;
    }
    return nullptr;
}

static void _setVar(const char *name, const char *value)
{
    for (int i = 0; i < _varCount; i++) {
        if (strcasecmp(_vars[i].name, name) == 0) {
            strlcpy(_vars[i].value, value, sizeof(_vars[i].value));
            return;
        }
    }
    if (_varCount < SCRIPT_MAX_VARS) {
        strlcpy(_vars[_varCount].name, name, sizeof(_vars[_varCount].name));
        strlcpy(_vars[_varCount].value, value, sizeof(_vars[_varCount].value));
        _varCount++;
    }
}

// Expand $VAR references in a line
static String _expandVars(const char *line)
{
    String result;
    result.reserve(strlen(line) + 32);
    const char *p = line;
    while (*p) {
        if (*p == '$') {
            p++;
            char varName[32];
            int vi = 0;
            while (*p && (isalnum(*p) || *p == '_') && vi < 31) {
                varName[vi++] = *p++;
            }
            varName[vi] = '\0';
            const char *val = _getVar(varName);
            if (val) result += val;
            else { result += '$'; result += varName; }
        } else {
            result += *p++;
        }
    }
    return result;
}

// =============================================================================
// Time / day helpers
// =============================================================================
static bool _timeInRange(const char *spec)
{
    // Format: HH:MM-HH:MM
    int sh, sm, eh, em;
    if (sscanf(spec, "%d:%d-%d:%d", &sh, &sm, &eh, &em) != 4) return false;
    struct tm tm;
    if (!getLocalTime(&tm, 0)) return false;
    int now = tm.tm_hour * 60 + tm.tm_min;
    int start = sh * 60 + sm;
    int end   = eh * 60 + em;
    if (start <= end) return (now >= start && now < end);
    else              return (now >= start || now < end);  // wraps midnight
}

static bool _dayMatches(const char *spec)
{
    struct tm tm;
    if (!getLocalTime(&tm, 0)) return false;
    static const char *dayNames[] = {"SUN","MON","TUE","WED","THU","FRI","SAT"};
    const char *today = dayNames[tm.tm_wday];
    // spec is comma-separated: "MON,TUE,WED"
    char buf[64];
    strlcpy(buf, spec, sizeof(buf));
    char *tok = strtok(buf, ",");
    while (tok) {
        while (*tok == ' ') tok++;
        if (strcasecmp(tok, today) == 0) return true;
        tok = strtok(nullptr, ",");
    }
    return false;
}

// =============================================================================
// Script execution core
// =============================================================================
static void _execLine(const char *raw)
{
    // Skip whitespace and comments
    while (*raw == ' ' || *raw == '\t') raw++;
    if (*raw == '\0' || *raw == '#') return;

    // Expand variables
    String line = _expandVars(raw);
    const char *l = line.c_str();

    // Parse directive
    if (strncasecmp(l, "delay ", 6) == 0) {
        uint32_t ms = strtoul(l + 6, nullptr, 10);
        if (ms > 0 && ms <= 300000) {
            Serial.printf("[SCRIPT] delay %lu ms\r\n", ms);
            uint32_t start = millis();
            while (millis() - start < ms && !_scriptAbort) delay(10);
        }
    }
    else if (strncasecmp(l, "wait ", 5) == 0) {
        uint32_t sec = strtoul(l + 5, nullptr, 10);
        if (sec > 0 && sec <= 3600) {
            Serial.printf("[SCRIPT] wait %lu s\r\n", sec);
            uint32_t start = millis();
            while (millis() - start < sec * 1000UL && !_scriptAbort) delay(10);
        }
    }
    else if (strncasecmp(l, "echo ", 5) == 0) {
        Serial.printf("%s\r\n", l + 5);
    }
    else if (strncasecmp(l, "log ", 4) == 0) {
        const char *arg = l + 4;
        while (*arg == ' ') arg++;
        if (strncasecmp(arg, "start", 5) == 0) {
            const char *name = arg + 5;
            while (*name == ' ') name++;
            logStart(name[0] ? name : nullptr);
        } else if (strncasecmp(arg, "stop", 4) == 0) {
            logStop();
        }
    }
    else if (strncasecmp(l, "if_time ", 8) == 0) {
        if (!_timeInRange(l + 8)) {
            Serial.printf("[SCRIPT] if_time %s -- outside window, stopping.\r\n", l + 8);
            _scriptAbort = true;
        }
    }
    else if (strncasecmp(l, "if_day ", 7) == 0) {
        if (!_dayMatches(l + 7)) {
            Serial.printf("[SCRIPT] if_day %s -- not today, stopping.\r\n", l + 7);
            _scriptAbort = true;
        }
    }
    else if (strncasecmp(l, "if_link ", 8) == 0) {
        // Requires checking link state - delegate to CLI status
        const char *want = l + 8;
        while (*want == ' ') want++;
        // We use the _cmdFn to run "status" and check output, or directly
        // provide a simple check. For now, just print.
        Serial.printf("[SCRIPT] if_link %s -- (link check not yet wired)\r\n", want);
    }
    else if (strncasecmp(l, "set ", 4) == 0) {
        char varName[32], varVal[64];
        if (sscanf(l + 4, "%31s %63[^\n]", varName, varVal) >= 2) {
            _setVar(varName, varVal);
            Serial.printf("[SCRIPT] %s = %s\r\n", varName, varVal);
        }
    }
    else if (strncasecmp(l, "upload ", 7) == 0) {
        // Parse: upload log <name> <url>  OR  upload pcap <url>
        char type[16] = {0}, arg1[128] = {0}, arg2[256] = {0};
        int n = sscanf(l + 7, "%15s %127s %255s", type, arg1, arg2);
        if (n >= 2 && strcasecmp(type, "pcap") == 0) {
            // upload pcap <url>
            const char *path = pcapPath();
            if (path && pcapSize() > 0) {
                uploadFileHttp(path, arg1);
            } else {
                Serial.println("[SCRIPT] No pcap file to upload.");
            }
        } else if (n >= 3 && strcasecmp(type, "log") == 0) {
            // upload log <name> <url>
            char logPath[80];
            snprintf(logPath, sizeof(logPath), "/logs/%s", arg1);
            // If arg1 doesn't have .log extension, add it
            if (!strstr(arg1, ".log")) strlcat(logPath, ".log", sizeof(logPath));
            uploadFileHttp(logPath, arg2);
        }
    }
    else if (strncasecmp(l, "rm ", 3) == 0 || strncasecmp(l, "delete ", 7) == 0) {
        const char *path = l + (l[0] == 'r' ? 3 : 7);
        while (*path == ' ') path++;
        if (pcapSdAvailable() && SD.remove(path))
            Serial.printf("[SCRIPT] Deleted: %s\r\n", path);
        else
            Serial.printf("[SCRIPT] Cannot delete: %s\r\n", path);
    }
    else if (strncasecmp(l, "rename ", 7) == 0) {
        char src[80] = {0}, dst[80] = {0};
        if (sscanf(l + 7, "%79s %79s", src, dst) == 2 && pcapSdAvailable()) {
            if (SD.rename(src, dst))
                Serial.printf("[SCRIPT] Renamed: %s -> %s\r\n", src, dst);
            else
                Serial.printf("[SCRIPT] Rename failed: %s -> %s\r\n", src, dst);
        }
    }
    else if (strncasecmp(l, "mkdir ", 6) == 0) {
        const char *path = l + 6;
        while (*path == ' ') path++;
        if (pcapSdAvailable()) SD.mkdir(path);
    }
    else if (strncasecmp(l, "write_file ", 11) == 0) {
        // write_file <path> <text>  -- append text to a file
        char path[80] = {0};
        const char *p = l + 11;
        int pi = 0;
        while (*p && *p != ' ' && pi < 79) path[pi++] = *p++;
        path[pi] = '\0';
        while (*p == ' ') p++;
        if (path[0] && pcapSdAvailable()) {
            File f = SD.open(path, FILE_APPEND);
            if (f) { f.println(p); f.close(); }
        }
    }
    else if (strcasecmp(l, "abort") == 0) {
        Serial.println("[SCRIPT] abort");
        _scriptAbort = true;
    }
    else {
        // Treat as a CLI command
        if (_cmdFn) {
            Serial.printf("[SCRIPT] > %s\r\n", l);
            _cmdFn(String(l));
        }
    }
}

// Run lines from a file
static void _runFromFile(File &f)
{
    char buf[CLI_BUF_SIZE];
    // Simple repeat stack (one level deep)
    int repeatCount = 0;
    long repeatFilePos = 0;
    int repeatRemaining = 0;

    while (f.available() && !_scriptAbort) {
        // Read one line
        int len = 0;
        while (f.available() && len < (int)sizeof(buf) - 1) {
            char c = f.read();
            if (c == '\n') break;
            if (c != '\r') buf[len++] = c;
        }
        buf[len] = '\0';

        // Handle repeat/end_repeat
        const char *trimmed = buf;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        if (strncasecmp(trimmed, "repeat ", 7) == 0) {
            repeatCount = atoi(trimmed + 7);
            if (repeatCount < 1) repeatCount = 1;
            if (repeatCount > 1000) repeatCount = 1000;
            repeatRemaining = repeatCount;
            repeatFilePos = f.position();
            continue;
        }
        if (strcasecmp(trimmed, "end_repeat") == 0) {
            if (repeatRemaining > 1) {
                repeatRemaining--;
                f.seek(repeatFilePos);
            } else {
                repeatCount = 0;
                repeatRemaining = 0;
            }
            continue;
        }

        _execLine(buf);
        yield();  // Let RTOS tasks run
    }
}

bool scriptRun(const char *path, const char *logName)
{
    if (_scriptRunning) {
        Serial.println("[SCRIPT] A script is already running.");
        return false;
    }
    if (!pcapSdAvailable()) {
        Serial.println("[SCRIPT] SD card not available.");
        return false;
    }

    File f = SD.open(path, FILE_READ);
    if (!f) {
        Serial.printf("[SCRIPT] Cannot open %s\r\n", path);
        return false;
    }

    strlcpy(_scriptPath, path, sizeof(_scriptPath));
    _scriptRunning = true;
    _scriptAbort = false;
    _varCount = 0;

    if (logName) logStart(logName);

    Serial.printf("[SCRIPT] Running %s (%u bytes)\r\n", path, (uint32_t)f.size());

    _runFromFile(f);
    f.close();

    if (logName) logStop();

    _scriptRunning = false;
    _scriptPath[0] = '\0';
    Serial.printf("[SCRIPT] Finished%s.\r\n", _scriptAbort ? " (aborted)" : "");
    _scriptAbort = false;
    return true;
}

bool scriptRunInline(const char *scriptText, const char *logName)
{
    if (_scriptRunning) {
        Serial.println("[SCRIPT] A script is already running.");
        return false;
    }

    _scriptRunning = true;
    _scriptAbort = false;
    _varCount = 0;
    strlcpy(_scriptPath, "(inline)", sizeof(_scriptPath));

    if (logName) logStart(logName);

    // Parse line by line from the text buffer
    const char *p = scriptText;
    char buf[CLI_BUF_SIZE];
    while (*p && !_scriptAbort) {
        int len = 0;
        while (*p && *p != '\n' && len < (int)sizeof(buf) - 1) {
            if (*p != '\r') buf[len++] = *p;
            p++;
        }
        buf[len] = '\0';
        if (*p == '\n') p++;
        _execLine(buf);
        yield();
    }

    if (logName) logStop();

    _scriptRunning = false;
    _scriptPath[0] = '\0';
    Serial.printf("[SCRIPT] Inline script finished%s.\r\n", _scriptAbort ? " (aborted)" : "");
    _scriptAbort = false;
    return true;
}

void scriptAbort()
{
    if (_scriptRunning) _scriptAbort = true;
}

bool scriptIsRunning() { return _scriptRunning; }

const char *scriptCurrentFile()
{
    return _scriptRunning ? _scriptPath : "";
}

// =============================================================================
// Cron scheduler
// =============================================================================
#define CRON_MAX_ENTRIES 16

struct CronEntry {
    char spec[20];      // "*/5 * * * *"
    char cmd[128];      // CLI command or script path
    bool valid;
};

static CronEntry _cron[CRON_MAX_ENTRIES];
static int _cronCount = 0;
static uint32_t _cronLastCheck = 0;
static int _cronLastMinute = -1;

// Parse cron field: supports *, */N, N, N-M
static bool _cronFieldMatch(const char *field, int value, int maxVal)
{
    if (field[0] == '*') {
        if (field[1] == '/') {
            int step = atoi(field + 2);
            return step > 0 && (value % step) == 0;
        }
        return true;
    }
    // Range: N-M
    const char *dash = strchr(field, '-');
    if (dash) {
        int lo = atoi(field);
        int hi = atoi(dash + 1);
        return value >= lo && value <= hi;
    }
    // Comma-separated values
    char buf[20];
    strlcpy(buf, field, sizeof(buf));
    char *tok = strtok(buf, ",");
    while (tok) {
        if (atoi(tok) == value) return true;
        tok = strtok(nullptr, ",");
    }
    return false;
}

static bool _cronMatches(const CronEntry &e, const struct tm &tm)
{
    char spec[20];
    strlcpy(spec, e.spec, sizeof(spec));

    char *fields[5];
    int fi = 0;
    char *tok = strtok(spec, " \t");
    while (tok && fi < 5) {
        fields[fi++] = tok;
        tok = strtok(nullptr, " \t");
    }
    if (fi != 5) return false;

    return _cronFieldMatch(fields[0], tm.tm_min, 59) &&
           _cronFieldMatch(fields[1], tm.tm_hour, 23) &&
           _cronFieldMatch(fields[2], tm.tm_mday, 31) &&
           _cronFieldMatch(fields[3], tm.tm_mon + 1, 12) &&
           _cronFieldMatch(fields[4], tm.tm_wday, 6);   // 0=Sun
}

void cronInit()
{
    _cronCount = 0;
    memset(_cron, 0, sizeof(_cron));

    if (!pcapSdAvailable()) return;
    if (!SD.exists("/cron.txt")) return;

    File f = SD.open("/cron.txt", FILE_READ);
    if (!f) return;

    char buf[192];
    while (f.available() && _cronCount < CRON_MAX_ENTRIES) {
        int len = 0;
        while (f.available() && len < (int)sizeof(buf) - 1) {
            char c = f.read();
            if (c == '\n') break;
            if (c != '\r') buf[len++] = c;
        }
        buf[len] = '\0';

        // Skip empty lines and comments
        const char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        // Parse: 5 fields for the time spec, then the rest is the command
        CronEntry &e = _cron[_cronCount];
        char f1[10], f2[10], f3[10], f4[10], f5[10];
        char cmd[128];
        int n = sscanf(p, "%9s %9s %9s %9s %9s %127[^\n]",
                       f1, f2, f3, f4, f5, cmd);
        if (n == 6) {
            snprintf(e.spec, sizeof(e.spec), "%s %s %s %s %s", f1, f2, f3, f4, f5);
            strlcpy(e.cmd, cmd, sizeof(e.cmd));
            e.valid = true;
            _cronCount++;
        }
    }
    f.close();

    if (_cronCount > 0) {
        Serial.printf("[CRON] Loaded %d entries from /cron.txt\r\n", _cronCount);
    }
}

void cronTick()
{
    if (_cronCount == 0) return;

    // Only check once per minute
    uint32_t now = millis();
    if (now - _cronLastCheck < 15000) return;  // check every 15s for safety
    _cronLastCheck = now;

    struct tm tm;
    if (!getLocalTime(&tm, 0)) return;

    int curMinute = tm.tm_hour * 60 + tm.tm_min;
    if (curMinute == _cronLastMinute) return;
    _cronLastMinute = curMinute;

    for (int i = 0; i < _cronCount; i++) {
        if (!_cron[i].valid) continue;
        if (!_cronMatches(_cron[i], tm)) continue;

        Serial.printf("[CRON] Trigger: %s\r\n", _cron[i].cmd);

        // If it starts with /, treat as a script path
        if (_cron[i].cmd[0] == '/') {
            scriptRun(_cron[i].cmd);
        } else if (_cmdFn) {
            _cmdFn(String(_cron[i].cmd));
        }
    }
}

void cronReload()
{
    _cronCount = 0;
    _cronLastMinute = -1;
    cronInit();
}

void cronList()
{
    if (_cronCount == 0) {
        Serial.println("  No cron entries loaded.");
        Serial.println("  Add entries to /cron.txt on SD card.");
        return;
    }
    Serial.println("  # | Schedule          | Command");
    Serial.println("  --+-------------------+--------------------------------");
    for (int i = 0; i < _cronCount; i++) {
        if (!_cron[i].valid) continue;
        Serial.printf("  %d | %-17s | %s\r\n", i, _cron[i].spec, _cron[i].cmd);
    }
}

bool cronAdd(const char *entry)
{
    if (!pcapSdAvailable()) {
        Serial.println("[CRON] SD card not available.");
        return false;
    }
    File f = SD.open("/cron.txt", FILE_APPEND);
    if (!f) return false;
    f.println(entry);
    f.close();
    cronReload();
    return true;
}

bool cronRemove(int index)
{
    if (index < 0 || index >= _cronCount) return false;
    if (!pcapSdAvailable()) return false;

    // Rewrite the file without the specified entry
    File f = SD.open("/cron.txt", FILE_READ);
    if (!f) return false;

    String content;
    char buf[192];
    int entryIdx = 0;
    while (f.available()) {
        int len = 0;
        while (f.available() && len < (int)sizeof(buf) - 1) {
            char c = f.read();
            if (c == '\n') break;
            if (c != '\r') buf[len++] = c;
        }
        buf[len] = '\0';

        const char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        bool isEntry = (*p && *p != '#');

        if (isEntry) {
            if (entryIdx != index) {
                content += buf;
                content += "\n";
            }
            entryIdx++;
        } else {
            content += buf;
            content += "\n";
        }
    }
    f.close();

    // Rewrite
    f = SD.open("/cron.txt", FILE_WRITE);
    if (!f) return false;
    f.print(content);
    f.close();

    cronReload();
    return true;
}

bool cronClear()
{
    if (!pcapSdAvailable()) return false;
    SD.remove("/cron.txt");
    _cronCount = 0;
    return true;
}

// =============================================================================
// File upload -- HTTP POST (multipart/form-data)
// =============================================================================
bool uploadFileHttp(const char *sdPath, const char *url)
{
    return uploadFileHttpAuth(sdPath, url, nullptr, nullptr);
}

bool uploadFileHttpAuth(const char *sdPath, const char *url,
                        const char *user, const char *pass)
{
    if (!pcapSdAvailable()) {
        Serial.println("[UPLOAD] SD card not available.");
        return false;
    }
    if (!WiFi.isConnected()) {
        Serial.println("[UPLOAD] Wi-Fi not connected.");
        return false;
    }

    File f = SD.open(sdPath, FILE_READ);
    if (!f) {
        Serial.printf("[UPLOAD] Cannot open %s\r\n", sdPath);
        return false;
    }

    uint32_t fileSize = f.size();
    Serial.printf("[UPLOAD] Uploading %s (%u bytes) to %s\r\n", sdPath, fileSize, url);

    HTTPClient http;
    http.begin(url);
    http.setTimeout(30000);

    if (user && user[0] && pass) {
        http.setAuthorization(user, pass);
    }

    // Extract filename from path
    const char *filename = strrchr(sdPath, '/');
    filename = filename ? filename + 1 : sdPath;

    // Build multipart boundary
    String boundary = "----ESP32Upload" + String(millis());

    // Multipart header
    String head = "--" + boundary + "\r\n";
    head += "Content-Disposition: form-data; name=\"file\"; filename=\"";
    head += filename;
    head += "\"\r\nContent-Type: application/octet-stream\r\n\r\n";

    // Multipart footer
    String tail = "\r\n--" + boundary + "--\r\n";

    uint32_t totalLen = head.length() + fileSize + tail.length();
    http.addHeader("Content-Type", "multipart/form-data; boundary=" + boundary);
    http.addHeader("Content-Length", String(totalLen));

    // Stream upload using WiFiClient
    WiFiClient *stream = http.getStreamPtr();
    if (!stream) {
        // Fall back: read entire file into memory (limited to 64KB)
        if (fileSize > 65536) {
            Serial.println("[UPLOAD] File too large for memory upload.");
            f.close();
            http.end();
            return false;
        }
        uint8_t *buf = (uint8_t *)malloc(fileSize);
        if (!buf) {
            Serial.println("[UPLOAD] Out of memory.");
            f.close();
            http.end();
            return false;
        }
        f.read(buf, fileSize);
        f.close();

        // Build complete body
        String body = head;
        body.reserve(totalLen);
        for (uint32_t i = 0; i < fileSize; i++) body += (char)buf[i];
        body += tail;
        free(buf);

        int code = http.POST(body);
        Serial.printf("[UPLOAD] HTTP %d\r\n", code);
        if (code > 0) {
            String resp = http.getString();
            if (resp.length() > 0 && resp.length() < 256)
                Serial.printf("[UPLOAD] Response: %s\r\n", resp.c_str());
        }
        http.end();
        return code >= 200 && code < 300;
    }

    // Streaming upload
    http.addHeader("Content-Length", String(totalLen));

    // We need to use sendRequest with a stream
    // Use POST with stream approach
    f.close();

    // Reopen and use the simple POST approach with a buffer
    f = SD.open(sdPath, FILE_READ);
    if (!f) { http.end(); return false; }

    // Allocate chunked buffer
    const size_t chunkSize = 4096;
    uint8_t *chunk = (uint8_t *)malloc(chunkSize);
    if (!chunk) {
        Serial.println("[UPLOAD] Out of memory for chunk buffer.");
        f.close();
        http.end();
        return false;
    }

    // Manual POST with chunked reading
    // Use sendRequest which accepts a Stream
    int code = http.sendRequest("POST", &f, fileSize);

    free(chunk);
    f.close();

    Serial.printf("[UPLOAD] HTTP %d\r\n", code);
    if (code > 0) {
        String resp = http.getString();
        if (resp.length() > 0 && resp.length() < 256)
            Serial.printf("[UPLOAD] Response: %s\r\n", resp.c_str());
    }
    http.end();
    return code >= 200 && code < 300;
}

// =============================================================================
// NVS storage for default upload destination
// =============================================================================
#define UPLOAD_NVS_NS "upload"

void uploadSetDefault(const char *url, const char *user, const char *pass)
{
    Preferences prefs;
    prefs.begin(UPLOAD_NVS_NS, false);
    prefs.putString("url", url ? url : "");
    prefs.putString("user", user ? user : "");
    prefs.putString("pass", pass ? pass : "");
    prefs.end();
    Serial.printf("[UPLOAD] Default destination: %s\r\n", url ? url : "(cleared)");
}

void uploadGetDefault(char *url, size_t urlLen,
                      char *user, size_t userLen,
                      char *pass, size_t passLen)
{
    Preferences prefs;
    prefs.begin(UPLOAD_NVS_NS, true);
    String u = prefs.getString("url", "");
    String un = prefs.getString("user", "");
    String pw = prefs.getString("pass", "");
    prefs.end();
    if (url) strlcpy(url, u.c_str(), urlLen);
    if (user) strlcpy(user, un.c_str(), userLen);
    if (pass) strlcpy(pass, pw.c_str(), passLen);
}

#include "pcap.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <LittleFS.h>
#include <SD.h>
#include <SPI.h>
#include <string.h>
#include "ff.h"

#define Serial Out

// =============================================================================
// SD card state
// =============================================================================
static bool _sdReady = false;
static SPIClass _sdSpi(HSPI);   // Use HSPI for SD (separate from W5500 on FSPI)

bool pcapSdInit()
{
    _sdSpi.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
    // Try normal mount first
    if (SD.begin(PIN_SD_CS, _sdSpi, 4000000UL, "/sd", 5, false)) {
        _sdReady = true;
        uint64_t totalBytes = SD.totalBytes();
        uint64_t usedBytes  = SD.usedBytes();
        Serial.printf("[SD] TF card mounted: %llu MB total, %llu MB used.\r\n",
                      totalBytes / (1024 * 1024), usedBytes / (1024 * 1024));
        return true;
    }
    // If normal mount fails, try with format_if_empty (handles blank/corrupt cards)
    Serial.println("[SD] Normal mount failed, trying with auto-format...");
    if (SD.begin(PIN_SD_CS, _sdSpi, 4000000UL, "/sd", 5, true)) {
        _sdReady = true;
        uint64_t totalBytes = SD.totalBytes();
        uint64_t usedBytes  = SD.usedBytes();
        Serial.printf("[SD] TF card formatted and mounted: %llu MB total, %llu MB used.\r\n",
                      totalBytes / (1024 * 1024), usedBytes / (1024 * 1024));
        return true;
    }
    _sdReady = false;
    Serial.println("[SD] No TF card detected or card unreadable. PCAP will use internal flash (LittleFS).");
    Serial.println("[SD] If a card is inserted, try: sd format");
    return false;
}

bool pcapSdFormat()
{
    Serial.println("[SD] Formatting TF card (FAT32)...");
    // End any existing mount
    if (_sdReady) {
        SD.end();
        _sdReady = false;
    }
    // Re-init SPI and attempt mount with format
    _sdSpi.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);
    if (!SD.begin(PIN_SD_CS, _sdSpi, 4000000UL, "/sd", 5, true)) {
        Serial.println("[SD] Cannot communicate with card. Check card is inserted properly.");
        return false;
    }
    // Card is mounted (possibly auto-formatted). Force a full format via FatFS.
    SD.end();
    // Remount to get raw access, then format
    if (!SD.begin(PIN_SD_CS, _sdSpi, 4000000UL, "/sd", 5, false)) {
        // Mount failed again - try format_if_empty
        if (!SD.begin(PIN_SD_CS, _sdSpi, 4000000UL, "/sd", 5, true)) {
            Serial.println("[SD] Format failed: cannot access card.");
            return false;
        }
    }
    // Use FatFS f_mkfs to force-format the mounted volume
    uint8_t *workBuf = (uint8_t *)malloc(4096);
    if (!workBuf) {
        Serial.println("[SD] Format failed: out of memory.");
        return false;
    }
    MKFS_PARM opt = {};
    opt.fmt = FM_FAT32;
    FRESULT res = f_mkfs("/sd", &opt, workBuf, 4096);
    free(workBuf);
    if (res != FR_OK) {
        Serial.printf("[SD] FAT32 format failed (error %d). Trying FM_ANY...\r\n", res);
        workBuf = (uint8_t *)malloc(4096);
        if (workBuf) {
            opt.fmt = FM_ANY;
            res = f_mkfs("/sd", &opt, workBuf, 4096);
            free(workBuf);
        }
        if (res != FR_OK) {
            Serial.printf("[SD] Format failed (error %d). Card may be defective.\r\n", res);
            return false;
        }
    }
    // Remount clean
    SD.end();
    if (SD.begin(PIN_SD_CS, _sdSpi, 4000000UL, "/sd", 5, false)) {
        _sdReady = true;
        Serial.printf("[SD] Format complete: %llu MB available.\r\n",
                      SD.totalBytes() / (1024 * 1024));
        return true;
    }
    Serial.println("[SD] Format succeeded but remount failed.");
    return false;
}

bool pcapSdAvailable()
{
    return _sdReady;
}

// =============================================================================
// Internal helpers
// =============================================================================

// Return the filesystem to use for captures.
static fs::FS &activeFs()
{
    return _sdReady ? (fs::FS &)SD : (fs::FS &)LittleFS;
}

static const char *activePath()
{
    return _sdReady ? PCAP_PATH_SD : PCAP_PATH_FS;
}

fs::FS *pcapFs()
{
    const char *p = activePath();
    fs::FS &f = activeFs();
    if (!f.exists(p)) return nullptr;
    return &f;
}

const char *pcapPath()
{
    return activePath();
}

// PCAP little-endian writers.
static inline void le32(uint8_t *p, uint32_t v)
{
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static inline void le16(uint8_t *p, uint16_t v)
{
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
}

// =============================================================================
// pcapCapture
// =============================================================================
uint32_t pcapCapture(W5500Raw &eth, uint32_t seconds, uint32_t maxFrames)
{
    const char *path = activePath();
    fs::FS &fs = activeFs();

    File fp = fs.open(path, "w");
    if (!fp) {
        Serial.printf("PCAP: cannot open %s on %s (full?).\r\n", path,
                      _sdReady ? "SD card" : "LittleFS");
        return 0;
    }

    // Global header (24 bytes), network type 1 = Ethernet.
    uint8_t gh[24];
    le32(gh + 0, 0xA1B2C3D4UL);    // magic
    le16(gh + 4, 2); le16(gh + 6, 4);   // version 2.4
    le32(gh + 8, 0);               // thiszone
    le32(gh + 12, 0);              // sigfigs
    le32(gh + 16, ETH_MAX_LEN);    // snaplen
    le32(gh + 20, 1);              // LINKTYPE_ETHERNET
    fp.write(gh, 24);

    Serial.printf("\r\nCapturing to %s (%s)", path, _sdReady ? "SD card" : "LittleFS");
    if (seconds)   Serial.printf(" for %lu s", (unsigned long)seconds);
    if (maxFrames) Serial.printf(", max %lu frames", (unsigned long)maxFrames);
    Serial.println(" (any key stops)...");

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = seconds ? (millis() + seconds * 1000UL) : 0;
    uint32_t n = 0, bytes = 24;
    uint32_t t0 = millis();

    while (true) {
        if (deadline && (int32_t)(deadline - millis()) <= 0) break;
        if (maxFrames && n >= maxFrames) break;
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len >= 14) {
            uint32_t ms = millis() - t0;
            uint8_t rh[16];
            le32(rh + 0, ms / 1000);
            le32(rh + 4, (ms % 1000) * 1000);   // usec
            le32(rh + 8, len);                  // incl_len
            le32(rh + 12, len);                 // orig_len
            fp.write(rh, 16);
            fp.write(buf, len);
            bytes += 16 + len;
            n++;
            if ((n & 0x3F) == 0) Serial.printf("  %lu frames (%lu bytes)...\r\n",
                                               (unsigned long)n, (unsigned long)bytes);
        } else {
            delay(1);
        }
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
    }
    fp.close();
    Serial.printf("Capture done: %lu frame(s), %lu bytes saved to %s (%s).\r\n",
                  (unsigned long)n, (unsigned long)bytes, path,
                  _sdReady ? "SD card" : "LittleFS");
    if (!_sdReady)
        Serial.println("Tip: insert a TF card for larger captures.");
    Serial.println("Download from the web UI (PCAP card) and open in Wireshark.");
    return n;
}

// =============================================================================
// pcapSize / pcapDelete
// =============================================================================
uint32_t pcapSize()
{
    const char *path = activePath();
    fs::FS &fs = activeFs();
    if (!fs.exists(path)) return 0;
    File fp = fs.open(path, "r");
    if (!fp) return 0;
    uint32_t s = fp.size();
    fp.close();
    return s;
}

void pcapDelete()
{
    // Try both locations
    if (_sdReady && SD.exists(PCAP_PATH_SD)) SD.remove(PCAP_PATH_SD);
    if (LittleFS.exists(PCAP_PATH_FS)) LittleFS.remove(PCAP_PATH_FS);
}

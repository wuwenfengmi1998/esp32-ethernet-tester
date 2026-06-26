#include "pcap.h"
#include "pcap_filter.h"
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
    if (pcapFilterActive()) Serial.print(" [filter active]");
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
            if (!pcapFilterMatch(buf, len)) continue;  // filter mismatch
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

// =============================================================================
// pcapCaptureRing -- circular-buffer capture
//
// Uses a raw ring file on SD (required for ring mode). The ring file stores
// back-to-back: [4-byte recLen][16-byte pcap record hdr][frame data].
// When the write position reaches maxBytes, it wraps to 0.
// On stop we reconstruct a proper PCAP from the ring.
// =============================================================================
#define RING_TMP_PATH  "/capture_ring.tmp"
#define RING_REC_OVERHEAD  (4 + 16)  // recLen(4) + pcap record header(16)

uint32_t pcapCaptureRing(W5500Raw &eth, uint32_t seconds, uint64_t maxBytes)
{
    if (!_sdReady) {
        Serial.println("[pcap] Ring capture requires an SD card.");
        return 0;
    }

    // Determine ring size
    if (maxBytes == 0) {
        uint64_t freeBytes = SD.totalBytes() - SD.usedBytes();
        maxBytes = (freeBytes * 90ULL) / 100ULL;
        if (maxBytes < 4096) {
            Serial.println("[pcap] SD card too full for ring capture.");
            return 0;
        }
    }

    // Remove any previous temp file
    if (SD.exists(RING_TMP_PATH)) SD.remove(RING_TMP_PATH);

    // Pre-allocate by creating the file
    File ring = SD.open(RING_TMP_PATH, "w");
    if (!ring) {
        Serial.println("[pcap] Cannot create ring file on SD.");
        return 0;
    }
    ring.close();

    // Open for random-access writing
    ring = SD.open(RING_TMP_PATH, "w");
    if (!ring) {
        Serial.println("[pcap] Cannot open ring file.");
        return 0;
    }

    Serial.printf("\r\n[pcap] Ring capture: %.1f MB max",
                  (double)maxBytes / (1024.0 * 1024.0));
    if (seconds) Serial.printf(", %lu s", (unsigned long)seconds);
    if (pcapFilterActive()) Serial.print(" [filter active]");
    Serial.println(" (any key stops)...");

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = seconds ? (millis() + seconds * 1000UL) : 0;
    uint64_t writePos = 0;
    uint32_t totalFrames = 0;
    bool wrapped = false;
    uint64_t wrapPoint = 0;     // where the oldest data starts after wrapping
    uint32_t t0 = millis();

    while (true) {
        if (deadline && (int32_t)(deadline - millis()) <= 0) break;
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }

        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len < 14) { delay(1); continue; }
        if (!pcapFilterMatch(buf, len)) continue;  // filter mismatch

        uint32_t recSize = RING_REC_OVERHEAD + len;

        // Check if this record would push us past the limit
        if (writePos + recSize > maxBytes) {
            // Wrap around
            wrapped = true;
            writePos = 0;
        }

        // If we've wrapped, the data after writePos+recSize may contain old
        // records that are now being overwritten. Track where valid data starts.
        if (wrapped) {
            wrapPoint = writePos + recSize;
            if (wrapPoint >= maxBytes) wrapPoint = 0;
        }

        // Seek and write the record
        ring.seek(writePos);

        // Record format: [recLen:4][ts_sec:4][ts_usec:4][incl_len:4][orig_len:4][frame]
        uint32_t ms = millis() - t0;
        uint8_t hdr[RING_REC_OVERHEAD];
        le32(hdr + 0, recSize);            // total record size (for skipping)
        le32(hdr + 4, ms / 1000);          // timestamp seconds
        le32(hdr + 8, (ms % 1000) * 1000); // timestamp microseconds
        le32(hdr + 12, len);               // incl_len
        le32(hdr + 16, len);               // orig_len
        ring.write(hdr, RING_REC_OVERHEAD);
        ring.write(buf, len);

        writePos += recSize;
        totalFrames++;

        if ((totalFrames & 0xFF) == 0)
            Serial.printf("  %lu frames, pos %llu/%llu%s\r\n",
                          (unsigned long)totalFrames,
                          (unsigned long long)writePos,
                          (unsigned long long)maxBytes,
                          wrapped ? " (wrapped)" : "");
    }

    ring.close();

    // Now reconstruct a proper PCAP file from the ring
    Serial.println("[pcap] Reconstructing PCAP from ring buffer...");

    ring = SD.open(RING_TMP_PATH, "r");
    if (!ring) {
        Serial.println("[pcap] Cannot reopen ring file!");
        return 0;
    }

    uint64_t ringFileSize = ring.size();
    // Determine the read range
    uint64_t readStart, readEnd;
    if (!wrapped) {
        readStart = 0;
        readEnd = writePos;
    } else {
        readStart = wrapPoint;
        readEnd = writePos;  // we'll read from wrapPoint -> EOF, then 0 -> writePos
    }

    // Open the final PCAP file
    if (SD.exists(PCAP_PATH_SD)) SD.remove(PCAP_PATH_SD);
    File out = SD.open(PCAP_PATH_SD, "w");
    if (!out) {
        Serial.println("[pcap] Cannot create output PCAP!");
        ring.close();
        return 0;
    }

    // Write PCAP global header
    uint8_t gh[24];
    le32(gh + 0, 0xA1B2C3D4UL);
    le16(gh + 4, 2); le16(gh + 6, 4);
    le32(gh + 8, 0); le32(gh + 12, 0);
    le32(gh + 16, ETH_MAX_LEN);
    le32(gh + 20, 1);
    out.write(gh, 24);

    uint32_t keptFrames = 0;
    uint32_t bytesWritten = 24;

    // Lambda to copy records from a range in the ring file
    auto copyRecords = [&](uint64_t from, uint64_t to) {
        ring.seek(from);
        uint64_t pos = from;
        while (pos + RING_REC_OVERHEAD <= to) {
            uint8_t hdr[RING_REC_OVERHEAD];
            if (ring.read(hdr, RING_REC_OVERHEAD) != RING_REC_OVERHEAD) break;

            uint32_t recSize = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8)
                             | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
            uint32_t frameLen = recSize - RING_REC_OVERHEAD;

            if (pos + recSize > to) break; // partial record
            if (recSize < RING_REC_OVERHEAD || frameLen > ETH_MAX_LEN + 4) break;

            // Write the pcap record header (skip the 4-byte recLen prefix)
            out.write(hdr + 4, 16);

            // Copy frame data in chunks
            uint32_t remaining = frameLen;
            while (remaining > 0) {
                uint32_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
                uint32_t got = ring.read(buf, chunk);
                if (got == 0) break;
                out.write(buf, got);
                remaining -= got;
            }

            bytesWritten += 16 + frameLen;
            keptFrames++;
            pos += recSize;
        }
    };

    if (!wrapped) {
        copyRecords(0, writePos);
    } else {
        // Read from wrapPoint to end of written data (may be ringFileSize or less)
        copyRecords(wrapPoint, ringFileSize);
        // Then from 0 to writePos
        if (writePos > 0) copyRecords(0, writePos);
    }

    out.close();
    ring.close();

    // Clean up temp file
    SD.remove(RING_TMP_PATH);

    Serial.printf("[pcap] Ring done: %lu total frames, %lu kept, %lu bytes saved.\r\n",
                  (unsigned long)totalFrames, (unsigned long)keptFrames,
                  (unsigned long)bytesWritten);
    Serial.println("Download from the web UI (PCAP card) and open in Wireshark.");
    return keptFrames;
}

#include "ota.h"
#include "weblog.h"
#include <Update.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>

// Tee output to web capture buffer
#define Serial Out

// =============================================================================
// TFTP client (RFC 1350) — minimal read-only implementation for OTA binary
// =============================================================================

static constexpr uint16_t TFTP_PORT      = 69;
static constexpr size_t   TFTP_BLOCK_SZ  = 512;
static constexpr int      TFTP_TIMEOUT_MS = 3000;
static constexpr int      TFTP_RETRIES   = 5;

// TFTP opcodes
enum { TFTP_RRQ = 1, TFTP_WRQ = 2, TFTP_DATA = 3, TFTP_ACK = 4, TFTP_ERROR = 5 };

bool otaTftp(const char *serverIp, const char *filename)
{
    Serial.printf("\r\nOTA via TFTP: %s/%s\r\n", serverIp, filename);

    // Resolve server address
    struct sockaddr_in srv = {};
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(TFTP_PORT);
    if (inet_pton(AF_INET, serverIp, &srv.sin_addr) != 1) {
        Serial.println("[OTA] Invalid server IP.");
        return false;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        Serial.println("[OTA] Socket creation failed.");
        return false;
    }

    // Set receive timeout
    struct timeval tv = { .tv_sec = TFTP_TIMEOUT_MS / 1000,
                          .tv_usec = (TFTP_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Build RRQ: opcode(2) + filename + '\0' + "octet" + '\0'
    uint8_t rrq[256];
    size_t fnLen = strlen(filename);
    if (fnLen > 200) { close(sock); Serial.println("[OTA] Filename too long."); return false; }
    size_t pos = 0;
    rrq[pos++] = 0; rrq[pos++] = TFTP_RRQ;
    memcpy(rrq + pos, filename, fnLen); pos += fnLen;
    rrq[pos++] = 0;
    memcpy(rrq + pos, "octet", 5); pos += 5;
    rrq[pos++] = 0;

    if (sendto(sock, rrq, pos, 0, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        close(sock);
        Serial.println("[OTA] Failed to send RRQ.");
        return false;
    }

    // Receive loop
    uint8_t buf[TFTP_BLOCK_SZ + 4];
    uint16_t expectedBlock = 1;
    size_t totalBytes = 0;
    bool started = false;

    Serial.println("[OTA] Waiting for TFTP data...");

    while (true) {
        // Check for user abort
        if (Serial.available()) {
            while (Serial.available()) Serial.read();
            Serial.println("\r\n[OTA] Aborted by user.");
            if (started) Update.abort();
            close(sock);
            return false;
        }

        struct sockaddr_in from = {};
        socklen_t fromLen = sizeof(from);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromLen);

        if (n < 0) {
            // Timeout — retry or fail
            static int retries = 0;
            if (++retries > TFTP_RETRIES) {
                Serial.println("[OTA] TFTP timeout (no response).");
                if (started) Update.abort();
                close(sock);
                return false;
            }
            continue;
        }

        if (n < 4) continue;  // too short

        uint16_t opcode = (buf[0] << 8) | buf[1];

        if (opcode == TFTP_ERROR) {
            buf[n] = '\0';  // ensure null-terminated error message
            Serial.printf("[OTA] TFTP error %u: %s\r\n",
                          (buf[2] << 8) | buf[3], (char *)&buf[4]);
            if (started) Update.abort();
            close(sock);
            return false;
        }

        if (opcode != TFTP_DATA) continue;

        uint16_t blockNum = (buf[2] << 8) | buf[3];
        size_t dataLen = n - 4;

        if (blockNum != expectedBlock) continue;  // duplicate or out of order

        // Start OTA on first block
        if (!started) {
            if (!Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) {
                Serial.printf("[OTA] Update.begin failed: %s\r\n",
                              Update.errorString());
                close(sock);
                return false;
            }
            started = true;
            Serial.println("[OTA] Flashing...");
        }

        // Write data
        if (dataLen > 0) {
            if (Update.write(buf + 4, dataLen) != dataLen) {
                Serial.printf("[OTA] Write failed: %s\r\n", Update.errorString());
                Update.abort();
                close(sock);
                return false;
            }
        }
        totalBytes += dataLen;

        // Send ACK
        uint8_t ack[4] = { 0, TFTP_ACK, buf[2], buf[3] };
        sendto(sock, ack, 4, 0, (struct sockaddr *)&from, fromLen);

        expectedBlock++;

        // Print progress every 64 blocks (~32 KB)
        if ((blockNum & 0x3F) == 0)
            Serial.printf("\r[OTA] %u KB received...", (unsigned)(totalBytes / 1024));

        // Last block (less than 512 bytes) signals end of transfer
        if (dataLen < TFTP_BLOCK_SZ) {
            Serial.printf("\r\n[OTA] Transfer complete: %u bytes\r\n", (unsigned)totalBytes);
            break;
        }
    }

    close(sock);

    if (!Update.end(true)) {
        Serial.printf("[OTA] Finalize failed: %s\r\n", Update.errorString());
        return false;
    }

    Serial.println("[OTA] Update successful! Rebooting...");
    Serial.flush();
    delay(500);
    ESP.restart();
    return true;  // unreachable
}

// =============================================================================
// Streaming OTA — for web upload (multipart chunked)
// =============================================================================

bool otaBeginStream(size_t totalSize)
{
    if (!Update.begin(totalSize, U_FLASH)) {
        return false;
    }
    return true;
}

bool otaWriteChunk(const uint8_t *data, size_t len)
{
    return Update.write((uint8_t *)data, len) == len;
}

bool otaFinishStream()
{
    if (!Update.end(true)) {
        return false;
    }
    return true;
}

void otaAbortStream()
{
    Update.abort();
}

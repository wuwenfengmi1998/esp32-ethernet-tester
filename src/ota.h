#pragma once

#include <Arduino.h>

// =============================================================================
// OTA Update — TFTP fetch and direct binary apply
//
// CLI:   ota tftp <server_ip> [filename]
// Web:   HTTP file upload to /api/ota  OR  ota tftp <server_ip> [filename]
// =============================================================================

// Apply OTA from a TFTP server. Blocks until complete or error.
// Returns true on success (device will reboot).
bool otaTftp(const char *serverIp, const char *filename = "firmware.bin");

// Begin streaming OTA (called from web upload handler).
// Returns false if the update cannot be started.
bool otaBeginStream(size_t totalSize);

// Write a chunk during streaming OTA.
bool otaWriteChunk(const uint8_t *data, size_t len);

// Finalize streaming OTA. Returns true on success (caller should reboot).
bool otaFinishStream();

// Abort an in-progress streaming OTA.
void otaAbortStream();

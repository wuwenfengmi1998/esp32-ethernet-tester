#pragma once

#include <Arduino.h>
#include "w5500_raw.h"
#include <FS.h>

// =============================================================================
// Packet capture in classic PCAP format (Wireshark-compatible).
//
// Storage priority:
//   1. TF (micro-SD) card -- large captures, virtually unlimited size
//   2. LittleFS (internal flash) -- fallback if no SD card is present
//
// The capture file is downloadable from the web UI (route /capture.pcap).
// =============================================================================

#define PCAP_FILENAME   "capture.pcap"
#define PCAP_PATH_SD    "/capture.pcap"
#define PCAP_PATH_FS    "/capture.pcap"

// Initialise SD card (call once from setup). Returns true if SD is usable.
bool pcapSdInit();

// Returns true if an SD card is present and mounted.
bool pcapSdAvailable();

// Capture up to `maxFrames` frames (0 = unlimited) for at most `seconds`
// (0 = until maxFrames or a key press). Returns the number of frames written.
uint32_t pcapCapture(W5500Raw &eth, uint32_t seconds, uint32_t maxFrames);

// Size in bytes of the stored capture (0 if none).
uint32_t pcapSize();

// Delete the stored capture file.
void pcapDelete();

// Get a pointer to the filesystem containing the capture (for web serving).
// Returns nullptr if no capture exists.
fs::FS *pcapFs();

// Get the path to the capture file on whichever FS holds it.
const char *pcapPath();

#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// Packet capture to LittleFS in classic PCAP format (Wireshark-compatible).
//
// Captures raw Ethernet frames to /capture.pcap, which can then be downloaded
// from the web UI (route /capture.pcap) and opened directly in Wireshark.
// =============================================================================

#define PCAP_PATH "/capture.pcap"

// Capture up to `maxFrames` frames (0 = unlimited) for at most `seconds`
// (0 = until maxFrames or a key press). Returns the number of frames written.
uint32_t pcapCapture(W5500Raw &eth, uint32_t seconds, uint32_t maxFrames);

// Size in bytes of the stored capture (0 if none).
uint32_t pcapSize();

// Delete the stored capture file.
void pcapDelete();

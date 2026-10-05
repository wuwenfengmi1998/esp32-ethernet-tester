#pragma once

#include <Arduino.h>

// =============================================================================
// Display -- 1.3" 128x64 SH1106 OLED over I2C (optional hardware)
//
// Hand-rolled driver: Wire I2C transport, 1 KB framebuffer, 5x7 ASCII font,
// page addressing with dirty-page flush. A live status page is rendered from
// a provider callback (same pattern as WebControl::setStatusProvider).
//
// Boot: displayBegin() probes the panel; if it does not answer every call
// becomes a no-op (non-fatal, like the SD card). 1 MHz I2C by default with
// automatic fallback to 400 kHz / 100 kHz.
//
// Usage:
//   setup(): displayBegin(); displaySetStatusProvider(fn);
//   loop():  displayTick();
//
//   display status          -- force status page (CLI)
//   display text <row> <s>  -- write a line, pauses auto status page
// =============================================================================

struct DisplayStatus {
    bool     linkUp;        // Ethernet link state
    bool     speed100;      // true: 100 Mbps, false: 10 Mbps
    bool     fullDuplex;
    char     ip[16];        // Ethernet IPv4 address ("0.0.0.0" if none)
    char     host[33];      // device hostname
    uint32_t uptimeSec;
    uint16_t heapKb;        // free heap in KB
    bool     wifiUp;        // Wi-Fi station connected
    char     wifiIp[16];    // Wi-Fi IP ("0.0.0.0" if none)
    bool     sdPresent;     // TF/SD card mounted
};

typedef void (*DisplayStatusFn)(DisplayStatus &);

// Probe and initialise the panel. Returns false if no I2C device answers
// (display disabled, all other calls become no-ops).
bool displayBegin();

bool displayAvailable();

// Provider called by displayTick() when the status page is due.
void displaySetStatusProvider(DisplayStatusFn fn);

// Call from loop(): refresh the status page every DISPLAY_REFRESH_MS.
void displayTick();

// Force an immediate status redraw and resume auto-refresh.
void displayShowStatus();

// Draw one 8-pixel text row (0..7), left-aligned. Pauses auto status page.
void displayDrawText(uint8_t row, const char *text);

// Blank the framebuffer (pauses auto status page).
void displayClear();

// Shut down the display: stop auto-refresh, blank the pixels and turn the
// panel off. Used by the power-off path; all drawing/refresh calls become
// no-ops afterwards.
void displayShutdown();

void displayOn(bool on);                 // panel power (0xAE/0xAF)
void displayInvert(bool on);             // invert pixels
void displaySetContrast(uint8_t value);  // 0..255

// Runtime I2C clock tuning (e.g. display speed 400000).
void     displaySetSpeed(uint32_t hz);
uint32_t displayGetSpeed();

// Print panel info (address, pins, speed, contrast, mode) to the CLI.
void displayPrintInfo();

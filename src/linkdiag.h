#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// Physical-link diagnostics
//
//   - linkInfo    : one-shot auto-negotiation / speed / duplex / link summary
//   - linkMonitor : sample the PHY for N seconds and report link-flap events
// =============================================================================

void linkInfo(W5500Raw &eth);
void linkMonitor(W5500Raw &eth, uint32_t seconds);

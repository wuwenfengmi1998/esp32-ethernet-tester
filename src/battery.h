#pragma once

#include <Arduino.h>

// =============================================================================
// Battery Monitor -- single-cell Li-ion (4.2 V max)
//
// VBAT is scaled by a 0.5 divider into PIN_BAT_ADC (ADC1, eFuse-calibrated
// analogReadMilliVolts). Charge detect on PIN_CHG_DETECT is a pull-down input,
// HIGH while the charger is connected.
//
// batteryTick() samples at 1 Hz from loop(); the getters return cached values
// so both the status display and the low-voltage cut-off see the same reading.
// batteryLow() asserts after BAT_CUTOFF_COUNT consecutive samples at or below
// BAT_CUTOFF_MV while not charging (charging is exempt so a deeply discharged
// battery can recover).
// =============================================================================

void batteryInit();          // setup(): configure pins and take a first sample
void batteryTick();          // loop(): 1 Hz sample + low-voltage debounce

bool     batteryCharging();  // true while the charge-detect input is HIGH
uint32_t batteryVoltageMv(); // cached battery voltage (mV)
uint8_t  batteryPercent();   // cached 0..100, linear BAT_EMPTY_MV..BAT_FULL_MV
bool     batteryLow();       // true once the cutoff threshold is confirmed

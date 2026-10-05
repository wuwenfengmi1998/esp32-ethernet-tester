#include "battery.h"
#include "../include/config.h"
#include "weblog.h"

// Tee serial output to the web capture ring (see weblog.h).
#define Serial Out

#define BAT_SAMPLES 8

static uint32_t _mv = 0;
static uint8_t  _pct = 0;
static bool     _charging = false;
static bool     _low = false;
static uint8_t  _lowCount = 0;
static uint32_t _lastSample = 0;

// Average BAT_SAMPLES calibrated reads and undo the divider.
static uint32_t _sampleMv()
{
    uint32_t sum = 0;
    for (int i = 0; i < BAT_SAMPLES; i++)
        sum += analogReadMilliVolts(PIN_BAT_ADC);
    uint32_t pinMv = sum / BAT_SAMPLES;
    return (uint32_t)(pinMv / BAT_DIVIDER_RATIO);
}

static uint8_t _toPercent(uint32_t mv)
{
    if (mv <= BAT_EMPTY_MV) return 0;
    if (mv >= BAT_FULL_MV)  return 100;
    return (uint8_t)((mv - BAT_EMPTY_MV) * 100UL / (BAT_FULL_MV - BAT_EMPTY_MV));
}

void batteryInit()
{
    analogSetPinAttenuation(PIN_BAT_ADC, ADC_11db);
    pinMode(PIN_CHG_DETECT, INPUT_PULLDOWN);

    _charging   = (digitalRead(PIN_CHG_DETECT) == HIGH);
    _mv         = _sampleMv();
    _pct        = _toPercent(_mv);
    _low        = false;
    _lowCount   = 0;
    _lastSample = millis();

    Serial.printf("[BAT] Monitor on GPIO%d (divider %.1f), charge detect GPIO%d: %s, %lu mV (%u%%).\r\n",
                  PIN_BAT_ADC, (double)BAT_DIVIDER_RATIO, PIN_CHG_DETECT,
                  _charging ? "charging" : "discharging",
                  (unsigned long)_mv, _pct);
}

void batteryTick()
{
    uint32_t now = millis();
    if (now - _lastSample < 1000) return;   // 1 Hz
    _lastSample = now;

    _charging = (digitalRead(PIN_CHG_DETECT) == HIGH);
    _mv       = _sampleMv();
    _pct      = _toPercent(_mv);

    if (_low) return;                       // latch: once tripped, stays tripped

    if (_charging) {
        _lowCount = 0;                      // charging is exempt
    } else if (_mv <= BAT_CUTOFF_MV) {
        if (++_lowCount >= BAT_CUTOFF_COUNT) {
            _low = true;
            Serial.printf("[BAT] Low voltage confirmed (%lu mV) -- cutting power.\r\n",
                          (unsigned long)_mv);
        }
    } else {
        _lowCount = 0;
    }
}

bool     batteryCharging()  { return _charging; }
uint32_t batteryVoltageMv() { return _mv; }
uint8_t  batteryPercent()   { return _pct; }
bool     batteryLow()       { return _low; }

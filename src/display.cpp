#include "display.h"
#include "../include/config.h"
#include "weblog.h"
#include <Wire.h>
#include <string.h>
#include <stdio.h>

// Tee serial output to the web capture ring (see weblog.h).
#define Serial Out

// =============================================================================
// SH1106 panel constants
// =============================================================================
#define SH1106_PAGES        (DISPLAY_HEIGHT / 8)
#define SH1106_CTRL_CMD     0x00    // control byte: following byte is a command
#define SH1106_CTRL_DATA    0x40    // control byte: following bytes are RAM data
#define SH1106_CHUNK        32      // I2C data bytes per Wire transaction

// =============================================================================
// 5x7 ASCII font (0x20..0x7E), classic Adafruit glcdfont glyphs.
// Each glyph is 5 column bytes, LSB = top pixel row.
// =============================================================================
static const uint8_t FONT5X7[95][5] PROGMEM = {
    { 0x00, 0x00, 0x00, 0x00, 0x00 },  // ' '
    { 0x00, 0x00, 0x5F, 0x00, 0x00 },  // '!'
    { 0x00, 0x07, 0x00, 0x07, 0x00 },  // '"'
    { 0x14, 0x7F, 0x14, 0x7F, 0x14 },  // '#'
    { 0x24, 0x2A, 0x7F, 0x2A, 0x12 },  // '$'
    { 0x23, 0x13, 0x08, 0x64, 0x62 },  // '%'
    { 0x36, 0x49, 0x56, 0x20, 0x50 },  // '&'
    { 0x00, 0x08, 0x07, 0x03, 0x00 },  // apostrophe
    { 0x00, 0x1C, 0x22, 0x41, 0x00 },  // '('
    { 0x00, 0x41, 0x22, 0x1C, 0x00 },  // ')'
    { 0x2A, 0x1C, 0x7F, 0x1C, 0x2A },  // '*'
    { 0x08, 0x08, 0x3E, 0x08, 0x08 },  // '+'
    { 0x00, 0x80, 0x70, 0x30, 0x00 },  // ','
    { 0x08, 0x08, 0x08, 0x08, 0x08 },  // '-'
    { 0x00, 0x00, 0x60, 0x60, 0x00 },  // '.'
    { 0x20, 0x10, 0x08, 0x04, 0x02 },  // '/'
    { 0x3E, 0x51, 0x49, 0x45, 0x3E },  // '0'
    { 0x00, 0x42, 0x7F, 0x40, 0x00 },  // '1'
    { 0x72, 0x49, 0x49, 0x49, 0x46 },  // '2'
    { 0x21, 0x41, 0x49, 0x4D, 0x33 },  // '3'
    { 0x18, 0x14, 0x12, 0x7F, 0x10 },  // '4'
    { 0x27, 0x45, 0x45, 0x45, 0x39 },  // '5'
    { 0x3C, 0x4A, 0x49, 0x49, 0x31 },  // '6'
    { 0x41, 0x21, 0x11, 0x09, 0x07 },  // '7'
    { 0x36, 0x49, 0x49, 0x49, 0x36 },  // '8'
    { 0x46, 0x49, 0x49, 0x29, 0x1E },  // '9'
    { 0x00, 0x00, 0x14, 0x00, 0x00 },  // ':'
    { 0x00, 0x40, 0x34, 0x00, 0x00 },  // ';'
    { 0x00, 0x08, 0x14, 0x22, 0x41 },  // '<'
    { 0x14, 0x14, 0x14, 0x14, 0x14 },  // '='
    { 0x00, 0x41, 0x22, 0x14, 0x08 },  // '>'
    { 0x02, 0x01, 0x59, 0x09, 0x06 },  // '?'
    { 0x3E, 0x41, 0x5D, 0x59, 0x4E },  // '@'
    { 0x7C, 0x12, 0x11, 0x12, 0x7C },  // 'A'
    { 0x7F, 0x49, 0x49, 0x49, 0x36 },  // 'B'
    { 0x3E, 0x41, 0x41, 0x41, 0x22 },  // 'C'
    { 0x7F, 0x41, 0x41, 0x41, 0x3E },  // 'D'
    { 0x7F, 0x49, 0x49, 0x49, 0x41 },  // 'E'
    { 0x7F, 0x09, 0x09, 0x09, 0x01 },  // 'F'
    { 0x3E, 0x41, 0x41, 0x51, 0x73 },  // 'G'
    { 0x7F, 0x08, 0x08, 0x08, 0x7F },  // 'H'
    { 0x00, 0x41, 0x7F, 0x41, 0x00 },  // 'I'
    { 0x20, 0x40, 0x41, 0x3F, 0x01 },  // 'J'
    { 0x7F, 0x08, 0x14, 0x22, 0x41 },  // 'K'
    { 0x7F, 0x40, 0x40, 0x40, 0x40 },  // 'L'
    { 0x7F, 0x02, 0x1C, 0x02, 0x7F },  // 'M'
    { 0x7F, 0x04, 0x08, 0x10, 0x7F },  // 'N'
    { 0x3E, 0x41, 0x41, 0x41, 0x3E },  // 'O'
    { 0x7F, 0x09, 0x09, 0x09, 0x06 },  // 'P'
    { 0x3E, 0x41, 0x51, 0x21, 0x5E },  // 'Q'
    { 0x7F, 0x09, 0x19, 0x29, 0x46 },  // 'R'
    { 0x26, 0x49, 0x49, 0x49, 0x32 },  // 'S'
    { 0x03, 0x01, 0x7F, 0x01, 0x03 },  // 'T'
    { 0x3F, 0x40, 0x40, 0x40, 0x3F },  // 'U'
    { 0x1F, 0x20, 0x40, 0x20, 0x1F },  // 'V'
    { 0x3F, 0x40, 0x38, 0x40, 0x3F },  // 'W'
    { 0x63, 0x14, 0x08, 0x14, 0x63 },  // 'X'
    { 0x03, 0x04, 0x78, 0x04, 0x03 },  // 'Y'
    { 0x61, 0x59, 0x49, 0x4D, 0x43 },  // 'Z'
    { 0x00, 0x7F, 0x41, 0x41, 0x41 },  // '['
    { 0x02, 0x04, 0x08, 0x10, 0x20 },  // backslash
    { 0x00, 0x41, 0x41, 0x41, 0x7F },  // ']'
    { 0x04, 0x02, 0x01, 0x02, 0x04 },  // '^'
    { 0x40, 0x40, 0x40, 0x40, 0x40 },  // '_'
    { 0x00, 0x03, 0x07, 0x08, 0x00 },  // '`'
    { 0x20, 0x54, 0x54, 0x78, 0x40 },  // 'a'
    { 0x7F, 0x28, 0x44, 0x44, 0x38 },  // 'b'
    { 0x38, 0x44, 0x44, 0x44, 0x28 },  // 'c'
    { 0x38, 0x44, 0x44, 0x28, 0x7F },  // 'd'
    { 0x38, 0x54, 0x54, 0x54, 0x18 },  // 'e'
    { 0x00, 0x08, 0x7E, 0x09, 0x02 },  // 'f'
    { 0x18, 0xA4, 0xA4, 0x9C, 0x78 },  // 'g'
    { 0x7F, 0x08, 0x04, 0x04, 0x78 },  // 'h'
    { 0x00, 0x44, 0x7D, 0x40, 0x00 },  // 'i'
    { 0x20, 0x40, 0x40, 0x3D, 0x00 },  // 'j'
    { 0x7F, 0x10, 0x28, 0x44, 0x00 },  // 'k'
    { 0x00, 0x41, 0x7F, 0x40, 0x00 },  // 'l'
    { 0x7C, 0x04, 0x78, 0x04, 0x78 },  // 'm'
    { 0x7C, 0x08, 0x04, 0x04, 0x78 },  // 'n'
    { 0x38, 0x44, 0x44, 0x44, 0x38 },  // 'o'
    { 0xFC, 0x18, 0x24, 0x24, 0x18 },  // 'p'
    { 0x18, 0x24, 0x24, 0x18, 0xFC },  // 'q'
    { 0x7C, 0x08, 0x04, 0x04, 0x08 },  // 'r'
    { 0x48, 0x54, 0x54, 0x54, 0x24 },  // 's'
    { 0x04, 0x04, 0x3F, 0x44, 0x24 },  // 't'
    { 0x3C, 0x40, 0x40, 0x20, 0x7C },  // 'u'
    { 0x1C, 0x20, 0x40, 0x20, 0x1C },  // 'v'
    { 0x3C, 0x40, 0x30, 0x40, 0x3C },  // 'w'
    { 0x44, 0x28, 0x10, 0x28, 0x44 },  // 'x'
    { 0x4C, 0x90, 0x90, 0x90, 0x7C },  // 'y'
    { 0x44, 0x64, 0x54, 0x4C, 0x44 },  // 'z'
    { 0x00, 0x08, 0x36, 0x41, 0x00 },  // '{'
    { 0x00, 0x00, 0x77, 0x00, 0x00 },  // '|'
    { 0x00, 0x41, 0x36, 0x08, 0x00 },  // '}'
    { 0x02, 0x01, 0x02, 0x04, 0x02 },  // '~'
};

// =============================================================================
// State
// =============================================================================
enum DisplayMode { MODE_STATUS, MODE_TEXT };

static uint8_t  _fb[DISPLAY_WIDTH * SH1106_PAGES];       // current frame
static uint8_t  _shadow[DISPLAY_WIDTH * SH1106_PAGES];   // last frame sent
static bool     _ok = false;
static bool     _suspended = false;                      // shutdown: no more I2C
static bool     _panelOn = true;
static uint8_t  _contrast = DISPLAY_CONTRAST;
static uint32_t _speed = DISPLAY_I2C_FREQ;
static uint32_t _lastRefresh = 0;
static DisplayStatusFn _statusFn = nullptr;
static DisplayMode _mode = MODE_STATUS;

// =============================================================================
// Low-level I2C
// =============================================================================
static void _cmd(uint8_t c)
{
    Wire.beginTransmission(DISPLAY_I2C_ADDR);
    Wire.write((uint8_t)SH1106_CTRL_CMD);
    Wire.write(c);
    Wire.endTransmission();
}

static void _cmd2(uint8_t c, uint8_t v)
{
    Wire.beginTransmission(DISPLAY_I2C_ADDR);
    Wire.write((uint8_t)SH1106_CTRL_CMD);
    Wire.write(c);
    Wire.write(v);
    Wire.endTransmission();
}

static void _data(const uint8_t *p, size_t n)
{
    while (n) {
        size_t chunk = (n > SH1106_CHUNK) ? SH1106_CHUNK : n;
        Wire.beginTransmission(DISPLAY_I2C_ADDR);
        Wire.write((uint8_t)SH1106_CTRL_DATA);
        Wire.write(p, chunk);
        Wire.endTransmission();
        p += chunk;
        n -= chunk;
    }
}

static bool _probe()
{
    Wire.beginTransmission(DISPLAY_I2C_ADDR);
    return Wire.endTransmission() == 0;
}

static void _initPanel()
{
    _cmd(0xAE);            // display off
    _cmd2(0xD5, 0x80);     // clock divide / oscillator
    _cmd2(0xA8, 0x3F);     // multiplex ratio 64
    _cmd2(0xD3, 0x00);     // display offset 0
    _cmd(0x40);            // start line 0
    _cmd2(0xAD, 0x8B);     // internal DC-DC on
    _cmd(0x33);            // charge pump 9 V
    _cmd2(0x81, _contrast);// contrast
    _cmd(0xA1);            // segment remap
    _cmd(0xC8);            // COM scan direction reversed
    _cmd2(0xDA, 0x12);     // COM pins: alternate
    _cmd2(0xD9, 0x22);     // pre-charge period
    _cmd2(0xDB, 0x30);     // VCOM deselect level
    _cmd(0xA4);            // output follows RAM
    _cmd(0xA6);            // normal (non-inverted)
    _cmd(0xAF);            // display on
}

// Push changed pages (force = all pages). SH1106 has 132-column RAM, so the
// visible 128 columns start at DISPLAY_COL_OFFSET.
static void _flush(bool force)
{
    for (uint8_t page = 0; page < SH1106_PAGES; page++) {
        uint16_t off = (uint16_t)page * DISPLAY_WIDTH;
        if (!force && memcmp(_fb + off, _shadow + off, DISPLAY_WIDTH) == 0) continue;

        _cmd(0xB0 | page);
        _cmd(0x00 | (DISPLAY_COL_OFFSET & 0x0F));
        _cmd(0x10 | ((DISPLAY_COL_OFFSET >> 4) & 0x0F));
        _data(_fb + off, DISPLAY_WIDTH);
    }
    memcpy(_shadow, _fb, sizeof(_fb));
}

// =============================================================================
// Framebuffer drawing
// =============================================================================
static void _clearFb()
{
    memset(_fb, 0, sizeof(_fb));
}

static void _clearRow(uint8_t row)
{
    if (row < SH1106_PAGES) memset(_fb + (uint16_t)row * DISPLAY_WIDTH, 0, DISPLAY_WIDTH);
}

// Draw one character at pixel column x on page `row` (6 px advance).
static void _drawChar(uint8_t x, uint8_t row, char c)
{
    if (row >= SH1106_PAGES || x >= DISPLAY_WIDTH) return;
    if (c < 0x20 || c > 0x7E) c = '?';

    const uint8_t *g = FONT5X7[c - 0x20];
    uint16_t base = (uint16_t)row * DISPLAY_WIDTH;
    for (uint8_t i = 0; i < 5 && x + i < DISPLAY_WIDTH; i++)
        _fb[base + x + i] = pgm_read_byte(&g[i]);
    if (x + 5 < DISPLAY_WIDTH)
        _fb[base + x + 5] = 0x00;
}

static void _drawStr(uint8_t x, uint8_t row, const char *s)
{
    while (*s && x + 5 < DISPLAY_WIDTH) {
        _drawChar(x, row, *s++);
        x += 6;
    }
}

// =============================================================================
// Status page
// =============================================================================
static void _formatUptime(uint32_t sec, char *out, size_t n)
{
    uint32_t d = sec / 86400; sec %= 86400;
    uint32_t h = sec / 3600;  sec %= 3600;
    uint32_t m = sec / 60;    sec %= 60;
    if (d)
        snprintf(out, n, "%lud %02lu:%02lu", (unsigned long)d, (unsigned long)h, (unsigned long)m);
    else
        snprintf(out, n, "%02lu:%02lu:%02lu", (unsigned long)h, (unsigned long)m, (unsigned long)sec);
}

static void _renderStatus()
{
    DisplayStatus st;
    memset(&st, 0, sizeof(st));
    strcpy(st.ip, "0.0.0.0");
    strcpy(st.wifiIp, "0.0.0.0");
    if (_statusFn) _statusFn(st);

    for (uint8_t r = 0; r < SH1106_PAGES; r++) _clearRow(r);

    char line[32];
    char up[24];

    _drawStr(0, 0, "ESP32 Ethernet Tester");

    _formatUptime(st.uptimeSec, up, sizeof(up));
    snprintf(line, sizeof(line), "FW %s  %s", FW_VERSION, up);
    _drawStr(0, 1, line);

    snprintf(line, sizeof(line), "Link: %s %s %s",
             st.linkUp ? "UP" : "DOWN",
             st.speed100 ? "100M" : "10M",
             st.fullDuplex ? "full" : "half");
    _drawStr(0, 2, line);

    snprintf(line, sizeof(line), "IP:   %s", st.ip);
    _drawStr(0, 3, line);

    snprintf(line, sizeof(line), "Host: %s", st.host);
    _drawStr(0, 4, line);

    snprintf(line, sizeof(line), "WiFi: %s", st.wifiUp ? st.wifiIp : "off");
    _drawStr(0, 5, line);

    snprintf(line, sizeof(line), "SD:   %s", st.sdPresent ? "present" : "absent");
    _drawStr(0, 6, line);

    snprintf(line, sizeof(line), "Heap: %u KB", (unsigned)st.heapKb);
    _drawStr(0, 7, line);
}

static void _splash()
{
    _clearFb();
    _drawStr(0, 1, "ESP32 Ethernet Tester");
    _drawStr(0, 3, "Firmware " FW_VERSION);
    _drawStr(0, 5, "Display init...");
    _flush(true);
    delay(500);
}

// =============================================================================
// Public API
// =============================================================================
bool displayBegin()
{
    _ok = false;
    _suspended = false;
    _mode = MODE_STATUS;

    Wire.begin(DISPLAY_I2C_SDA, DISPLAY_I2C_SCL, DISPLAY_I2C_FREQ);
    Wire.setTimeOut(50);

    const uint32_t speeds[] = { DISPLAY_I2C_FREQ, DISPLAY_I2C_FREQ_FALLBACK, 100000UL };
    for (size_t i = 0; i < sizeof(speeds) / sizeof(speeds[0]); i++) {
        if (!Wire.setClock(speeds[i])) continue;
        if (_probe()) {
            _speed = speeds[i];
            _ok = true;
            if (i > 0)
                Serial.printf("[DISP] No ACK at %lu Hz; using %lu Hz.\r\n",
                              (unsigned long)speeds[0], (unsigned long)_speed);
            break;
        }
    }

    if (!_ok) {
        Serial.printf("[DISP] SH1106 not found at 0x%02X (SDA %d, SCL %d) -- display disabled.\r\n",
                      DISPLAY_I2C_ADDR, DISPLAY_I2C_SDA, DISPLAY_I2C_SCL);
        return false;
    }

    _initPanel();
    _panelOn = true;
    _contrast = DISPLAY_CONTRAST;

    memset(_shadow, 0xFF, sizeof(_shadow));   // force a full first flush
    _clearFb();
    _flush(true);                             // blank the panel RAM
    _splash();

    Serial.printf("[DISP] SH1106 ready @ %lu Hz (addr 0x%02X, SDA %d, SCL %d).\r\n",
                  (unsigned long)_speed, DISPLAY_I2C_ADDR,
                  DISPLAY_I2C_SDA, DISPLAY_I2C_SCL);
    return true;
}

bool displayAvailable() { return _ok; }

void displaySetStatusProvider(DisplayStatusFn fn) { _statusFn = fn; }

void displayTick()
{
    if (!_ok || _suspended || _mode != MODE_STATUS || !_statusFn) return;

    uint32_t now = millis();
    if (now - _lastRefresh < DISPLAY_REFRESH_MS) return;
    _lastRefresh = now;

    _renderStatus();
    _flush(false);
}

void displayShowStatus()
{
    if (!_ok || _suspended) return;
    _mode = MODE_STATUS;
    _renderStatus();
    _flush(true);
    _lastRefresh = millis();
}

void displayDrawText(uint8_t row, const char *text)
{
    if (!_ok || _suspended || row >= SH1106_PAGES) return;
    _mode = MODE_TEXT;
    _clearRow(row);
    _drawStr(0, row, text ? text : "");
    _flush(false);
}

void displayClear()
{
    if (!_ok || _suspended) return;
    _mode = MODE_TEXT;
    _clearFb();
    _flush(false);
}

// Power-off path: render a final blank frame, turn the panel off and latch
// the suspended state so no later tick/CLI call can touch the I2C bus.
void displayShutdown()
{
    if (!_ok || _suspended) return;
    _suspended = true;
    _mode = MODE_TEXT;
    _clearFb();
    _flush(true);
    _cmd(0xAE);                 // panel off
    _panelOn = false;
    Serial.println("[DISP] Display shutdown (panel blanked and off).");
}

void displayOn(bool on)
{
    if (!_ok || _suspended) return;
    _panelOn = on;
    _cmd(on ? 0xAF : 0xAE);
}

void displayInvert(bool on)
{
    if (!_ok || _suspended) return;
    _cmd(on ? 0xA7 : 0xA6);
}

void displaySetContrast(uint8_t value)
{
    if (!_ok || _suspended) return;
    _contrast = value;
    _cmd2(0x81, value);
}

void displaySetSpeed(uint32_t hz)
{
    if (!_ok || _suspended || hz < 10000) return;
    if (Wire.setClock(hz)) {
        _speed = hz;
        Serial.printf("[DISP] I2C clock: %lu Hz\r\n", (unsigned long)_speed);
    } else {
        Serial.printf("[DISP] Cannot set I2C clock to %lu Hz.\r\n", (unsigned long)hz);
    }
}

uint32_t displayGetSpeed() { return _speed; }

void displayPrintInfo()
{
    if (_ok) {
        Serial.printf("  SH1106 128x64 @ 0x%02X (SDA %d, SCL %d)\r\n",
                      DISPLAY_I2C_ADDR, DISPLAY_I2C_SDA, DISPLAY_I2C_SCL);
        Serial.printf("  I2C: %lu Hz   contrast: 0x%02X   panel: %s   mode: %s\r\n",
                      (unsigned long)_speed, _contrast,
                      _suspended ? "shutdown" : (_panelOn ? "on" : "off"),
                      _mode == MODE_STATUS ? "status" : "text");
    } else {
        Serial.printf("  Display not detected at 0x%02X (SDA %d, SCL %d).\r\n",
                      DISPLAY_I2C_ADDR, DISPLAY_I2C_SDA, DISPLAY_I2C_SCL);
    }
}

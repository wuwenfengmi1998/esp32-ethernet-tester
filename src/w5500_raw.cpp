#include "w5500_raw.h"
#include "../include/config.h"

// W5500 buffer sizes (socket 0 gets all 16 KB for TX and RX)
static constexpr uint16_t BUF_SIZE_KB   = 16;
static constexpr uint32_t BUF_SIZE      = BUF_SIZE_KB * 1024UL;   // 16384 bytes
static constexpr uint16_t BUF_MASK      = BUF_SIZE - 1;           // 0x3FFF

static SPIClass _spi(FSPI);
static SPISettings _spiSettings(W5500_SPI_FREQ, MSBFIRST, SPI_MODE0);

// =============================================================================
// Construction
// =============================================================================
W5500Raw::W5500Raw(uint8_t csPin, uint8_t rstPin)
    : _csPin(csPin), _rstPin(rstPin)
{
    memset(&_stats, 0, sizeof(_stats));
}

// =============================================================================
// Public API
// =============================================================================
bool W5500Raw::begin(const uint8_t mac[6])
{
    // Configure pins
    pinMode(_csPin, OUTPUT);
    digitalWrite(_csPin, HIGH);

    if (_rstPin != 255) {
        pinMode(_rstPin, OUTPUT);
        digitalWrite(_rstPin, HIGH);
    }

    // Start FSPI with explicit pin mapping
    _spi.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI, _csPin);

    // Hardware reset
    reset();
    delay(200);  // Wait for W5500 internal PLL to stabilise

    // Verify chip version (0x04)
    uint8_t ver = _readReg8(W5500_VERSIONR, BSB_COMMON);
    if (ver != 0x04) {
        Serial.printf("[W5500] Version check failed: got 0x%02X, expected 0x04\r\n", ver);
        return false;
    }

    // Software reset
    _writeReg8(W5500_MR, BSB_COMMON, 0x80);
    delay(10);
    while (_readReg8(W5500_MR, BSB_COMMON) & 0x80) delay(1);

    // Set source MAC
    _writeBuf(W5500_SHAR, BSB_COMMON, mac, 6);

    // Allocate all 16 KB TX buffer to socket 0; set sockets 1-7 to 0 KB
    _writeReg8(Sn_TXBUF_SIZE, BSB_S0_REG, BUF_SIZE_KB);
    for (uint8_t n = 1; n <= 7; n++) {
        _writeReg8(Sn_TXBUF_SIZE, (n * 4 + 2), 0);  // not standard helper, write direct
    }
    // Allocate all 16 KB RX buffer to socket 0; set sockets 1-7 to 0 KB
    _writeReg8(Sn_RXBUF_SIZE, BSB_S0_REG, BUF_SIZE_KB);
    for (uint8_t n = 1; n <= 7; n++) {
        _writeReg8(Sn_RXBUF_SIZE, (n * 4 + 1), 0);
    }

    // Open socket 0 in MACRAW mode (without MAC filter so we receive all frames)
    _writeReg8(Sn_MR, BSB_S0_REG, Sn_MR_MACRAW);
    _execCmd(Sn_CR_OPEN);
    delay(5);

    uint8_t sr = _readReg8(Sn_SR, BSB_S0_REG);
    if (sr != SOCK_MACRAW) {
        Serial.printf("[W5500] Socket 0 open failed: SR=0x%02X\r\n", sr);
        return false;
    }

    return true;
}

void W5500Raw::reset()
{
    if (_rstPin != 255) {
        digitalWrite(_rstPin, LOW);
        delay(10);
        digitalWrite(_rstPin, HIGH);
        delay(50);
    }
}

bool W5500Raw::isLinked()
{
    return (_readReg8(W5500_PHYCFGR, BSB_COMMON) & PHYCFGR_LNK) != 0;
}

uint8_t W5500Raw::phyCfgr()
{
    return _readReg8(W5500_PHYCFGR, BSB_COMMON);
}

void W5500Raw::setPhyMode(uint8_t mode)
{
    // PHYCFGR bits [7]=RST [6]=OPMD [5:3]=OPMDC [2:0]=status(RO)
    // OPMDC: 111=auto, 011=100FD, 010=100HD, 001=10FD, 000=10HD
    uint8_t opmdc;
    switch (mode) {
        case 1: opmdc = 0x03; break; // 100FD
        case 2: opmdc = 0x02; break; // 100HD
        case 3: opmdc = 0x01; break; // 10FD
        case 4: opmdc = 0x00; break; // 10HD
        default: opmdc = 0x07; break; // auto
    }
    // Set OPMD=1 (use register config), write OPMDC, then pulse RST
    uint8_t val = 0x40 | (opmdc << 3); // OPMD=1, RST=0 (triggers reset)
    _writeReg8(W5500_PHYCFGR, BSB_COMMON, val);
    delay(1);
    val |= 0x80; // release RST
    _writeReg8(W5500_PHYCFGR, BSB_COMMON, val);
    delay(50); // allow PHY to settle
}

// =============================================================================
// TX
// =============================================================================
bool W5500Raw::sendFrame(const uint8_t *frame, uint16_t len)
{
    if (len == 0) return false;

    // Wait for TX free space (timeout 100 ms)
    uint32_t deadline = millis() + 100;
    while (_txFree() < len) {
        if (millis() > deadline) {
            _stats.txErrors++;
            return false;
        }
        delayMicroseconds(10);
    }

    // Read current TX write pointer
    uint16_t wr = _readReg16(Sn_TX_WR, BSB_S0_REG);

    // Write frame into TX ring buffer (handles wrap-around)
    _writeTxBuf(wr & BUF_MASK, frame, len);

    // Advance TX write pointer and issue SEND
    _writeReg16(Sn_TX_WR, BSB_S0_REG, wr + len);
    _execCmd(Sn_CR_SEND);

    _stats.txFrames++;
    _stats.txBytes += len;
    return true;
}

// =============================================================================
// RX
// In MACRAW mode the W5500 prepends a 2-byte size field to each received frame.
// Size field value = frame_len + 2 (includes itself).
// FCS is stripped by the hardware.
// =============================================================================
uint16_t W5500Raw::recvFrame(uint8_t *buf, uint16_t maxLen)
{
    uint16_t rxSz = _rxSize();
    if (rxSz < 2) return 0;

    uint16_t rd = _readReg16(Sn_RX_RD, BSB_S0_REG);

    // Read the 2-byte size header
    uint8_t hdr[2];
    _readRxBuf(rd & BUF_MASK, hdr, 2);
    uint16_t pktLen = ((uint16_t)hdr[0] << 8) | hdr[1];  // includes the 2-byte header

    if (pktLen < 2 || pktLen > rxSz) {
        // Malformed: flush RX by advancing past what's claimed available
        _writeReg16(Sn_RX_RD, BSB_S0_REG, rd + rxSz);
        _execCmd(Sn_CR_RECV);
        _stats.rxDropped++;
        return 0;
    }

    uint16_t frameLen = pktLen - 2;

    if (frameLen > maxLen) {
        // Buffer too small — discard this frame
        _writeReg16(Sn_RX_RD, BSB_S0_REG, rd + pktLen);
        _execCmd(Sn_CR_RECV);
        _stats.rxDropped++;
        return 0;
    }

    // Read actual frame data
    _readRxBuf((rd + 2) & BUF_MASK, buf, frameLen);

    // Advance RX read pointer and issue RECV
    _writeReg16(Sn_RX_RD, BSB_S0_REG, rd + pktLen);
    _execCmd(Sn_CR_RECV);

    _stats.rxFrames++;
    _stats.rxBytes += frameLen;
    return frameLen;
}

uint16_t W5500Raw::rxAvailable()
{
    return _rxSize();
}

// =============================================================================
// Low-level SPI helpers
// =============================================================================
static inline void _spiHeader(uint16_t addr, uint8_t ctl)
{
    _spi.transfer((addr >> 8) & 0xFF);
    _spi.transfer(addr & 0xFF);
    _spi.transfer(ctl);
}

uint8_t W5500Raw::_readReg8(uint16_t addr, uint8_t bsb)
{
    _spi.beginTransaction(_spiSettings);
    _csLow();
    _spiHeader(addr, W5500_CTL_READ(bsb));
    uint8_t val = _spi.transfer(0x00);
    _csHigh();
    _spi.endTransaction();
    return val;
}

uint16_t W5500Raw::_readReg16(uint16_t addr, uint8_t bsb)
{
    _spi.beginTransaction(_spiSettings);
    _csLow();
    _spiHeader(addr, W5500_CTL_READ(bsb));
    uint16_t val = (uint16_t)_spi.transfer(0x00) << 8;
    val |= _spi.transfer(0x00);
    _csHigh();
    _spi.endTransaction();
    return val;
}

void W5500Raw::_readBuf(uint16_t addr, uint8_t bsb, uint8_t *dst, uint16_t len)
{
    _spi.beginTransaction(_spiSettings);
    _csLow();
    _spiHeader(addr, W5500_CTL_READ(bsb));
    for (uint16_t i = 0; i < len; i++) dst[i] = _spi.transfer(0x00);
    _csHigh();
    _spi.endTransaction();
}

void W5500Raw::_writeReg8(uint16_t addr, uint8_t bsb, uint8_t val)
{
    _spi.beginTransaction(_spiSettings);
    _csLow();
    _spiHeader(addr, W5500_CTL_WRITE(bsb));
    _spi.transfer(val);
    _csHigh();
    _spi.endTransaction();
}

void W5500Raw::_writeReg16(uint16_t addr, uint8_t bsb, uint16_t val)
{
    _spi.beginTransaction(_spiSettings);
    _csLow();
    _spiHeader(addr, W5500_CTL_WRITE(bsb));
    _spi.transfer((val >> 8) & 0xFF);
    _spi.transfer(val & 0xFF);
    _csHigh();
    _spi.endTransaction();
}

void W5500Raw::_writeBuf(uint16_t addr, uint8_t bsb, const uint8_t *src, uint16_t len)
{
    _spi.beginTransaction(_spiSettings);
    _csLow();
    _spiHeader(addr, W5500_CTL_WRITE(bsb));
    for (uint16_t i = 0; i < len; i++) _spi.transfer(src[i]);
    _csHigh();
    _spi.endTransaction();
}

// =============================================================================
// Socket 0 helpers
// =============================================================================
void W5500Raw::_execCmd(uint8_t cmd)
{
    _writeReg8(Sn_CR, BSB_S0_REG, cmd);
    // Wait until the command register clears (W5500 clears it when accepted)
    uint32_t t = millis();
    while (_readReg8(Sn_CR, BSB_S0_REG) != 0x00) {
        if (millis() - t > 100) break;
    }
}

uint16_t W5500Raw::_txFree()
{
    // Read twice and compare for stability (W5500 errata workaround)
    uint16_t a, b;
    do {
        a = _readReg16(Sn_TX_FSR, BSB_S0_REG);
        b = _readReg16(Sn_TX_FSR, BSB_S0_REG);
    } while (a != b);
    return a;
}

uint16_t W5500Raw::_rxSize()
{
    uint16_t a, b;
    do {
        a = _readReg16(Sn_RX_RSR, BSB_S0_REG);
        b = _readReg16(Sn_RX_RSR, BSB_S0_REG);
    } while (a != b);
    return a;
}

// =============================================================================
// Ring-buffer TX/RX with wrap-around
// =============================================================================
void W5500Raw::_writeTxBuf(uint16_t startOfs, const uint8_t *src, uint16_t len)
{
    uint16_t end = startOfs + len;
    if (end <= BUF_SIZE) {
        _writeBuf(startOfs, BSB_S0_TX, src, len);
    } else {
        uint16_t firstLen = BUF_SIZE - startOfs;
        _writeBuf(startOfs, BSB_S0_TX, src, firstLen);
        _writeBuf(0, BSB_S0_TX, src + firstLen, len - firstLen);
    }
}

void W5500Raw::_readRxBuf(uint16_t startOfs, uint8_t *dst, uint16_t len)
{
    uint16_t end = startOfs + len;
    if (end <= BUF_SIZE) {
        _readBuf(startOfs, BSB_S0_RX, dst, len);
    } else {
        uint16_t firstLen = BUF_SIZE - startOfs;
        _readBuf(startOfs, BSB_S0_RX, dst, firstLen);
        _readBuf(0, BSB_S0_RX, dst + firstLen, len - firstLen);
    }
}

#pragma once

#include <Arduino.h>
#include <SPI.h>

// =============================================================================
// W5500 Common Register Addresses
// =============================================================================
#define W5500_MR         0x0000   // Mode Register
#define W5500_SHAR       0x0009   // Source Hardware Address (MAC, 6 bytes)
#define W5500_PHYCFGR    0x002E   // PHY Configuration Register
#define W5500_VERSIONR   0x0039   // Chip Version (should read 0x04)

// W5500 PHY Configuration Register bits
#define PHYCFGR_LNK      (1 << 0)  // Link status: 1 = up
#define PHYCFGR_SPD      (1 << 1)  // Speed: 1 = 100 Mbps
#define PHYCFGR_DPX      (1 << 2)  // Duplex: 1 = full

// =============================================================================
// W5500 Socket Register Addresses (relative offset within socket block)
// =============================================================================
#define Sn_MR        0x0000   // Socket Mode
#define Sn_CR        0x0001   // Socket Command
#define Sn_IR        0x0002   // Socket Interrupt
#define Sn_SR        0x0003   // Socket Status
#define Sn_RXBUF_SIZE 0x001E  // RX Buffer Size (KB: 0,1,2,4,8,16)
#define Sn_TXBUF_SIZE 0x001F  // TX Buffer Size (KB: 0,1,2,4,8,16)
#define Sn_TX_FSR    0x0020   // TX Free Size    (2 bytes)
#define Sn_TX_RD     0x0022   // TX Read Pointer (2 bytes)
#define Sn_TX_WR     0x0024   // TX Write Pointer(2 bytes)
#define Sn_RX_RSR    0x0026   // RX Received Size(2 bytes)
#define Sn_RX_RD     0x0028   // RX Read Pointer (2 bytes)
#define Sn_RX_WR     0x002A   // RX Write Pointer(2 bytes, read-only)

// Socket Mode Register values
#define Sn_MR_MACRAW  0x04   // MAC RAW mode (socket 0 only)
#define Sn_MR_MF      0x40   // MAC filter: accept only own MAC + broadcast

// Socket Command values
#define Sn_CR_OPEN    0x01
#define Sn_CR_CLOSE   0x10
#define Sn_CR_SEND    0x20
#define Sn_CR_RECV    0x40

// Socket Status values
#define SOCK_CLOSED   0x00
#define SOCK_MACRAW   0x42

// =============================================================================
// SPI Control Byte construction
// Bits 7:3 = BSB (Block Select Bits)
// Bit  2   = RWB (0=Read, 1=Write)
// Bits 1:0 = OM  (00=VDM variable data length)
// =============================================================================
#define W5500_CTL_READ(bsb)  (((bsb) << 3) | 0x00)
#define W5500_CTL_WRITE(bsb) (((bsb) << 3) | 0x04)

// BSB values
#define BSB_COMMON     0x00   // Common register block
#define BSB_S0_REG     0x01   // Socket 0 register block
#define BSB_S0_TX      0x02   // Socket 0 TX buffer
#define BSB_S0_RX      0x03   // Socket 0 RX buffer
// For socket N: BSB_SN_REG = N*4+1, BSB_SN_TX = N*4+2, BSB_SN_RX = N*4+3

// =============================================================================
// Statistics
// =============================================================================
struct EthStats {
    uint32_t txFrames;
    uint32_t rxFrames;
    uint32_t txBytes;
    uint32_t rxBytes;
    uint32_t txErrors;   // sendFrame() returned false
    uint32_t rxDropped;  // frames discarded (buffer too small)
};

// =============================================================================
// W5500Raw — low-level MACRAW driver for socket 0
// =============================================================================
class W5500Raw {
public:
    W5500Raw(uint8_t csPin, uint8_t rstPin = 255);

    // Initialise SPI and configure W5500 in MACRAW mode.
    // mac: 6-byte source MAC address.
    // Returns true on success (chip version check passed).
    bool begin(const uint8_t mac[6]);

    // Hardware reset (pulls RST low for 10 ms).
    void reset();

    // Returns true if the Ethernet link is up.
    bool isLinked();

    // Returns raw PHYCFGR register value.
    uint8_t phyCfgr();

    // Send one raw Ethernet frame (without FCS; W5500 appends FCS).
    // len: frame length in bytes (ETH_HDR_LEN .. ETH_GIANT_LEN).
    // Returns true on success.
    bool sendFrame(const uint8_t *frame, uint16_t len);

    // Receive one raw Ethernet frame (FCS already stripped by W5500).
    // buf: destination buffer; maxLen: buffer capacity.
    // Returns actual frame length, or 0 if no frame available.
    uint16_t recvFrame(uint8_t *buf, uint16_t maxLen);

    // How many bytes are in the RX buffer (>0 means at least one frame waiting).
    uint16_t rxAvailable();

    EthStats &stats() { return _stats; }
    void clearStats() { memset(&_stats, 0, sizeof(_stats)); }

private:
    uint8_t  _csPin;
    uint8_t  _rstPin;
    EthStats _stats;

    // ---- low-level SPI helpers ----
    inline void _csLow()  { digitalWrite(_csPin, LOW);  }
    inline void _csHigh() { digitalWrite(_csPin, HIGH); }

    uint8_t  _readReg8 (uint16_t addr, uint8_t bsb);
    uint16_t _readReg16(uint16_t addr, uint8_t bsb);
    void     _readBuf  (uint16_t addr, uint8_t bsb, uint8_t *dst, uint16_t len);
    void     _writeReg8 (uint16_t addr, uint8_t bsb, uint8_t val);
    void     _writeReg16(uint16_t addr, uint8_t bsb, uint16_t val);
    void     _writeBuf  (uint16_t addr, uint8_t bsb, const uint8_t *src, uint16_t len);

    // ---- socket 0 helpers ----
    void     _execCmd(uint8_t cmd);
    uint16_t _txFree();
    uint16_t _rxSize();

    // Write to TX buffer with automatic wrap-around (16 KB ring)
    void _writeTxBuf(uint16_t startOfs, const uint8_t *src, uint16_t len);
    // Read from RX buffer with automatic wrap-around (16 KB ring)
    void _readRxBuf (uint16_t startOfs, uint8_t *dst, uint16_t len);
};

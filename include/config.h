#pragma once

// =============================================================================
// Firmware Version
// =============================================================================
#define FW_VERSION  "1.0.3"

// =============================================================================
// Hardware Pin Configuration
// Waveshare ESP32-S3-POE-ETH (onboard WIZnet W5500 over FSPI)
// Pin mapping per Waveshare ESP32-S3-ETH wiki.
// =============================================================================
// Previous hardware: ESP-WROOM32 (VSPI) <-> WIZnet W5500 Lite
//   PIN_W5500_CS    5    // SPI Chip Select  (W5500 /SCS)
//   PIN_W5500_RST  17    // Hardware reset   (W5500 /RESET, active-low)
//   PIN_W5500_INT   4    // Interrupt        (W5500 /INT, not used in polling mode)
//   PIN_SPI_SCK    18    // VSPI SCK
//   PIN_SPI_MISO   19    // VSPI MISO
//   PIN_SPI_MOSI   23    // VSPI MOSI
// =============================================================================
#define PIN_W5500_CS     14      // SPI Chip Select  (W5500 /SCS)
#define PIN_W5500_RST     9      // Hardware reset   (W5500 /RESET, active-low)
#define PIN_W5500_INT    10      // Interrupt        (W5500 /INT,   not used in polling mode)
#define PIN_SPI_SCK      13      // FSPI SCK
#define PIN_SPI_MISO     12      // FSPI MISO
#define PIN_SPI_MOSI     11      // FSPI MOSI
// 8 MHz is reliable over dupont/breadboard wiring. Raise toward 40 MHz only
// once init succeeds and you are on a clean PCB or short wires.
#define W5500_SPI_FREQ   8000000UL    // 8 MHz (W5500 max 80 MHz)

// =============================================================================
// Serial CLI
// =============================================================================
#define CLI_BAUD      115200
#define CLI_BUF_SIZE  256

// =============================================================================
// Default MAC Addresses
// Source MAC: locally administered, unicast (bit 1 of first octet = 1)
// =============================================================================
#define TESTER_MAC_DEF  { 0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC }
#define BROADCAST_MAC   { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

// EtherType used in tester probe frames (IEEE 802 locally assigned test value)
#define ETHERTYPE_TEST   0x88B5
// 802.3x PAUSE frames
#define ETHERTYPE_PAUSE  0x8808
// PAUSE control opcode
#define PAUSE_OPCODE     0x0001

// =============================================================================
// Ethernet Frame Size Constants
// W5500 in MACRAW mode auto-appends 4-byte FCS on TX and strips it on RX.
// All lengths here are WITHOUT FCS (as presented to/from the W5500).
// =============================================================================
#define ETH_HDR_LEN       14     // DA(6) + SA(6) + EtherType(2)
#define ETH_MIN_LEN       60     // Minimum valid frame without FCS (64 - 4)
#define ETH_MAX_LEN      1514    // Maximum standard frame without FCS (1518 - 4)
#define ETH_RUNT_LEN      34     // Runt: 14-byte header + 20-byte payload  => <64 on wire
#define ETH_GIANT_LEN    1604    // Giant: exceeds 1518 on wire
#define ETH_JUMBO_LEN    9000    // Jumbo: valid oversized frame (requires jumbo MTU on DUT)

// Multicast destination used for multicast injection (IPv4 multicast range)
#define INJECT_MCAST_MAC  { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 }

// =============================================================================
// RFC 2544 Test Parameters
// =============================================================================
// Frame sizes mandated by RFC 2544 §9
static const uint16_t RFC2544_SIZES[]   = { 64, 128, 256, 512, 1024, 1280, 1518 };
#define RFC2544_NUM_SIZES   7
#define RFC2544_TEST_SEC   10    // Test duration per size (use 60 for full compliance)
#define RFC2544_SEARCH_N   10    // Binary search iterations for throughput test
// Throughput: acceptable loss count (0 = zero frame loss)
#define RFC2544_LOSS_MAX    0

// =============================================================================
// Latency Probe Frame Format (payload offsets, without FCS)
// [0..3]  MAGIC (0xC0FFEE01)
// [4..11] Send timestamp (µs, uint64_t, big-endian)
// [12..]  Padding (0xAB)
// =============================================================================
#define PROBE_MAGIC       0xC0FFEE01UL
#define LATENCY_SAMPLES   100

// =============================================================================
// TF (micro-SD) Card SPI Pins
// Waveshare ESP32-S3-POE-ETH onboard TF card slot (separate SPI bus from W5500)
// =============================================================================
#define PIN_SD_CS       4
#define PIN_SD_MOSI     6
#define PIN_SD_MISO     5
#define PIN_SD_SCK      7

// =============================================================================
// Power Latch / Button
// POWER_EN high keeps the system powered via its own latch; the button
// supplies temporary power while pressed and reads low.
// =============================================================================
#define PIN_POWER_EN      39    // HIGH = hold system power on, LOW = release
#define PIN_POWER_BUTTON  38    // Power button, active-low (press = temporary power)
#define POWER_ON_HOLD_MS  2000  // Hold to latch power on
#define POWER_OFF_HOLD_MS 3000  // Hold to release latch (power off)

// Status LED, active-low (LOW = lit)
#define PIN_STATUS_LED    2
#define LED_BLINK_MS      500   // Blink half-period while powered on

// =============================================================================
// Battery Monitor (single-cell Li-ion, 4.2 V max)
// VBAT --[0.5 divider]--> PIN_BAT_ADC;  charge detect HIGH = charging
// =============================================================================
#define PIN_BAT_ADC        1      // ADC1_CH0
#define BAT_DIVIDER_RATIO  0.5f   // Vadc = Vbat * 0.5 -> Vbat = Vadc * 2
#define PIN_CHG_DETECT     40     // input pull-down; HIGH while charging
#define BAT_FULL_MV        4200
#define BAT_EMPTY_MV       3300
#define BAT_CUTOFF_MV      3300   // auto power-off threshold
#define BAT_CUTOFF_COUNT   3      // consecutive 1 Hz samples below threshold

// =============================================================================
// Display: 1.3" 128x64 SH1106 over I2C (SA0 pulled down -> 0x3C)
// =============================================================================
#define DISPLAY_I2C_SDA   41
#define DISPLAY_I2C_SCL   42
#define DISPLAY_I2C_ADDR  0x3C
#define DISPLAY_WIDTH     128
#define DISPLAY_HEIGHT    64
// 1 MHz overclock (SH1106 datasheet max is 400 kHz). Boot falls back through
// 400 kHz / 100 kHz if the panel does not ACK. Runtime tuning: display speed <hz>
#define DISPLAY_I2C_FREQ        1000000UL
#define DISPLAY_I2C_FREQ_FALLBACK 400000UL
#define DISPLAY_REFRESH_MS      1000    // Status page refresh period
#define DISPLAY_COL_OFFSET      2       // SH1106 has 132-column RAM; visible area starts at col 2
#define DISPLAY_CONTRAST        0x80

// =============================================================================
// Error Injection Defaults
// =============================================================================
#define INJECT_DEFAULT_COUNT   100     // Frames to send when no count specified
#define STORM_MAX_RATE_HZ     50000   // Hard cap on storm injection rate

# ESP32 Ethernet Tester

A bench tool for stress-testing and validating Ethernet switch ports (built and
tuned against an Aruba CX6300). An ESP-WROOM-32 drives a WIZnet **W5500 Lite**
in raw MAC (MACRAW) mode, giving full control over the frames placed on the
wire. A minimal IPv4 stack layered on top adds L3/DHCP testing, and an optional
Wi-Fi web interface provides remote control.

> **Hardware note (FCS):** In MACRAW mode the W5500 auto-calculates and appends
> the 4-byte FCS, and auto-pads short frames to the 60-byte minimum. As a
> result, **true CRC error injection and true runt injection are not possible**
> through this hardware. See [Limitations](#limitations).

---

## Contents
- [Features](#features)
- [Hardware](#hardware)
- [Wiring](#wiring)
- [Build & Flash](#build--flash)
- [Serial CLI Reference](#serial-cli-reference)
- [Wi-Fi & Web Interface](#wi-fi--web-interface)
- [L3 / DHCP Testing](#l3--dhcp-testing)
- [LLDP / CDP](#lldp--cdp)
- [RFC 2544 Suite](#rfc-2544-suite)
- [Architecture](#architecture)
- [Configuration (NVS)](#configuration-nvs)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

---

## Features

| Area | Capability |
|------|-----------|
| **Raw frame TX/RX** | Arbitrary Ethernet frames via W5500 MACRAW (socket 0, no MAC filter) |
| **Error injection** | Giant, jumbo, bad-EtherType, broadcast, multicast, PAUSE, payload patterns, broadcast storm |
| **Continuous mode** | Sustained error stream of any injectable type at a configurable rate |
| **RFC 2544** | Throughput, latency, frame-loss, back-to-back (requires DUT loopback) |
| **LLDP / CDP** | Passive neighbour discovery (decode) **and** configurable advertisement (TX) |
| **L3 / IP** | Minimal ARP/IP/UDP/ICMP stack; ping; static or DHCP addressing |
| **DHCP testing** | Full DORA verification plus six failure/abuse scenarios |
| **mDNS probe** | Resolve `<host>.local` over multicast DNS and ping for reachability |
| **Wi-Fi web UI** | STA auto-connect (NVS creds) with AP fallback; async control page + JSON API |
| **Persistence** | Wi-Fi credentials, hostname, and IP config stored in NVS |

---

## Hardware

| Item | Detail |
|------|--------|
| MCU | ESP-WROOM-32 dev board (USB, 3.3 V regulator on board) |
| Ethernet | WIZnet **W5500 Lite** module (3.3 V only — **no onboard regulator**) |
| Interface | VSPI @ 8 MHz (see note below) |

> The W5500 Lite is a **3.3 V-only** board. Power it from the ESP32 **3V3**
> pin, *not* 5V/VIN. The SPI clock is set to **8 MHz** in
> [include/config.h](include/config.h) for reliable operation over
> dupont/breadboard wiring; raise toward 40 MHz only on short wires or a clean
> PCB.

---

## Wiring

W5500 Lite ⟷ ESP-WROOM-32 (pins defined in [include/config.h](include/config.h)):

| W5500 Lite pin | ESP32 GPIO | Notes |
|----------------|------------|-------|
| 3V3 (×2)       | 3V3        | Both 3V3 pins to 3.3 V |
| GND (×2 + ×2)  | GND        | Tie all grounds together |
| MOSI           | 23         | VSPI MOSI |
| MISO           | 19         | VSPI MISO |
| SCLK           | 18         | VSPI SCK |
| CS             | 5          | Chip select |
| RST            | 17         | Hardware reset (moved off GPIO2 strapping pin) |
| INT            | 4          | Not used in polling mode |
| NC             | —          | Leave unconnected |

```
 ESP32                      W5500 Lite
 ┌──────────┐               ┌──────────┐
 │ 3V3 ─────┼───────────────┤ 3V3 ×2   │
 │ GND ─────┼───────────────┤ GND ×4   │
 │ G23 MOSI ┼──────────────►│ MOSI     │
 │ G19 MISO │◄──────────────┤ MISO     │
 │ G18 SCK  ┼──────────────►│ SCLK     │
 │ G5  CS   ┼──────────────►│ CS       │
 │ G17 RST  ┼──────────────►│ RST      │
 └──────────┘               └──────────┘
```

---

## Build & Flash

This is a [PlatformIO](https://platformio.org/) project
([platformio.ini](platformio.ini), `board = esp32dev`, Arduino framework).

```bash
# Build
pio run

# Build, upload, and open the serial monitor (115200 baud)
pio run --target upload
pio device monitor -b 115200
```

Library dependencies (fetched automatically): `mathieucarbou/ESPAsyncWebServer`.

On boot the device prints W5500 init status, link state, attempts Wi-Fi (if
enabled), and presents the `ETH>` prompt.

---

## Serial CLI Reference

Connect at **115200 baud**. Type `help` (or `?`) for the live list. Commands are
case-insensitive.

### General
| Command | Description |
|---------|-------------|
| `status` | Link state, PHY info, MACs, modes |
| `stats` | TX/RX counters |
| `stats clear` | Reset counters |
| `mac <XX:XX:XX:XX:XX:XX>` | Set source MAC |
| `target <XX:XX:XX:XX:XX:XX>` | Set destination MAC |
| `loopback on\|off` | Reflector mode (echo RX back to sender) |
| `send <count> [size]` | Send `count` test frames of `size` bytes |

### Error Injection
| Command | Description |
|---------|-------------|
| `inject runt [count]` | Runt frames — **see limitation**; W5500 pads to 64 B so the DUT will *not* count these as runts |
| `inject giant [count]` | Giant frames (>1518 B on wire) |
| `inject jumbo [count [size]]` | Jumbo frames (default 9000 B; needs jumbo MTU enabled on the DUT) |
| `inject broadcast [count]` | Frames to `FF:FF:FF:FF:FF:FF` |
| `inject multicast [count]` | Frames to `01:00:5E:00:00:01` |
| `inject badtype [count]` | Reserved/undefined EtherType (`0x88B6`) |
| `inject pause [count [quanta]]` | 802.3x PAUSE frames |
| `inject pattern <pat> [len] [n]` | Stress pattern: `zeros\|ones\|alt\|incr\|random` |
| `inject storm <rate_hz>` | Background broadcast storm (`0` to stop) |
| `inject continuous <type> <rate_hz> [size]` | Continuous error stream; type = `giant\|jumbo\|badtype\|broadcast\|multicast\|pause\|pattern` |
| `inject continuous stop` | Stop continuous injection |
| `inject stop` | Stop both storm and continuous injection |

### RFC 2544 (requires DUT port loopback)
| Command | Description |
|---------|-------------|
| `test throughput [size]` | Zero-loss throughput (binary search) |
| `test latency [size]` | Round-trip latency |
| `test frameloss [size]` | Frame loss at 100/50/10 % load |
| `test backtoback [size]` | Max burst without loss |
| `test all` | Full RFC 2544 suite across all mandated frame sizes |

### Neighbour Discovery / Advertisement
| Command | Description |
|---------|-------------|
| `discover [seconds]` | Listen for and decode LLDP/CDP neighbours (default 65 s) |
| `advertise` | Show advertisement config |
| `advertise lldp on\|off` | Toggle LLDP advertisement |
| `advertise cdp on\|off` | Toggle CDP advertisement |
| `advertise name <string>` | System name / device ID |
| `advertise port <string>` | Port ID |
| `advertise platform <string>` | Platform / description string |
| `advertise ip <a.b.c.d>` | Management IPv4 (`0.0.0.0` = none) |
| `advertise vlan <id>` | Port / native VLAN (`0` = none) |
| `advertise ttl <seconds>` | Advertised TTL |
| `advertise interval <seconds>` | Transmit interval |
| `advertise off` | Disable both LLDP and CDP |

### L3 / IP Testing
| Command | Description |
|---------|-------------|
| `ip show` | Show IP stack address config |
| `ip dhcp` | Obtain address via DHCP (DORA) and apply it |
| `ip static <ip> <mask> <gw>` | Set and persist a static IPv4 address |
| `dhcp discover` | Full DORA exchange (verify a server) |
| `dhcp detect` | Server presence / server-down detection |
| `dhcp flood [count]` | Starvation / pool-exhaustion test (unique random MACs) |
| `dhcp decline` | OFFER then DECLINE (address-conflict simulation) |
| `dhcp nak [ip]` | Request a bogus IP, expect NAK |
| `dhcp malformed` | Send a malformed DISCOVER, expect the server to ignore it |
| `dhcp renew [secs]` | Short lease, then unicast renew |
| `probe <hostname>` | Resolve `<name>.local` via mDNS and ping it |

### Wi-Fi / Web (persisted to NVS)
| Command | Description |
|---------|-------------|
| `wifi` | Show Wi-Fi status |
| `wifi ssid <ssid>` | Set SSID |
| `wifi pass <password>` | Set password |
| `wifi on\|off` | Enable/disable Wi-Fi on boot |
| `host <hostname>` | Set device hostname (used by the mDNS responder) |

> Wi-Fi/host changes are saved immediately but applied on the next **reboot**.

---

## Wi-Fi & Web Interface

Implemented in [src/wifi_web.cpp](src/wifi_web.cpp).

1. **STA auto-connect:** if Wi-Fi is enabled and credentials exist in NVS, the
   device connects as a station on boot and registers `<hostname>.local` via
   mDNS (`ESPmDNS`).
2. **AP fallback:** if no credentials exist or the connection fails, it starts
   an open AP named **`ESP32-Tester-Setup`** hosting the same control page so
   credentials can be entered.

### Web UI
Browse to `http://<hostname>.local/` (STA) or the AP IP (fallback). The page
provides:
- **Status** — auto-refreshing link/speed/duplex, MAC, IP config, counters, and
  injection state (polls `/api/status`).
- **Error injection** — one-shot and continuous controls.
- **DHCP test** — buttons for every DHCP scenario.
- **Reachability probe** — resolve + ping a `.local` host.
- **Configuration** — set Wi-Fi SSID/password/hostname (saved to NVS).

### HTTP API
| Method | Path | Body | Purpose |
|--------|------|------|---------|
| `GET`  | `/` | — | Control page (HTML) |
| `GET`  | `/api/status` | — | JSON status object |
| `POST` | `/api/cmd` | `c=<command>` | Queue a CLI command for execution |
| `POST` | `/api/config` | `ssid,pass,host,wifi` | Save Wi-Fi config to NVS |

Commands received over HTTP are **queued and executed from the main loop** so
the async server callbacks never block; detailed command output appears on the
serial console.

---

## L3 / DHCP Testing

A deliberately minimal IPv4 stack ([src/ip_stack.cpp](src/ip_stack.cpp)) runs on
top of MACRAW — the W5500 hardware TCP/IP stack is **not** used, preserving full
raw-frame control. It implements:
- **ARP** (request/reply + an 8-entry cache; answers ARP for our IP)
- **IPv4** (header build + Internet checksum)
- **UDP** (send/receive with pseudo-header checksum)
- **ICMP** (echo request/reply — `ping`, and replies to inbound pings)
- Destination MAC resolution for broadcast, IPv4 multicast mapping, and on/off-subnet unicast (via ARP)

### DHCP scenarios
[src/dhcp_test.cpp](src/dhcp_test.cpp):

| Scenario | What it validates |
|----------|-------------------|
| `discover` (DORA) | Server hands out a lease correctly (OFFER → REQUEST → ACK) |
| `detect` | Whether *any* server answers (server-down detection) |
| `flood` | Pool exhaustion / starvation behaviour (unique client MAC per DISCOVER) |
| `decline` | Server marks an address conflicted after DECLINE |
| `nak` | Server correctly NAKs a request for an out-of-pool/bogus IP |
| `malformed` | Server ignores a packet with a bad magic cookie + truncated options |
| `renew` | Renew/rebind handling via a short lease + unicast renew |

---

## LLDP / CDP

[src/discovery.cpp](src/discovery.cpp) provides both directions:

- **Listen (`discover`)** — decodes LLDP (EtherType `0x88CC`) and CDP
  (`01:00:0C:CC:CC:CC`, LLC/SNAP) PDUs the switch emits: system name, port,
  TTL, capabilities, management address, VLAN, platform, etc.
- **Advertise (`advertise`)** — builds and periodically transmits configurable
  LLDP and CDP PDUs. CDP uses proper LLC/SNAP encapsulation and Cisco's
  sign-extending checksum.

---

## RFC 2544 Suite

[src/rfc2544.cpp](src/rfc2544.cpp) implements the four core benchmarks
(throughput, latency, frame-loss, back-to-back) per RFC 2544. These require the
DUT to **reflect frames** back to the tester. Two options:

- **Port loopback (one cable):** `interface 1/1/X` → `loopback` on the CX6300.
- **Cable loop (two cables):** connect port A to the tester and loop port B back
  to port A.

Frame sizes and durations are configured in [include/config.h](include/config.h)
(`RFC2544_SIZES`, `RFC2544_TEST_SEC`, etc.).

---

## Architecture

```
                       ┌─────────────────────────────────────────────┐
                       │                  main.cpp                    │
                       │  setup(): init, NVS load, Wi-Fi, web         │
                       │  loop():  CLI · inj.tick · loopback ·         │
                       │           advertise · web                    │
                       └───────────────┬─────────────────────────────┘
                                       │
        ┌───────────┬───────────┬──────┴──────┬────────────┬───────────┐
        ▼           ▼           ▼             ▼            ▼           ▼
   ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐
   │   CLI   │ │ Error   │ │ RFC2544  │ │ Discovery│ │ IpStack │ │WebControl│
   │ (cli)   │ │ Inject  │ │          │ │ LLDP/CDP │ │ ARP/IP/ │ │ WiFi +   │
   │         │ │         │ │          │ │          │ │ UDP/ICMP│ │ Async UI │
   └────┬────┘ └────┬────┘ └────┬─────┘ └────┬─────┘ └────┬────┘ └────┬─────┘
        │           │           │            │            │           │
        │           │           │            │       ┌────▼─────┐     │
        │           │           │            │       │ DhcpTest │     │
        │           │           │            │       │ NetProbe │     │
        │           │           │            │       └────┬─────┘     │
        └───────────┴───────────┴────────────┴────────────┘           │
                                 │                                     │
                          ┌──────▼───────┐                    ┌────────▼────────┐
                          │   W5500Raw   │                    │   NetConfig     │
                          │ MACRAW / SPI │                    │   (NVS / Prefs) │
                          └──────────────┘                    └─────────────────┘
```

| File | Responsibility |
|------|----------------|
| [src/main.cpp](src/main.cpp) | Wiring, boot sequence, main loop |
| [src/w5500_raw.cpp](src/w5500_raw.cpp) | Low-level W5500 MACRAW SPI driver (socket 0) |
| [src/packet.cpp](src/packet.cpp) | Ethernet frame builders, patterns, MAC helpers |
| [src/error_inject.cpp](src/error_inject.cpp) | One-shot, storm, and continuous injectors |
| [src/rfc2544.cpp](src/rfc2544.cpp) | RFC 2544 benchmark suite |
| [src/discovery.cpp](src/discovery.cpp) | LLDP/CDP decode + advertisement |
| [src/ip_stack.cpp](src/ip_stack.cpp) | Minimal ARP/IP/UDP/ICMP over MACRAW |
| [src/dhcp_test.cpp](src/dhcp_test.cpp) | DHCP DORA + failure scenarios |
| [src/net_probe.cpp](src/net_probe.cpp) | mDNS resolve + ping reachability |
| [src/net_config.cpp](src/net_config.cpp) | NVS persistence (Preferences) |
| [src/wifi_web.cpp](src/wifi_web.cpp) | Wi-Fi STA/AP + ESPAsyncWebServer UI |
| [src/cli.cpp](src/cli.cpp) | Serial command parser and dispatch |
| [include/config.h](include/config.h) | Pins, constants, defaults |

---

## Configuration (NVS)

Persisted via the `Preferences` library in the **`tester`** namespace
([src/net_config.cpp](src/net_config.cpp)):

| Key | Field | Default |
|-----|-------|---------|
| `ssid` | Wi-Fi SSID | (empty) |
| `pass` | Wi-Fi password | (empty) |
| `host` | Hostname (`<host>.local`) | `esp32-tester` |
| `wifiEn` | Connect Wi-Fi on boot | `false` |
| `dhcp` | Use DHCP for the Ethernet IP | `true` |
| `ip` / `mask` / `gw` | Static IPv4 config | `0` / `255.255.255.0` / `0` |

---

## Limitations

These stem from the W5500 hardware operating in MACRAW mode:

- **No CRC/FCS error injection.** The W5500 always computes and appends a valid
  FCS; corrupted-CRC frames require a hardware bit manipulator.
- **No true runts.** Frames shorter than 60 bytes are auto-padded to the
  60-byte minimum before FCS, so they leave the wire at the legal 64-byte
  minimum. The `inject runt` command is retained but prints a warning and the
  DUT will not count the frames as runts.
- **Jumbo frames** require jumbo MTU to be enabled on the DUT port; otherwise
  they are dropped or counted as giants.
- The minimal IP stack is intentionally lightweight (no fragmentation, single
  outstanding request per exchange) — sufficient for testing, not a general
  purpose stack.

---

## Troubleshooting

### W5500 init fails — `Version check failed`
The driver reads the W5500 version register (expected `0x04`). The value read is
diagnostic:

| Read value | Likely cause |
|------------|--------------|
| `0x7F` or random | SPI returning garbage — usually the **MISO** line (loose/long/swapped) or clock too fast. The clock is already at 8 MHz; recheck MISO ↔ GPIO19. |
| `0x00` | MISO delivering no data — MISO disconnected, **no 3.3 V power**, or CS not reaching the chip. Verify 3V3/GND on the module and CS ↔ GPIO5. |
| `0xFF` | MISO stuck high / module unpowered or absent. |

Checklist, in order:
1. **Power** — the W5500 Lite is **3.3 V only**; feed it from 3V3 (not 5V).
   It draws ~130 mA; a brownout corrupts SPI.
2. **MISO** — most common culprit; reseat GPIO19 ↔ MISO, confirm not swapped
   with MOSI.
3. **CS / RST** — CS ↔ GPIO5, RST ↔ GPIO17 (kept off the GPIO2 strapping pin).
4. **Clock** — already 8 MHz in [include/config.h](include/config.h); keep wires
   short.

### Web UI not reachable
- In STA mode, confirm the device connected (serial prints the IP) and try the
  IP directly if `<hostname>.local` mDNS resolution fails.
- In AP fallback mode, join **`ESP32-Tester-Setup`** and browse to the AP IP
  printed on the console.

### DHCP / probe commands do nothing useful
These depend on the W5500 being initialised and the link being up. Resolve any
W5500 init failure first, then confirm `status` shows **Link: UP**.

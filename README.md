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
- [802.1X / EAP Authentication](#8021x--eap-authentication)
- [LLDP / CDP](#lldp--cdp)
- [FHRP (HSRP / VRRP)](#fhrp-hsrp--vrrp)
- [DHCPv6](#dhcpv6)
- [DNS Tools](#dns-tools)
- [SNMP Recon](#snmp-recon)
- [Rogue Authenticator](#rogue-authenticator)
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
| **DHCP testing** | Full DORA verification plus six failure/abuse scenarios + rogue server |
| **DHCPv6** | Stateful IPv6 server discovery (SOLICIT) and rogue DHCPv6 server |
| **DNS** | Unicast DNS A-record resolution and rogue DNS responder (spoof) |
| **mDNS probe** | Resolve `<host>.local` over multicast DNS and ping for reachability |
| **802.1X / EAP** | Full supplicant: EAP-MD5, EAP-TLS, PEAPv0/MSCHAPv2, EAP-TTLS (PAP + MSCHAPv2) |
| **Rogue authenticator** | Fake 802.1X authenticator to harvest EAP-MD5 / MSCHAPv2 credentials |
| **EAPOL attacks** | Start-flood, spoofed logoff, MAB probe |
| **IPv6 / NDP** | Passive NDP decode (RS/RA/NS/NA) and rogue Router Advertisement (SLAAC takeover) |
| **FHRP (HSRP/VRRP)** | Passive decode of HSRP/VRRP advertisements + gateway hijack |
| **L2 attacks** | 802.1Q VLAN inject, Q-in-Q hop, DTP spoof, CAM flood, STP root/TCN, LLDP/CDP flood |
| **ARP tools** | Gratuitous ARP, ARP MITM spoof, ARP storm, ARP scan |
| **SNMP recon** | Community-string probe (sysDescr) and IP-range sweep |
| **Port scanning** | TCP SYN scan, banner grab, common-port scan |
| **Reconnaissance** | Passive host/protocol mapping, ICMP ping sweep, traceroute |
| **PCAP capture** | Capture frames to LittleFS file, downloadable from web UI |
| **Wi-Fi web UI** | STA auto-connect (NVS creds) with AP fallback; async control page + JSON API |
| **Persistence** | Wi-Fi credentials, hostname, IP config, 802.1X creds stored in NVS |

---

## Hardware

| Item | Detail |
|------|--------|
| MCU | Waveshare **ESP32-S3-POE-ETH** (ESP32-S3, USB-C, 16 MB flash, 8 MB PSRAM) |
| Ethernet | Onboard WIZnet **W5500** (PoE-capable carrier) |
| Interface | FSPI @ 8 MHz (see note below) |

> Ethernet, W5500 power, and (optional) PoE are all onboard — no external
> wiring is required. The SPI clock is set to **8 MHz** in
> [include/config.h](include/config.h); it can be raised toward 40 MHz since
> the W5500 is connected over short onboard PCB traces.

---

## Wiring

The W5500 is integrated on the Waveshare ESP32-S3-POE-ETH board, so no external
Ethernet wiring is needed. The onboard SPI mapping (defined in
[include/config.h](include/config.h)) is:

| W5500 signal | ESP32-S3 GPIO | Notes |
|--------------|---------------|-------|
| MOSI         | 11            | FSPI MOSI |
| MISO         | 12            | FSPI MISO |
| SCLK         | 13            | FSPI SCK |
| CS           | 14            | Chip select |
| RST          | 9             | Hardware reset |
| INT          | 10            | Not used in polling mode |

---

## Build & Flash

This is a [PlatformIO](https://platformio.org/) project
([platformio.ini](platformio.ini), `board = esp32-s3-devkitc-1`, Arduino framework).

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
| `dns resolve <host> [server]` | Unicast DNS A-record query (uses gateway if no server given) |

### 802.1X / EAP (EAPOL Supplicant)
| Command | Description |
|---------|-------------|
| `dot1x` | Show 802.1X method / credential status |
| `dot1x method md5\|tls\|peap\|ttls-pap\|ttls-mschap` | Select EAP method |
| `dot1x probe` | Detect whether the port enforces 802.1X |
| `dot1x auth [user] [pass]` | Authenticate with the selected method |
| `dot1x user <name>` | Set 802.1X identity (saved) |
| `dot1x pass <password>` | Set EAP password (saved) |
| `dot1x keypass <pw>` | Set EAP-TLS private-key passphrase (saved) |
| `dot1x cert [clear ...]` | Show / remove uploaded certificates |
| `dot1x logoff` | Send EAPOL-Logoff |

### Reconnaissance
| Command | Description |
|---------|-------------|
| `recon passive [secs]` | Passively map hosts/protocols (default 30 s) |
| `recon sweep <start> <end>` | ICMP ping sweep of an address range |
| `recon trace <ip> [maxhops]` | ICMP traceroute to a target |
| `arp scan <start> <end>` | ARP sweep for live hosts (L2 discovery) |
| `scan common <ip>` | TCP SYN scan of common ports |
| `scan ports <ip> <first> <last>` | TCP SYN scan of a port range |
| `scan banner <ip> <port> [probe]` | Banner grab via full TCP handshake |
| `link [monitor [secs]]` | Link speed/duplex info or flap monitor |
| `wifi scan` | Scan Wi-Fi (rogue-AP / evil-twin recon) |
| `ipv6 listen [secs]` | Decode IPv6 NDP (RS/RA/NS/NA) |
| `fhrp listen [secs]` | Decode HSRP/VRRP advertisements |
| `dhcpv6 probe [secs]` | Discover DHCPv6 servers (SOLICIT) |
| `snmp probe <ip>` | SNMP community-string probe (tries public/private/community/admin/snmp/monitor) |
| `snmp sweep <start> <end> [comm]` | SNMP sweep of an IP range |
| `pcap start [secs] [maxframes]` | Capture frames to `/capture.pcap` (web download) |
| `pcap status \| delete` | Show or remove the stored capture |

### Offensive / DoS Tests (require `arm`)
| Command | Description |
|---------|-------------|
| `arm [on]` | Show or enable authorized (lab) mode |
| `disarm` | Disable authorized mode |
| `l2 vlan <vid> [pcp] [count]` | 802.1Q single-tag VLAN inject |
| `l2 dtag <native> <target> [n]` | Double-tag (Q-in-Q) VLAN hop |
| `l2 dtp` | DTP trunk-negotiation spoof |
| `l2 macflood [count] [rate]` | CAM-table flood (random MACs) |
| `l2 stp listen [secs]` | Decode STP/RSTP BPDUs |
| `l2 stp root [prio] [secs]` | Claim root bridge (BPDU/Root Guard test) |
| `l2 stp tcn [count]` | Inject topology-change BPDUs |
| `l2 lldpflood [count]` | LLDP neighbour-table flood |
| `l2 cdpflood [count]` | CDP neighbour-table flood |
| `arp gratuitous <ip> [count]` | Gratuitous ARP announce |
| `arp spoof <victim> <gw> [secs]` | ARP MITM (auto-restores on stop) |
| `arp storm [count] [rate]` | ARP request flood |
| `ipv6 rogue [lifetime] [count]` | Rogue Router Advertisement (SLAAC takeover) |
| `fhrp hsrp <grp> <vip> [prio] [n]` | HSRP gateway hijack |
| `fhrp vrrp <vrid> <vip> [prio] [n]` | VRRP master hijack |
| `dhcpv6 rogue <prefix> <dns> [s]` | Rogue DHCPv6 server (stateful IPv6) |
| `dns spoof <ip> [secs]` | DNS spoof (answer all queries with `<ip>`) |
| `dhcp rogue <pool> [mask gw dns secs]` | Rogue DHCP server (hands out leases) |
| `dot1x startflood [count]` | EAPOL-Start flood (random MACs) |
| `dot1x logoffmac <mac>` | Spoofed EAPOL-Logoff (deauth a client) |
| `dot1x mab [secs]` | MAB / 802.1X enforcement probe |
| `dot1x rogue [secs] [md5]` | Rogue authenticator (harvest EAP credentials) |

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

## 802.1X / EAP Authentication

[src/dot1x.cpp](src/dot1x.cpp) implements a full 802.1X supplicant supporting
multiple EAP methods:

| Method | Description |
|--------|-------------|
| **EAP-MD5** | Simple challenge/response (username + password) |
| **EAP-TLS** | Certificate-based mutual authentication (RFC 5216); client cert + key uploaded via web UI |
| **PEAPv0/MSCHAPv2** | TLS tunnel with inner EAP-MSCHAPv2 (RFC 2759); most common enterprise Wi-Fi/wired auth |
| **EAP-TTLS/PAP** | TLS tunnel with inner PAP (cleartext inside tunnel, RFC 5281) |
| **EAP-TTLS/MSCHAPv2** | TLS tunnel with inner MS-CHAPv2 via Diameter AVPs |

The TLS engine uses mbedTLS (ESP-IDF); fragmented EAP-TLS exchange is handled
per RFC 5216. Certificates are stored in LittleFS and managed via the web UI or
`dot1x cert` CLI commands.

---

## FHRP (HSRP / VRRP)

[src/fhrp.cpp](src/fhrp.cpp) provides First-Hop Redundancy Protocol assessment:

- **Listen (`fhrp listen`)** — passively sniffs and decodes HSRP (UDP/1985) and
  VRRP (IP protocol 112) advertisements, revealing group IDs, virtual IPs,
  priorities, and state.
- **HSRP hijack (`fhrp hsrp`)** — sends HSRP Coup + Hello frames with priority
  255 using the HSRP virtual MAC (`00:00:0c:07:ac:GG`), taking over the default
  gateway. Tests HSRP authentication and FHRP hardening.
- **VRRP hijack (`fhrp vrrp`)** — sends VRRP advertisements with max priority
  using the VRRP virtual MAC (`00:00:5e:00:01:VR`), taking over the master role.

---

## DHCPv6

[src/dhcpv6.cpp](src/dhcpv6.cpp) implements stateful IPv6 address assignment
testing per RFC 8415:

- **Probe (`dhcpv6 probe`)** — sends SOLICIT and decodes ADVERTISE/REPLY,
  revealing the server DUID, offered IPv6 address, and DNS servers.
- **Rogue server (`dhcpv6 rogue`)** — answers SOLICIT/REQUEST with
  ADVERTISE/REPLY, handing out addresses from a specified /64 prefix and
  advertising a controlled DNS server. Tests DHCPv6 guard/snooping.

---

## DNS Tools

[src/dns_tool.cpp](src/dns_tool.cpp) provides DNS assessment capabilities:

- **Resolve (`dns resolve`)** — unicast DNS A-record query to a specified server
  (or the configured gateway). ARP-resolves the target, sends a standard DNS
  query, and parses the response.
- **Spoof (`dns spoof`)** — rogue DNS responder that monitors the wire for DNS
  queries (UDP/53) and injects forged replies redirecting all queried names to a
  controlled IP. Tests DNS inspection / DNSSEC enforcement.

---

## SNMP Recon

[src/snmp_recon.cpp](src/snmp_recon.cpp) performs SNMP reconnaissance:

- **Probe (`snmp probe`)** — sends SNMPv1 GET requests for `sysDescr.0`
  (OID 1.3.6.1.2.1.1.1.0) using common community strings (`public`, `private`,
  `community`, `admin`, `snmp`, `monitor`). Reports any accepted community and
  the device description.
- **Sweep (`snmp sweep`)** — probes an IP range (up to 1024 hosts) with a given
  community string, identifying all SNMP-responsive devices.

---

## Rogue Authenticator

[src/rogue_auth.cpp](src/rogue_auth.cpp) implements a fake 802.1X authenticator
for credential harvesting (authorized pentest use):

- Broadcasts EAP-Request/Identity to solicit supplicants (or responds to
  EAPOL-Start frames)
- Challenges with EAP-MD5 or EAP-MSCHAPv2 (configurable)
- Captures and displays:
  - Outer identity (often the real username)
  - EAP-MD5 challenge/response pairs
  - MS-CHAPv2 auth-challenge / peer-challenge / NT-Response
- Outputs MS-CHAPv2 hashes in **hashcat mode 5500** format for offline cracking
- Tracks up to 8 concurrent supplicants

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
| [src/dhcp_test.cpp](src/dhcp_test.cpp) | DHCP DORA + failure scenarios + rogue server |
| [src/dhcpv6.cpp](src/dhcpv6.cpp) | DHCPv6 client probe + rogue server (RFC 8415) |
| [src/dns_tool.cpp](src/dns_tool.cpp) | Unicast DNS resolver + rogue DNS responder |
| [src/snmp_recon.cpp](src/snmp_recon.cpp) | SNMPv1 community-string probe + sweep |
| [src/net_probe.cpp](src/net_probe.cpp) | mDNS resolve + ping reachability |
| [src/dot1x.cpp](src/dot1x.cpp) | 802.1X supplicant (MD5/TLS/PEAP/TTLS) + EAPOL attacks |
| [src/rogue_auth.cpp](src/rogue_auth.cpp) | Rogue 802.1X authenticator / EAP credential harvester |
| [src/mschapv2.cpp](src/mschapv2.cpp) | MS-CHAPv2 crypto (self-contained MD4 + DES) |
| [src/cert_store.cpp](src/cert_store.cpp) | LittleFS certificate storage for EAP-TLS |
| [src/l2_attack.cpp](src/l2_attack.cpp) | L2 attack suite (VLAN/DTP/STP/MAC-flood/LLDP-CDP flood) |
| [src/arp_tool.cpp](src/arp_tool.cpp) | ARP scan, gratuitous, spoof, storm |
| [src/fhrp.cpp](src/fhrp.cpp) | FHRP assessment (HSRP/VRRP listen + hijack) |
| [src/ipv6_tool.cpp](src/ipv6_tool.cpp) | IPv6 NDP listen + rogue RA |
| [src/portscan.cpp](src/portscan.cpp) | TCP SYN scan + banner grab |
| [src/recon.cpp](src/recon.cpp) | Passive recon, ping sweep, traceroute |
| [src/linkdiag.cpp](src/linkdiag.cpp) | Link diagnostics + flap monitor |
| [src/pcap.cpp](src/pcap.cpp) | PCAP capture to LittleFS |
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

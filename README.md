# ESP32 Ethernet Tester

A bench tool for stress-testing and validating Ethernet switch ports (built and
tuned against an Aruba CX6300). An ESP32-S3 drives a WIZnet **W5500** in raw
MAC (MACRAW) mode, giving full control over the frames placed on the wire. A
minimal IPv4 stack layered on top adds L3/DHCP testing, and a Wi-Fi web
interface provides remote control with a tabbed multi-panel UI.

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
- [Quick-Start Tutorial](#quick-start-tutorial)
- [Serial CLI Reference](#serial-cli-reference)
- [Wi-Fi & Web Interface](#wi-fi--web-interface)
- [L3 / DHCP Testing](#l3--dhcp-testing)
- [802.1X / EAP Authentication](#8021x--eap-authentication)
- [LLDP / CDP](#lldp--cdp)
- [FHRP (HSRP / VRRP)](#fhrp-hsrp--vrrp)
- [DHCPv6](#dhcpv6)
- [DNS Tools](#dns-tools)
- [SNMP Recon](#snmp-recon)
- [Port Scanning & Banner Grab](#port-scanning--banner-grab)
- [Network Assessment](#network-assessment)
- [MAC Randomization](#mac-randomization)
- [Rogue Authenticator](#rogue-authenticator)
- [OTA Firmware Updates](#ota-firmware-updates)
- [RFC 2544 Suite](#rfc-2544-suite)
- [SD Card & File Manager](#sd-card--file-manager)
- [WireGuard VPN](#wireguard-vpn)
- [Scripting & Automation](#scripting--automation)
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
| **802.1X / EAP** | Full supplicant: EAP-MD5, EAP-TLS, PEAPv0/MSCHAPv2, EAP-TTLS (PAP + MSCHAPv2); configurable target MAC/IP |
| **Rogue authenticator** | Fake 802.1X authenticator to harvest EAP-MD5 / MSCHAPv2 credentials |
| **EAPOL attacks** | Start-flood, spoofed logoff, MAB probe |
| **IPv6 / NDP** | Passive NDP decode (RS/RA/NS/NA) and rogue Router Advertisement (SLAAC takeover) |
| **FHRP (HSRP/VRRP)** | Passive decode of HSRP/VRRP advertisements + gateway hijack |
| **L2 attacks** | 802.1Q VLAN inject, Q-in-Q hop, DTP spoof, CAM flood, STP root/TCN, LLDP/CDP flood |
| **ARP tools** | Gratuitous ARP, ARP MITM spoof, ARP storm, ARP scan |
| **SNMP recon** | Community probe, IP sweep, write-access test (sysContact.0 read/set/restore) |
| **Port scanning** | TCP SYN scan with banner grab for 30+ services, randomizable port order |
| **Network assessment** | Combined ping sweep + ARP scan + port scan + SNMP with CIDR, host/port randomization, per-host MAC rotation |
| **Reconnaissance** | Passive host/protocol mapping, ICMP ping sweep, traceroute |
| **MAC randomization** | Per-operation or per-host random locally-administered MACs; global auto-randomize option |
| **OTA updates** | Firmware update via TFTP (CLI) or HTTP file upload (web UI) |
| **PCAP capture** | Capture frames to SD card or LittleFS, downloadable from web UI |
| **SD card** | FAT32 file manager: ls, cat, rm, rename, mkdir, write; PCAP/log storage |
| **WireGuard VPN** | Tunnel management interface back to a central server |
| **Scripting** | Run multi-command scripts from SD with delays, loops, and conditionals |
| **Cron scheduler** | Time-based scheduled command execution (standard cron syntax) |
| **Output logging** | Tee all CLI output to timestamped log files on SD |
| **File upload** | HTTP POST upload of logs, pcaps, and arbitrary SD files to a server |
| **Web server** | HTTPS support, basic-auth, on/off control |
| **Wi-Fi web UI** | Tabbed multi-panel interface with real-time output; STA + AP modes |
| **PHY control** | Force link speed/duplex: auto, 100FD, 100HD, 10FD, 10HD |
| **Persistence** | Wi-Fi credentials, hostname, IP config, 802.1X creds, WireGuard keys stored in NVS |

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

## Quick-Start Tutorial

This walks through a typical first session: boot, get an IP, run some tests,
and use the web UI.

### 1. Connect and power on

Plug an Ethernet cable from the Waveshare board to a switch port. Connect USB-C
for serial and power. Open a terminal at 115200 baud:

```
pio device monitor -b 115200
```

You should see W5500 init output and `Link: UP`.

### 2. Get an IP address

```
ETH> ip dhcp
```

The device performs a full DHCP DORA exchange. Verify with:

```
ETH> status
```

If DHCP is unavailable, assign a static address:

```
ETH> ip static 192.168.1.100 255.255.255.0 192.168.1.1
```

> Commands that require an IP address (scan, recon sweep/trace, dns, snmp,
> probe, arp, fhrp hijack) will refuse to run and print a warning if no IP is
> configured.

### 3. Basic discovery

```
ETH> discover 30          # Listen for LLDP/CDP from the switch
ETH> recon passive 20     # Map hosts and protocols on the wire
ETH> arp scan 192.168.1.1 192.168.1.254  # ARP sweep for live hosts
```

### 4. Port scanning

```
ETH> scan common 192.168.1.1       # Scan common ports on the gateway
ETH> scan banner 192.168.1.1 22    # Grab SSH banner
```

### 5. Error injection and RFC 2544

```
ETH> inject giant 10               # Send 10 giant frames
ETH> inject storm 1000             # Start broadcast storm at 1000 fps
ETH> inject stop                   # Stop all injection

# For RFC 2544, enable port loopback on the DUT first:
ETH> test all                      # Full suite (throughput, latency, loss, burst)
```

### 6. Offensive tests (authorized networks only)

```
ETH> arm on                        # Enable offensive mode
ETH> l2 macflood 5000 10000        # CAM table flood
ETH> arp spoof 192.168.1.50 192.168.1.1 30   # ARP MITM for 30s
ETH> disarm                        # Lock out offensive tests
```

### 7. Enable the web UI

```
ETH> wifi ssid MyNetwork
ETH> wifi pass MyPassword
ETH> wifi on
ETH> reboot
```

After reboot, browse to `http://esp32-tester.local/`. The tabbed web UI gives
access to all tools:

| Tab | Contents |
|-----|----------|
| **Status** | Live device status, SD card info |
| **L1/L2** | PHY speed control, traffic generation, loopback |
| **Inject** | Error injection controls (one-shot and continuous) |
| **Tests** | RFC 2544, DHCP scenarios, DNS, offensive tests (when armed) |
| **Recon** | IP config, LLDP/CDP, network scan, port scanner, listeners |
| **Security** | 802.1X/EAP authentication |
| **Files** | PCAP capture, SD file browser, log viewer |
| **Scripts** | Script engine, cron scheduler, inline script runner |

The gear icon in the header opens the **Settings** modal for system controls,
offensive mode arm/disarm, web server HTTPS, authentication, Wi-Fi, WireGuard,
and upload destination configuration.

### 8. Scripting (automation)

Create a script on the SD card (via the web file manager or `sd write`):

```
ETH> sd write /scripts/daily.txt "# Daily port health check"
ETH> sd write /scripts/daily.txt "ip dhcp"
ETH> sd write /scripts/daily.txt "delay 2000"
ETH> sd write /scripts/daily.txt "discover 10"
ETH> sd write /scripts/daily.txt "recon passive 15"
ETH> sd write /scripts/daily.txt "arp scan 192.168.1.1 192.168.1.254"
```

Run it:

```
ETH> script run /scripts/daily.txt health-check
```

Output is automatically logged to `/logs/health-check-YYYYMMDD-HHMMSS.log`.

Schedule it with cron:

```
ETH> cron add 0 6 * * * script run /scripts/daily.txt morning
```

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
| `link speed auto\|100fd\|100hd\|10fd\|10hd` | Force PHY speed/duplex |
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

### SD Card / File Manager
| Command | Description |
|---------|-------------|
| `sd` | Show TF/SD card info |
| `sd init` | Re-detect / remount the SD card |
| `sd format` | Erase and format SD card (FAT32) |
| `sd ls [path]` | List directory contents |
| `sd cat <file>` | Print file contents |
| `sd rm <file>` | Delete a file |
| `sd rename <old> <new>` | Rename / move a file |
| `sd mkdir <path>` | Create a directory |
| `sd write <file> <text>` | Append a line of text to a file |

### WireGuard VPN
| Command | Description |
|---------|-------------|
| `wg` | Show tunnel status and config |
| `wg set localip <ip>` | Set tunnel interface IP |
| `wg set privkey <base64>` | Set local private key |
| `wg set pubkey <base64>` | Set peer public key |
| `wg set endpoint <host\|ip>` | Set peer endpoint address |
| `wg set port <port>` | Set peer endpoint port (default 51820) |
| `wg set psk <base64>` | Set pre-shared key (optional) |
| `wg enable` | Enable auto-start on boot |
| `wg disable` | Disable and stop tunnel |
| `wg start` | Start tunnel now |
| `wg stop` | Stop tunnel |
| `wg clear` | Erase all WireGuard config |

### Scripting & Automation
| Command | Description |
|---------|-------------|
| `script` | Show script engine status |
| `script list` | List scripts on SD (`/scripts/`) |
| `script run <file> [logname]` | Run a script (optional auto-log) |
| `script stop` | Abort running script |
| `script create <file>` | Create a template script on SD |

### Output Logging
| Command | Description |
|---------|-------------|
| `log` | Show logger status |
| `log start [name]` | Start logging to SD (auto-name if omitted) |
| `log stop` | Stop logging |
| `log list` | List log files on SD |
| `log delete <file>` | Delete a log file |
| `log flush` | Force flush to SD |

### Cron Scheduler
| Command | Description |
|---------|-------------|
| `cron` | List scheduled tasks |
| `cron add <min> <hr> <dom> <mon> <dow> <cmd>` | Add a cron entry |
| `cron remove <index>` | Remove entry by index |
| `cron reload` | Re-read `/cron.txt` from SD |
| `cron clear` | Remove all entries |

### File Upload
| Command | Description |
|---------|-------------|
| `upload` | Show upload destination config |
| `upload set <url> [user] [pass]` | Set default upload server |
| `upload clear` | Clear upload destination |
| `upload log <name> [url]` | Upload a log file (HTTP POST) |
| `upload pcap [url]` | Upload current pcap capture |
| `upload file <path> [url]` | Upload any SD file |

### Wi-Fi / Web (persisted to NVS)
| Command | Description |
|---------|-------------|
| `wifi` | Show Wi-Fi status |
| `wifi ssid <ssid>` | Set SSID |
| `wifi pass <password>` | Set password |
| `wifi mode ap\|sta` | Mgmt as soft AP (field) or station |
| `wifi apssid <ssid>` | Set soft-AP SSID |
| `wifi appass <password>` | Set soft-AP password (>=8 chars, blank=open) |
| `wifi on\|off` | Enable/disable Wi-Fi on boot |
| `host <hostname>` | Set device hostname (used by the mDNS responder) |
| `web` | Show web server status |
| `web on\|off` | Start/stop web server |
| `web auth set <user> <pass>` | Set basic-auth credentials (saved) |
| `web auth clear` | Disable authentication |
| `web https on\|off` | Enable/disable HTTPS (port 443) |

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
3. **Soft-AP mode (`wifi mode ap`):** the device always broadcasts its own AP
   for field use without infrastructure Wi-Fi.

### Web UI

Browse to `http://<hostname>.local/` (STA) or the AP IP (fallback). The
interface uses a **tabbed layout** with eight functional tabs:

| Tab | Contents |
|-----|----------|
| **Status** | Auto-refreshing device status (link, speed, MAC, IP, counters, heap, SD), SD card init/format |
| **L1/L2** | PHY speed selector, traffic generation (send frames), loopback toggle |
| **Inject** | One-shot and continuous error injection controls |
| **Tests** | RFC 2544 suite, DHCP test scenarios, DNS resolve, offensive tests (hidden until armed) |
| **Recon** | IP configuration (DHCP/static), LLDP/CDP discovery, network scan, port scanner, protocol listeners |
| **Security** | 802.1X/EAP authentication (method, credentials, auth) |
| **Files** | PCAP capture start/stop/download, SD card file browser, log file viewer |
| **Scripts** | Script engine (run/stop/list), cron scheduler, inline multi-line script runner |

A **gear icon** in the header opens the **Settings** modal with:
- System info and reboot
- Offensive mode arm/disarm (with confirmation dialog)
- Web server on/off and HTTPS toggle
- Basic authentication set/clear
- Wi-Fi configuration (STA and AP mode)
- WireGuard VPN full config
- Upload destination

The UI auto-detects mobile/desktop layouts and includes an output panel that
streams command results in real time.

### Security

- **Basic auth:** `web auth set <user> <pass>` protects all endpoints (saved to
  NVS, survives reboot).
- **HTTPS:** `web https on` enables TLS on port 443 with an auto-generated
  self-signed certificate.
- **Arm/disarm:** offensive tests are hidden in the web UI and blocked in the
  CLI until the device is explicitly armed.

### HTTP API
| Method | Path | Body | Purpose |
|--------|------|------|---------|
| `GET`  | `/` | -- | Control page (HTML) |
| `GET`  | `/api/status` | -- | JSON status object |
| `POST` | `/api/cmd` | `c=<command>` | Queue a CLI command for execution |
| `GET`  | `/api/result` | -- | Poll command output and running state |
| `POST` | `/api/config` | `ssid,pass,host,wifi` | Save Wi-Fi config to NVS |
| `GET`  | `/api/files` | -- | List SD card files (JSON) |
| `GET`  | `/api/download?f=<path>` | -- | Download a file from SD |
| `POST` | `/api/upload` | multipart file | Upload a file to SD |

Commands received over HTTP are **queued and executed from the main loop** so
the async server callbacks never block; output appears in the web output panel
via polling.

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

**Target specification:** By default EAPOL frames are sent to the PAE multicast
group (`01:80:C2:00:00:03`). Use `dot1x target <MAC>` to direct frames to a
specific authenticator's unicast MAC, or `dot1x target <IP>` to record the
authenticator's IP (useful for documentation/scripting). Clear with
`dot1x target clear`.

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

- **Probe (`snmp probe <ip> [community ...]`)** — sends SNMPv1 GET requests for
  `sysDescr.0` (OID 1.3.6.1.2.1.1.1.0) using specified or default community
  strings (`public`, `private`, `community`, `admin`, `snmp`, `monitor`).
  Reports any accepted community and the device description.
- **Sweep (`snmp sweep <cidr|start> [end] [community]`)** — probes an IP range
  (up to 1024 hosts, supports CIDR notation) with a given community string,
  identifying all SNMP-responsive devices.
- **Write Test (`snmp writetest <ip> [write-community]`)** — tests write access
  by reading `sysContact.0`, setting it to a test marker, verifying the write,
  then restoring the original value. Confirms whether the community string has
  SET privileges.

The web UI provides separate read/write community inputs and dedicated Probe,
Sweep, and Write Test buttons.

---

## Port Scanning & Banner Grab

[src/portscan.cpp](src/portscan.cpp) implements TCP SYN scanning with service
identification:

- **Common scan (`scan common <ip>`)** — scans well-known ports (21, 22, 23, 25,
  53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443)
- **Range scan (`scan ports <ip> <first> <last>`)** — scans a contiguous port range
- **Banner grab (`scan banner <ip> <port>`)** — connects and probes a single port
  for service identification

Service probing supports 30+ protocol-specific handshakes including HTTP, SSH,
FTP, Telnet, SMTP, POP3, IMAP, MySQL, PostgreSQL, Redis, MongoDB, MSSQL, RDP,
VNC, SIP, LDAP, Elasticsearch, Docker, Kubernetes, RTSP, Memcached, and more.
Unknown services receive a generic `\r\n` nudge to elicit a banner.

Port scan order can be randomized (Fisher-Yates shuffle) to evade sequential
scan detection.

---

## Network Assessment

[src/net_assess.cpp](src/net_assess.cpp) provides a combined multi-phase network
assessment that runs four scan types in sequence:

1. **Ping sweep** — ICMP echo to all hosts in range
2. **ARP scan** — L2 discovery of live hosts
3. **Port scan + banner grab** — TCP SYN scan of specified ports (default:
   21, 22, 80, 443) with service identification on open ports
4. **SNMP discovery** — probes all hosts with community string `public`

```
ETH> assess 192.168.1.0/24 22,80,443,8080 -r -m
```

Options:
- IP range via CIDR notation or explicit start/end addresses
- Custom port list (comma-separated)
- `-r` — randomize host iteration and port scan order (Fisher-Yates)
- `-m` — randomize source MAC per target host (locally-administered unicast,
  original MAC restored after completion)

The web UI provides a Network Assessment card with CIDR/port inputs and
checkboxes for randomization options.

---

## MAC Randomization

The tester supports source MAC randomization at multiple levels to reduce
detectability during scanning operations:

- **Per-operation** — "Random src MAC" checkboxes on Network Scan, Port Scanner,
  SNMP Scan, and 802.1X web UI cards. When checked, a fresh locally-administered
  unicast MAC is generated before the operation.
- **Per-host** — the Network Assessment `-m` flag generates a unique MAC for
  each target host, then restores the original after the scan completes.
- **Global default** — `mac autorand on` enables auto-randomization system-wide.
  When enabled, all per-card checkboxes are pre-checked on page load. This is
  overridden when the user explicitly sets a MAC address via `mac <XX:...>`.

```
ETH> mac random            # generate a random MAC now
ETH> mac autorand on       # enable auto-randomize (persistent, default: off)
ETH> mac autorand off      # disable
```

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

## OTA Firmware Updates

[src/ota.cpp](src/ota.cpp) provides over-the-air firmware updates:

- **TFTP** (`ota tftp <server-ip> [filename]`) — fetches a firmware binary from a
  TFTP server (RFC 1350) and flashes it to the alternate OTA partition. Supports
  progress display and abort via serial/web.
- **HTTP upload** (web UI) — direct file upload via the Settings modal. The
  device accepts a `.bin` file via multipart POST to `/api/ota`, flashes it, and
  reboots automatically.

The build process generates `ota/firmware.bin` (and a versioned copy) via the
`ota_copy.py` post-build script. The 16 MB flash uses a dual-OTA partition
scheme (6.25 MB per slot).

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

## SD Card & File Manager

The Waveshare ESP32-S3-POE-ETH has an onboard TF (micro-SD) card slot connected
via a dedicated HSPI bus (separate from the W5500 SPI). Insert a FAT32-formatted
micro-SD card for:

- **PCAP capture storage** (larger captures than LittleFS allows)
- **Script storage** (`/scripts/*.txt`)
- **Output logging** (`/logs/*.log`)
- **Cron configuration** (`/cron.txt`)
- **General file storage** (certificates, configs, data exports)

The SD card is auto-detected on boot. Use `sd init` to remount after hot-insert,
or `sd format` to erase and format.

| Pin | ESP32-S3 GPIO |
|-----|---------------|
| CS  | 4 |
| MOSI | 6 |
| MISO | 5 |
| SCK | 7 |

---

## WireGuard VPN

The device can establish a WireGuard tunnel over Wi-Fi for secure remote
management. Configure via CLI or the web Settings modal:

```
ETH> wg set localip 10.0.0.2
ETH> wg set privkey <base64-private-key>
ETH> wg set pubkey <base64-peer-public-key>
ETH> wg set endpoint vpn.example.com
ETH> wg set port 51820
ETH> wg enable
ETH> reboot
```

When enabled, the tunnel starts automatically on boot after Wi-Fi connects. The
`wg set weboff on` option stops the web server when the tunnel is active
(security hardening for field deployments).

---

## Scripting & Automation

Scripts are plain-text files on the SD card (one CLI command per line). Special
directives:

| Directive | Description |
|-----------|-------------|
| `# comment` | Ignored |
| `delay <ms>` | Pause execution for N milliseconds |
| `repeat <n>` | Repeat the next command N times |
| `loop <n>` ... `endloop` | Loop a block of commands N times |
| `if <condition>` ... `endif` | Conditional execution |
| `log start [name]` | Start output logging within script |
| `log stop` | Stop logging |

The **cron scheduler** reads `/cron.txt` from the SD card on boot (standard
5-field cron format) and executes commands at the scheduled times. The device
must have NTP time (obtained automatically via Wi-Fi) for cron to function.

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
| [src/snmp_recon.cpp](src/snmp_recon.cpp) | SNMPv1 community probe + sweep + write test |
| [src/net_probe.cpp](src/net_probe.cpp) | mDNS resolve + ping reachability |
| [src/dot1x.cpp](src/dot1x.cpp) | 802.1X supplicant (MD5/TLS/PEAP/TTLS) + EAPOL attacks |
| [src/rogue_auth.cpp](src/rogue_auth.cpp) | Rogue 802.1X authenticator / EAP credential harvester |
| [src/mschapv2.cpp](src/mschapv2.cpp) | MS-CHAPv2 crypto (self-contained MD4 + DES) |
| [src/cert_store.cpp](src/cert_store.cpp) | LittleFS certificate storage for EAP-TLS |
| [src/l2_attack.cpp](src/l2_attack.cpp) | L2 attack suite (VLAN/DTP/STP/MAC-flood/LLDP-CDP flood) |
| [src/arp_tool.cpp](src/arp_tool.cpp) | ARP scan, gratuitous, spoof, storm |
| [src/fhrp.cpp](src/fhrp.cpp) | FHRP assessment (HSRP/VRRP listen + hijack) |
| [src/ipv6_tool.cpp](src/ipv6_tool.cpp) | IPv6 NDP listen + rogue RA |
| [src/portscan.cpp](src/portscan.cpp) | TCP SYN scan + banner grab (30+ services) |
| [src/recon.cpp](src/recon.cpp) | Passive recon, ping sweep, traceroute |
| [src/net_assess.cpp](src/net_assess.cpp) | Combined network assessment (ping+ARP+ports+SNMP) |
| [src/ota.cpp](src/ota.cpp) | OTA firmware updates (TFTP + HTTP stream) |
| [src/linkdiag.cpp](src/linkdiag.cpp) | Link diagnostics + flap monitor |
| [src/pcap.cpp](src/pcap.cpp) | PCAP capture to SD card or LittleFS |
| [src/net_config.cpp](src/net_config.cpp) | NVS persistence (Preferences) |
| [src/wifi_web.cpp](src/wifi_web.cpp) | Wi-Fi STA/AP + ESPAsyncWebServer tabbed UI |
| [src/weblog.cpp](src/weblog.cpp) | TeeStream ring buffer for web output capture |
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
| `wifiMode` | Wi-Fi mode (0=STA, 1=AP) | `0` |
| `apSsid` | Soft-AP SSID | `ESP32-Tester` |
| `apPass` | Soft-AP password | (empty/open) |
| `dhcp` | Use DHCP for the Ethernet IP | `true` |
| `ip` / `mask` / `gw` | Static IPv4 config | `0` / `255.255.255.0` / `0` |
| `webUser` / `webPass` | Basic-auth credentials | (empty/disabled) |
| `httpsOn` | HTTPS enabled | `false` |
| `armed` | Offensive mode state | `false` |
| `wgLocalIp` | WireGuard tunnel IP | (empty) |
| `wgPrivKey` | WireGuard private key | (empty) |
| `wgPubKey` | WireGuard peer public key | (empty) |
| `wgEndpoint` | WireGuard peer endpoint | (empty) |
| `wgPort` | WireGuard peer port | `51820` |
| `wgEnabled` | WireGuard auto-start | `false` |
| `uploadUrl` | Default upload server URL | (empty) |
| `d1xuser` | 802.1X identity | (empty) |
| `d1xpass` | 802.1X password | (empty) |
| `d1xmeth` | EAP method (0=MD5, 1=TLS, 2=PEAP, 3=TTLS/PAP, 4=TTLS/MSCHAP) | `0` |
| `d1xkeypw` | EAP-TLS private key passphrase | (empty) |
| `d1xtgt` | 802.1X target authenticator MAC | (all-zeros/PAE mcast) |
| `d1xtgtip` | 802.1X target IP | `0` |
| `rmacdf` | Auto-randomize source MAC | `false` |

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

### W5500 init fails -- `Version check failed`
The driver reads the W5500 version register (expected `0x04`). The value read is
diagnostic:

| Read value | Likely cause |
|------------|--------------|
| `0x7F` or random | SPI returning garbage -- MISO line issue or clock too fast. |
| `0x00` | MISO delivering no data -- disconnected or no 3.3 V power. |
| `0xFF` | MISO stuck high / module unpowered or absent. |

On the Waveshare ESP32-S3-POE-ETH, SPI is onboard -- if init fails, check for
a damaged board or firmware misconfiguration.

### Web UI not reachable
- Check `wifi` shows connected (serial prints the IP on boot).
- Try the IP directly if `<hostname>.local` mDNS resolution fails.
- Verify `web` shows the server is running (`web on` to start).
- If basic auth is set, the browser will prompt for credentials.
- In AP mode, join the AP SSID and browse to the AP IP printed on console.

### Commands refuse to run -- "No IP address configured"
Commands that require network connectivity (scan, recon sweep/trace, dns, snmp,
probe, arp scan/spoof/storm, fhrp hijack) require an IP address. Run:
```
ETH> ip dhcp
```
or assign a static IP before using these tools.

### DHCP / probe commands do nothing useful
These depend on the W5500 being initialised and the link being up. Resolve any
W5500 init failure first, then confirm `status` shows **Link: UP**.

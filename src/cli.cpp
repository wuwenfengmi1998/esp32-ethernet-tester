#include "cli.h"
#include "../include/config.h"
#include "discovery.h"
#include "net_probe.h"
#include "dot1x.h"
#include "cert_store.h"
#include "l2_attack.h"
#include "arp_tool.h"
#include "portscan.h"
#include "recon.h"
#include "linkdiag.h"
#include "ipv6_tool.h"
#include "pcap.h"
#include "fhrp.h"
#include "dhcpv6.h"
#include "dns_tool.h"
#include "snmp_recon.h"
#include "rogue_auth.h"
#include "wg_tunnel.h"
#include "wifi_web.h"
#include "scripting.h"
#include "logger.h"
#include "net_util.h"
#include "ota.h"
#include "net_assess.h"
#include "weblog.h"
#include <WiFi.h>
#include <esp_timer.h>
#include <lwip/sockets.h>
#include <SD.h>
#include <LittleFS.h>
#include <string.h>
#include <stdlib.h>

// Tee all CLI output to the web capture buffer (input still reads from Serial).
#define Serial Out

// =============================================================================
// Construction / begin
// =============================================================================
CLI::CLI(W5500Raw    &eth,
         ErrorInject &inj,
         RFC2544     &rfc,
         IpStack     &ip,
         DhcpTest    &dhcp,
         NetConfig   &cfg,
         uint8_t     srcMac[6],
         uint8_t     dstMac[6])
    : _eth(eth), _inj(inj), _rfc(rfc), _ip(ip), _dhcp(dhcp), _cfg(cfg),
      _src(srcMac), _dst(dstMac),
      _pos(0), _loopback(false)
{
    memset(_buf, 0, sizeof(_buf));
    discoveryAdvertInit(_advert);
}

void CLI::begin()
{
    Serial.println();
    Serial.println("============================================");
    Serial.printf( "  Ethernet Tester v%s  (W5500 MACRAW)\r\n", FW_VERSION);
    Serial.println("  Type 'help' for command list.");
    Serial.println("============================================");
    _printPrompt();
}

// =============================================================================
// process — reads Serial bytes and dispatches complete lines
// =============================================================================
void CLI::process()
{
    while (Serial.available()) {
        char c = (char)Serial.read();

        if (c == '\r' || c == '\n') {
            Serial.println();
            _buf[_pos] = '\0';
            if (_pos > 0) {
                _dispatch(_buf);
            }
            _pos = 0;
            memset(_buf, 0, sizeof(_buf));
            _printPrompt();
            return;  // one line per call to keep loop() responsive
        } else if (c == '\b' || c == 0x7F) {  // backspace
            if (_pos > 0) {
                _pos--;
                Serial.print("\b \b");
            }
        } else if (_pos < CLI_BUF_SIZE - 1) {
            _buf[_pos++] = c;
            Serial.print(c);  // local echo
        }
    }
}

// =============================================================================
// loopbackTick — if loopback is enabled, reflect received frames back
// =============================================================================
void CLI::loopbackTick()
{
    if (!_loopback) return;

    static uint8_t buf[ETH_MAX_LEN + 4];
    uint16_t len = _eth.recvFrame(buf, sizeof(buf));
    if (len < ETH_HDR_LEN) return;

    // Swap DA and SA
    uint8_t tmp[6];
    memcpy(tmp,     buf,     6);   // save DA
    memcpy(buf,     buf + 6, 6);   // DA = original SA
    memcpy(buf + 6, tmp,     6);   // SA = original DA
    _eth.sendFrame(buf, len);
}

// =============================================================================
// Prompt
// =============================================================================
void CLI::_printPrompt()
{
    Serial.print("\r\nETH> ");
}

// =============================================================================
// Command dispatcher
// =============================================================================
void CLI::_dispatch(char *line)
{
    // Strip leading whitespace
    while (*line == ' ') line++;
    if (*line == '\0') return;

    // Split verb from rest
    char *verb = strtok(line, " \t");
    char *args = strtok(nullptr, "");   // rest of line (may be nullptr)
    if (args) while (*args == ' ') args++;  // strip leading spaces from args

    if      (strcasecmp(verb, "help")     == 0) _cmdHelp();
    else if (strcasecmp(verb, "?")        == 0) _cmdHelp();
    else if (strcasecmp(verb, "status")   == 0) _cmdStatus();
    else if (strcasecmp(verb, "stats")    == 0) _cmdStats(args);
    else if (strcasecmp(verb, "mac")      == 0) _cmdMac(args);
    else if (strcasecmp(verb, "target")   == 0) _cmdTarget(args);
    else if (strcasecmp(verb, "loopback") == 0) _cmdLoopback(args);
    else if (strcasecmp(verb, "send")     == 0) _cmdSend(args);
    else if (strcasecmp(verb, "inject")   == 0) _cmdInject(args);
    else if (strcasecmp(verb, "test")     == 0) _cmdTest(args);
    else if (strcasecmp(verb, "discover") == 0) _cmdDiscover(args);
    else if (strcasecmp(verb, "advertise")== 0) _cmdAdvertise(args);
    else if (strcasecmp(verb, "wifi")     == 0) _cmdWifi(args);
    else if (strcasecmp(verb, "host")     == 0) _cmdHost(args);
    else if (strcasecmp(verb, "ip")       == 0) _cmdIp(args);
    else if (strcasecmp(verb, "dhcp")     == 0) _cmdDhcp(args);
    else if (strcasecmp(verb, "probe")    == 0) _cmdProbe(args);
    else if (strcasecmp(verb, "dot1x")    == 0) _cmdDot1x(args);
    else if (strcasecmp(verb, "arm")      == 0) _cmdArm(args);
    else if (strcasecmp(verb, "disarm")   == 0) { _cfg.authorizedMode = false; netConfigSave(_cfg); Serial.println("Authorized (lab) mode DISABLED. Offensive tests blocked."); }
    else if (strcasecmp(verb, "l2")       == 0) _cmdL2(args);
    else if (strcasecmp(verb, "arp")      == 0) _cmdArp(args);
    else if (strcasecmp(verb, "scan")     == 0) _cmdScan(args);
    else if (strcasecmp(verb, "recon")    == 0) _cmdRecon(args);
    else if (strcasecmp(verb, "ipv6")     == 0) _cmdIpv6(args);
    else if (strcasecmp(verb, "fhrp")     == 0) _cmdFhrp(args);
    else if (strcasecmp(verb, "dhcpv6")   == 0) _cmdDhcpv6(args);
    else if (strcasecmp(verb, "dns")      == 0) _cmdDns(args);
    else if (strcasecmp(verb, "snmp")     == 0) _cmdSnmp(args);
    else if (strcasecmp(verb, "pcap")     == 0) _cmdPcap(args);
    else if (strcasecmp(verb, "sd")       == 0) _cmdSd(args);
    else if (strcasecmp(verb, "wg")       == 0) _cmdWg(args);
    else if (strcasecmp(verb, "web")      == 0) _cmdWeb(args);
    else if (strcasecmp(verb, "script")   == 0) _cmdScript(args);
    else if (strcasecmp(verb, "log")       == 0) _cmdLog(args);
    else if (strcasecmp(verb, "cron")      == 0) _cmdCron(args);
    else if (strcasecmp(verb, "upload")    == 0) _cmdUpload(args);
    else if (strcasecmp(verb, "ota")       == 0) _cmdOta(args);
    else if (strcasecmp(verb, "assess")    == 0) _cmdAssess(args);
    else if (strcasecmp(verb, "link")     == 0) {
        char *op = args ? strtok(args, " \t") : nullptr;
        char *a1 = strtok(nullptr, " \t");
        if (op && strcasecmp(op, "monitor") == 0)
            linkMonitor(_eth, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 30);
        else if (op && strcasecmp(op, "speed") == 0) {
            if (!a1) {
                uint8_t phy = _eth.phyCfgr();
                Serial.printf("Current: %s %s (PHY=0x%02X)\r\n",
                    (phy & PHYCFGR_SPD) ? "100M" : "10M",
                    (phy & PHYCFGR_DPX) ? "Full" : "Half", phy);
                Serial.println("Usage: link speed auto|100fd|100hd|10fd|10hd");
            } else if (strcasecmp(a1, "auto") == 0) {
                _eth.setPhyMode(0); Serial.println("PHY: auto-negotiate");
            } else if (strcasecmp(a1, "100fd") == 0) {
                _eth.setPhyMode(1); Serial.println("PHY: 100 Mbps Full-Duplex");
            } else if (strcasecmp(a1, "100hd") == 0) {
                _eth.setPhyMode(2); Serial.println("PHY: 100 Mbps Half-Duplex");
            } else if (strcasecmp(a1, "10fd") == 0) {
                _eth.setPhyMode(3); Serial.println("PHY: 10 Mbps Full-Duplex");
            } else if (strcasecmp(a1, "10hd") == 0) {
                _eth.setPhyMode(4); Serial.println("PHY: 10 Mbps Half-Duplex");
            } else {
                Serial.println("Options: auto, 100fd, 100hd, 10fd, 10hd");
            }
        }
        else
            linkInfo(_eth);
    }
    else if (strcasecmp(verb, "reboot")   == 0) _cmdReboot();
    else if (strcasecmp(verb, "reset")    == 0) _cmdReboot();
    else {
        Serial.printf("Unknown command: '%s'  (type 'help')\r\n", verb);
    }
}

// =============================================================================
// help
// =============================================================================
void CLI::_cmdHelp()
{
    Serial.println(
        "\r\n"
        "General:\r\n"
        "  status                           Link state, PHY info\r\n"
        "  stats                            TX/RX counters\r\n"
        "  stats clear                      Reset counters\r\n"
        "  mac  <XX:XX:XX:XX:XX:XX>         Set source MAC\r\n"
        "  mac  random                      Generate random src MAC\r\n"
        "  mac  autorand on|off             Auto-randomize MAC (default: off)\r\n"
        "  target <XX:XX:XX:XX:XX:XX>       Set destination MAC\r\n"
        "  loopback on|off                  Reflector mode (echo rx back to sender)\r\n"
        "  send <count> [size]              Send <count> test frames of <size> bytes\r\n"
        "\r\n"
        "Error Injection:\r\n"
        "  inject runt    [count]           Runt frames (NOTE: W5500 pads to 64B; not seen as runts)\r\n"
        "  inject giant   [count]           Giant frames (>1518 bytes on wire)\r\n"
        "  inject jumbo   [count [size]]    Jumbo frames (default 9000B; needs jumbo MTU on DUT)\r\n"
        "  inject broadcast [count]         Frames to FF:FF:FF:FF:FF:FF\r\n"
        "  inject multicast [count]         Frames to 01:00:5E:00:00:01\r\n"
        "  inject badtype [count]           Reserved EtherType frames\r\n"
        "  inject pause   [count [quanta]]  802.3x PAUSE frames\r\n"
        "  inject pattern <pat> [len] [n]   Stress pattern: zeros|ones|alt|incr|random\r\n"
        "  inject storm   <rate_hz>         Broadcast storm (0 to stop)\r\n"
        "  inject continuous <type> <rate>  Continuous error stream (type: giant|jumbo|\r\n"
        "                                   badtype|broadcast|multicast|pause|pattern)\r\n"
        "  inject stop                      Stop background storm + continuous\r\n"
        "\r\n"
        "RFC 2544 Tests (requires DUT port loopback):\r\n"
        "  test throughput [size]           Zero-loss throughput (binary search)\r\n"
        "  test latency    [size]           Round-trip latency\r\n"
        "  test frameloss  [size]           Frame loss at 100/50/10%% load\r\n"
        "  test backtoback [size]           Max burst without loss\r\n"
        "  test all                         Full RFC 2544 suite (all frame sizes)\r\n"
        "\r\n"
        "Neighbour Discovery:\r\n"
        "  discover [seconds]               Listen for LLDP/CDP (default 65 s)\r\n"
        "\r\n"
        "Neighbour Advertisement (TX):\r\n"
        "  advertise                        Show advertisement config\r\n"
        "  advertise lldp on|off            Toggle LLDP advertisement\r\n"
        "  advertise cdp  on|off            Toggle CDP advertisement\r\n"
        "  advertise name <string>          System name / device ID\r\n"
        "  advertise port <string>          Port ID\r\n"
        "  advertise platform <string>      Platform / description string\r\n"
        "  advertise ip <a.b.c.d>           Management IPv4 (0.0.0.0 = none)\r\n"
        "  advertise vlan <id>              Port/native VLAN (0 = none)\r\n"
        "  advertise ttl <seconds>          Advertised TTL\r\n"
        "  advertise interval <seconds>     Transmit interval\r\n"
        "  advertise off                    Disable both LLDP and CDP\r\n"
        "\r\n"
        "L3 / IP Testing (Ethernet side):\r\n"
        "  ip show                          Show IP stack address config\r\n"
        "  ip dhcp                          Obtain address via DHCP (DORA)\r\n"
        "  ip static <ip> <mask> <gw>       Set a static IPv4 address\r\n"
        "  dhcp discover                    Full DORA exchange (verify server)\r\n"
        "  dhcp detect                      Server-down / presence detection\r\n"
        "  dhcp flood [count]               Starvation / pool-exhaustion test\r\n"
        "  dhcp decline                     OFFER then DECLINE (conflict sim)\r\n"
        "  dhcp nak [ip]                    Request bogus IP, expect NAK\r\n"
        "  dhcp malformed                   Malformed packet, expect ignore\r\n"
        "  dhcp renew [secs]                Short lease + unicast renew\r\n"
        "  probe <hostname>                 Resolve <name>.local (mDNS) and ping\r\n"
        "\r\n"
        "802.1X / AAA Port Authentication (EAPOL supplicant):\r\n"
        "  dot1x                            Show 802.1X method / credential status\r\n"
        "  dot1x method md5|tls|peap|ttls-pap|ttls-mschap  Select EAP method\r\n"
        "  dot1x probe                      Detect whether the port enforces 802.1X\r\n"
        "  dot1x auth [user] [pass]         Authenticate with the selected method\r\n"
        "  dot1x user <name>                Set 802.1X identity (saved)\r\n"
        "  dot1x pass <password>            Set EAP-MD5 password (saved)\r\n"
        "  dot1x keypass <pw>               Set EAP-TLS private-key passphrase (saved)\r\n"
        "  dot1x cert [clear ...]           Show / remove uploaded certificates\r\n"
        "  dot1x logoff                     Send EAPOL-Logoff\r\n"
        "  (EAP-TLS certificates are uploaded from the web UI)\r\n"
        "\r\n"
        "Wi-Fi / Web (config stored in NVS):\r\n"
        "  wifi                             Show Wi-Fi status\r\n"
        "  wifi ssid <ssid>                 Set infrastructure SSID (saved)\r\n"
        "  wifi pass <password>             Set infrastructure password (saved)\r\n"
        "  wifi mode ap|sta                 Mgmt as soft AP (field) or station (saved)\r\n"
        "  wifi apssid <ssid>               Set soft-AP SSID (saved)\r\n"
        "  wifi appass <password>           Set soft-AP password (>=8 chars, blank=open)\r\n"
        "  wifi on|off                      Enable/disable Wi-Fi on boot (saved)\r\n"
        "  host <hostname>                  Set device hostname (saved)\r\n"
        "\r\n"
        "Reconnaissance:\r\n"
        "  recon passive [secs]             Passively map hosts/protocols (default 30 s)\r\n"
        "  recon sweep <start> <end>        ICMP ping sweep of an address range\r\n"
        "  recon trace <ip> [maxhops]       ICMP traceroute to a target\r\n"
        "  arp scan <start> <end>           ARP sweep for live hosts (L2 discovery)\r\n"
        "  scan common <ip>                 TCP SYN scan of common ports\r\n"
        "  scan ports <ip> <first> <last>   TCP SYN scan of a port range\r\n"
        "  scan banner <ip> <port> [probe]  Banner grab via full TCP handshake\r\n"
        "  link [monitor [secs]]            Link speed/duplex info or flap monitor\r\n"
        "  link speed auto|100fd|100hd|10fd|10hd  Force PHY speed/duplex\r\n"
        "  wifi scan                        Scan Wi-Fi (rogue-AP / evil-twin recon)\r\n"
        "  ipv6 listen [secs]               Decode IPv6 NDP (RS/RA/NS/NA)\r\n"
        "  fhrp listen [secs]               Decode HSRP/VRRP advertisements\r\n"
        "  dhcpv6 probe [secs]              Discover DHCPv6 servers (SOLICIT)\r\n"
        "  dns resolve <host> [server]      Unicast DNS A-record query\r\n"
        "  snmp probe <ip> [comm ...]       SNMP community-string probe (sysDescr)\r\n"
        "  snmp sweep <cidr|start> [end] [comm] SNMP sweep of an IP range\r\n"
        "  snmp writetest <ip> [write-comm]     Test write access via sysContact.0\r\n"
        "  pcap start [secs] [maxframes]    Capture frames to /capture.pcap (web download)\r\n"
        "  pcap status | delete             Show or remove the stored capture\r\n"
        "\r\n"
        "Offensive / DoS tests (require 'arm' -- authorized lab use only):\r\n"
        "  arm [on]                         Show or enable authorized (lab) mode\r\n"
        "  disarm                           Disable authorized mode\r\n"
        "  l2 vlan <vid> [pcp] [count]      802.1Q single-tag VLAN inject\r\n"
        "  l2 dtag <native> <target> [n]    Double-tag (Q-in-Q) VLAN hop\r\n"
        "  l2 dtp                           DTP trunk-negotiation spoof\r\n"
        "  l2 macflood [count] [rate]       CAM-table flood (random MACs)\r\n"
        "  l2 stp listen [secs]             Decode STP/RSTP BPDUs\r\n"
        "  l2 stp root [prio] [secs]        Claim root bridge (BPDU/Root Guard test)\r\n"
        "  l2 stp tcn [count]               Inject topology-change BPDUs\r\n"
        "  l2 lldpflood [count]             LLDP neighbour-table flood\r\n"
        "  l2 cdpflood [count]              CDP neighbour-table flood\r\n"
        "  arp gratuitous <ip> [count]      Gratuitous ARP announce\r\n"
        "  arp spoof <victim> <gw> [secs]   ARP MITM (auto-restores on stop)\r\n"
        "  arp storm [count] [rate]         ARP request flood\r\n"
        "  ipv6 rogue [lifetime] [count]    Rogue Router Advertisement (SLAAC takeover)\r\n"
        "  fhrp hsrp <grp> <vip> [prio] [n] HSRP gateway hijack\r\n"
        "  fhrp vrrp <vrid> <vip> [prio] [n] VRRP master hijack\r\n"
        "  dhcpv6 rogue <prefix> <dns> [s]  Rogue DHCPv6 server (stateful IPv6)\r\n"
        "  dns spoof <ip> [secs]            DNS spoof (answer all queries with <ip>)\r\n"
        "  dhcp rogue <pool> [mask gw dns secs]  Rogue DHCP server (hands out leases)\r\n"
        "  dot1x startflood [count]         EAPOL-Start flood (random MACs)\r\n"
        "  dot1x logoffmac <mac>            Spoofed EAPOL-Logoff (deauth a client)\r\n"
        "  dot1x mab [secs]                 MAB / 802.1X enforcement probe\r\n"
        "  dot1x rogue [secs] [md5]         Rogue authenticator (harvest credentials)\r\n"
        "\r\n"
        "SD Card / File Manager:\r\n"
        "  sd                               Show TF/SD card info\r\n"
        "  sd init                          Re-detect / remount the SD card\r\n"
        "  sd format                        Erase and format SD card (FAT32)\r\n"
        "  sd ls [path]                     List directory contents\r\n"
        "  sd cat <file>                    Print file contents\r\n"
        "  sd rm <file>                     Delete a file\r\n"
        "  sd rename <old> <new>            Rename / move a file\r\n"
        "  sd mkdir <path>                  Create a directory\r\n"
        "  sd write <file> <text>           Append a line of text to a file\r\n"
        "\r\n"
        "WireGuard VPN:\r\n"
        "  wg                               Show tunnel status and config\r\n"
        "  wg set localip <ip>              Set tunnel interface IP (e.g. 10.0.0.2)\r\n"
        "  wg set privkey <base64>          Set local private key\r\n"
        "  wg set pubkey <base64>           Set peer public key\r\n"
        "  wg set endpoint <host|ip>        Set peer endpoint address\r\n"
        "  wg set port <port>               Set peer endpoint port (default 51820)\r\n"
        "  wg set psk <base64>              Set pre-shared key (optional)\r\n"
        "  wg enable                        Enable auto-start on boot\r\n"
        "  wg disable                       Disable and stop tunnel\r\n"
        "  wg start                         Start tunnel now\r\n"
        "  wg stop                          Stop tunnel\r\n"
        "  wg clear                         Erase all WireGuard config\r\n"
        "  wg set weboff on|off             Stop web server when tunnel is active\r\n"
        "\r\n"
        "Web Server:\r\n"
        "  web                              Show web server status\r\n"
        "  web on|off                       Start/stop web server\r\n"
        "  web auth set <user> <pass>       Set basic-auth credentials (saved)\r\n"
        "  web auth clear                   Disable authentication\r\n"
        "  web https on|off                 Enable/disable HTTPS (port 443)\r\n"
        "\r\n"
        "Scripting & Automation:\r\n"
        "  script                           Show script engine status\r\n"
        "  script list                      List scripts on SD (/scripts/)\r\n"
        "  script run <file> [logname]      Run a script (optional auto-log)\r\n"
        "  script stop                      Abort running script\r\n"
        "  script create <file>             Create a template script on SD\r\n"
        "\r\n"
        "Output Logging:\r\n"
        "  log                              Show logger status\r\n"
        "  log start [name]                 Start logging to SD (auto-name if omitted)\r\n"
        "  log stop                         Stop logging\r\n"
        "  log list                         List log files on SD\r\n"
        "  log delete <file>                Delete a log file\r\n"
        "  log flush                        Force flush to SD\r\n"
        "\r\n"
        "Cron Scheduler:\r\n"
        "  cron                             List scheduled tasks\r\n"
        "  cron add <min> <hr> <dom> <mon> <dow> <cmd>  Add a cron entry\r\n"
        "  cron remove <index>              Remove entry by index\r\n"
        "  cron reload                      Re-read /cron.txt from SD\r\n"
        "  cron clear                       Remove all entries\r\n"
        "\r\n"
        "File Upload:\r\n"
        "  upload                           Show upload destination config\r\n"
        "  upload set <url> [user] [pass]   Set default upload server\r\n"
        "  upload clear                     Clear upload destination\r\n"
        "  upload log <name> [url]          Upload a log file (HTTP POST)\r\n"
        "  upload pcap [url]                Upload current pcap capture\r\n"
        "  upload file <path> [url]         Upload any SD file\r\n"
        "\r\n"
        "Network Assessment:\r\n"
        "  assess <start> <end> [ports] [-r] [-m]  Combined scan (ping+ARP+ports+SNMP)\r\n"
        "  assess <cidr> [ports] [-r] [-m]         Same, using CIDR notation\r\n"
        "                                   -r = randomize scan order\r\n"
        "                                   -m = random MAC per target\r\n"
        "                                   Default ports: 21,22,80,443\r\n"
        "\r\n"
        "OTA Update:\r\n"
        "  ota tftp <ip> [filename]         Fetch firmware via TFTP and flash\r\n"
        "\r\n"
        "System:\r\n"
        "  reboot | reset                   Restart the device\r\n"
        "\r\n"
        "NOTE: The W5500 auto-calculates FCS. True CRC error injection\r\n"
        "      is not possible through this interface.\r\n"
        "      Enable port loopback on CX6300:  interface X/X/X -> loopback\r\n"
    );
}

// =============================================================================
// status
// =============================================================================
void CLI::_cmdStatus()
{
    char srcStr[18], dstStr[18];
    macToStr(_src, srcStr);
    macToStr(_dst, dstStr);

    uint8_t phy = _eth.phyCfgr();
    bool link  = phy & PHYCFGR_LNK;
    bool spd   = phy & PHYCFGR_SPD;
    bool fdx   = phy & PHYCFGR_DPX;

    Serial.printf("\r\nLink:       %s\r\n", link ? "UP" : "DOWN");
    Serial.printf("Speed:      %s\r\n",    spd  ? "100 Mbps" : "10 Mbps");
    Serial.printf("Duplex:     %s\r\n",    fdx  ? "Full" : "Half");
    Serial.printf("PHY CFG:    0x%02X\r\n", phy);
    Serial.printf("Source MAC: %s\r\n",    srcStr);
    Serial.printf("Target MAC: %s\r\n",    dstStr);
    Serial.printf("Loopback:   %s\r\n",    _loopback ? "on (reflector)" : "off");
    Serial.printf("Storm:      %s\r\n",    _inj.isStormActive() ? "active" : "idle");
}

// =============================================================================
// stats
// =============================================================================
void CLI::_cmdStats(char *args)
{
    if (args && strcasecmp(args, "clear") == 0) {
        _eth.clearStats();
        Serial.println("Counters cleared.");
        return;
    }

    const EthStats &s = _eth.stats();
    Serial.printf("\r\nTX frames : %lu\r\n", s.txFrames);
    Serial.printf("TX bytes  : %lu\r\n",     s.txBytes);
    Serial.printf("TX errors : %lu\r\n",     s.txErrors);
    Serial.printf("RX frames : %lu\r\n",     s.rxFrames);
    Serial.printf("RX bytes  : %lu\r\n",     s.rxBytes);
    Serial.printf("RX dropped: %lu\r\n",     s.rxDropped);
}

// =============================================================================
// mac / target
// =============================================================================
void CLI::_cmdMac(char *args)
{
    if (!args || *args == '\0') {
        char str[18]; macToStr(_src, str);
        Serial.printf("Source MAC: %s\r\n", str);
        Serial.printf("Auto-randomize: %s\r\n", _cfg.randomMacDefault ? "on" : "off");
        return;
    }
    if (strcasecmp(args, "autorand on") == 0 || strcasecmp(args, "autorand true") == 0) {
        _cfg.randomMacDefault = true;
        netConfigSave(_cfg);
        Serial.println("MAC auto-randomize enabled (will randomize before operations).");
        return;
    }
    if (strcasecmp(args, "autorand off") == 0 || strcasecmp(args, "autorand false") == 0) {
        _cfg.randomMacDefault = false;
        netConfigSave(_cfg);
        Serial.println("MAC auto-randomize disabled.");
        return;
    }
    if (strncasecmp(args, "autorand", 8) == 0) {
        Serial.printf("MAC auto-randomize: %s\r\n", _cfg.randomMacDefault ? "on" : "off");
        Serial.println("Usage: mac autorand on|off");
        return;
    }
    if (strcasecmp(args, "random") == 0 || strcasecmp(args, "rand") == 0) {
        // Generate a random locally-administered unicast MAC
        uint32_t r1 = esp_random(), r2 = esp_random();
        _src[0] = (uint8_t)((r1 & 0xFC) | 0x02);  // locally administered, unicast
        _src[1] = (uint8_t)(r1 >> 8);
        _src[2] = (uint8_t)(r1 >> 16);
        _src[3] = (uint8_t)(r1 >> 24);
        _src[4] = (uint8_t)(r2 & 0xFF);
        _src[5] = (uint8_t)(r2 >> 8);
        _inj.setSrcMac(_src);
        _rfc.setSrcMac(_src);
        _ip.setMac(_src);
        char str[18]; macToStr(_src, str);
        Serial.printf("Source MAC randomized: %s\r\n", str);
        return;
    }
    uint8_t mac[6];
    if (!strToMac(args, mac)) {
        Serial.println("Invalid MAC. Format: XX:XX:XX:XX:XX:XX or 'random'");
        return;
    }
    memcpy(_src, mac, 6);
    _inj.setSrcMac(_src);
    _rfc.setSrcMac(_src);
    _ip.setMac(_src);
    char str[18]; macToStr(_src, str);
    Serial.printf("Source MAC set to: %s\r\n", str);
}

void CLI::_cmdTarget(char *args)
{
    if (!args || *args == '\0') {
        char str[18]; macToStr(_dst, str);
        Serial.printf("Target MAC: %s\r\n", str);
        return;
    }
    uint8_t mac[6];
    if (!strToMac(args, mac)) {
        Serial.println("Invalid MAC. Format: XX:XX:XX:XX:XX:XX");
        return;
    }
    memcpy(_dst, mac, 6);
    _inj.setDstMac(_dst);
    _rfc.setDstMac(_dst);
    char str[18]; macToStr(_dst, str);
    Serial.printf("Target MAC set to: %s\r\n", str);
}

// =============================================================================
// loopback
// =============================================================================
void CLI::_cmdLoopback(char *args)
{
    if (!args || *args == '\0') {
        Serial.printf("Loopback: %s\r\n", _loopback ? "on" : "off");
        return;
    }
    if (strcasecmp(args, "on")  == 0) { _loopback = true;  Serial.println("Loopback on."); }
    else if (strcasecmp(args, "off") == 0) { _loopback = false; Serial.println("Loopback off."); }
    else Serial.println("Usage: loopback on|off");
}

// =============================================================================
// send
// =============================================================================
void CLI::_cmdSend(char *args)
{
    if (!args || *args == '\0') {
        Serial.println("Usage: send <count> [size]");
        return;
    }
    char *tok = strtok(args, " \t");
    uint32_t count = (tok) ? (uint32_t)atol(tok) : 1;
    tok = strtok(nullptr, " \t");
    uint16_t size  = (tok) ? _parseFrameSize(tok, 64) : 64;

    uint16_t frameLen = size - 4;  // without FCS
    if (frameLen < ETH_HDR_LEN + 1) frameLen = ETH_MIN_LEN;
    if (frameLen > ETH_MAX_LEN)     frameLen = ETH_MAX_LEN;

    static uint8_t buf[ETH_MAX_LEN + 4];
    buildTestFrame(buf, _dst, _src, frameLen, PayloadPattern::INCR);

    Serial.printf("Sending %lu x %u-byte frames...\r\n", count, size);
    uint32_t sent = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (_eth.sendFrame(buf, frameLen)) sent++;
    }
    Serial.printf("Done. Sent %lu / %lu.\r\n", sent, count);
}

// =============================================================================
// inject
// =============================================================================
void CLI::_cmdInject(char *args)
{
    if (!args || *args == '\0') {
        Serial.println("Usage: inject <runt|giant|jumbo|broadcast|multicast|badtype|pause|pattern|storm|stop> [args]");
        return;
    }

    char *sub = strtok(args, " \t");
    char *rest = strtok(nullptr, "");
    if (rest) while (*rest == ' ') rest++;

    if (strcasecmp(sub, "runt") == 0) {
        _inj.injectRunts(_parseCount(rest));

    } else if (strcasecmp(sub, "giant") == 0) {
        _inj.injectGiants(_parseCount(rest));

    } else if (strcasecmp(sub, "jumbo") == 0) {
        uint32_t cnt = INJECT_DEFAULT_COUNT;
        uint16_t sz  = ETH_JUMBO_LEN;
        if (rest) {
            char *t = strtok(rest, " \t");
            if (t) cnt = (uint32_t)atol(t);
            t = strtok(nullptr, " \t");
            if (t) sz = (uint16_t)atoi(t);
        }
        _inj.injectJumbo(cnt, sz);

    } else if (strcasecmp(sub, "broadcast") == 0) {
        _inj.injectBroadcast(_parseCount(rest));

    } else if (strcasecmp(sub, "multicast") == 0) {
        _inj.injectMulticast(_parseCount(rest));

    } else if (strcasecmp(sub, "badtype") == 0) {
        _inj.injectBadEthertype(_parseCount(rest));

    } else if (strcasecmp(sub, "pause") == 0) {
        uint32_t cnt = INJECT_DEFAULT_COUNT;
        uint16_t q   = 0xFFFF;
        if (rest) {
            char *t = strtok(rest, " \t");
            if (t) cnt = (uint32_t)atol(t);
            t = strtok(nullptr, " \t");
            if (t) q = (uint16_t)atol(t);
        }
        _inj.injectPauseFrames(cnt, q);

    } else if (strcasecmp(sub, "pattern") == 0) {
        PayloadPattern pat = PayloadPattern::ALT;
        uint16_t len = ETH_MIN_LEN;
        uint32_t cnt = INJECT_DEFAULT_COUNT;

        if (rest) {
            char *t = strtok(rest, " \t");
            if (t) {
                if      (strcasecmp(t, "zeros")  == 0) pat = PayloadPattern::ZEROS;
                else if (strcasecmp(t, "ones")   == 0) pat = PayloadPattern::ONES;
                else if (strcasecmp(t, "alt")    == 0) pat = PayloadPattern::ALT;
                else if (strcasecmp(t, "incr")   == 0) pat = PayloadPattern::INCR;
                else if (strcasecmp(t, "random") == 0) pat = PayloadPattern::RANDOM;
                else { Serial.println("Pattern: zeros|ones|alt|incr|random"); return; }
            }
            t = strtok(nullptr, " \t");
            if (t) len = _parseFrameSize(t, ETH_MIN_LEN + 4) - 4;
            t = strtok(nullptr, " \t");
            if (t) cnt = (uint32_t)atol(t);
        }
        _inj.injectPayloadPattern(pat, len, cnt);

    } else if (strcasecmp(sub, "storm") == 0) {
        uint32_t rate = rest ? (uint32_t)atol(rest) : 0;
        if (rate == 0) { _inj.stopStorm(); }
        else           { _inj.startStorm(rate); }

    } else if (strcasecmp(sub, "continuous") == 0) {
        if (!rest || *rest == '\0') {
            Serial.println("Usage: inject continuous <giant|jumbo|badtype|broadcast|multicast|pause|pattern> <rate_hz> [size]");
            Serial.println("       inject continuous stop");
            return;
        }
        char *t = strtok(rest, " \t");
        if (strcasecmp(t, "stop") == 0) { _inj.stopContinuous(); return; }

        ErrorInject::ContType ct;
        if      (strcasecmp(t, "giant")     == 0) ct = ErrorInject::ContType::GIANT;
        else if (strcasecmp(t, "jumbo")     == 0) ct = ErrorInject::ContType::JUMBO;
        else if (strcasecmp(t, "badtype")   == 0) ct = ErrorInject::ContType::BADTYPE;
        else if (strcasecmp(t, "broadcast") == 0) ct = ErrorInject::ContType::BROADCAST;
        else if (strcasecmp(t, "multicast") == 0) ct = ErrorInject::ContType::MULTICAST;
        else if (strcasecmp(t, "pause")     == 0) ct = ErrorInject::ContType::PAUSE;
        else if (strcasecmp(t, "pattern")   == 0) ct = ErrorInject::ContType::PATTERN;
        else { Serial.printf("Unknown continuous type: '%s'\r\n", t); return; }

        uint32_t rate = 1000;
        uint16_t sz   = ETH_MIN_LEN;
        t = strtok(nullptr, " \t");
        if (t) rate = (uint32_t)atol(t);
        t = strtok(nullptr, " \t");
        if (t) sz = (uint16_t)atoi(t);
        _inj.startContinuous(ct, rate, sz);

    } else if (strcasecmp(sub, "stop") == 0) {
        _inj.stopStorm();
        _inj.stopContinuous();

    } else {
        Serial.printf("Unknown inject subcommand: '%s'\r\n", sub);
    }
}

// =============================================================================
// test
// =============================================================================
void CLI::_cmdTest(char *args)
{
    if (!args || *args == '\0') {
        Serial.println("Usage: test <throughput|latency|frameloss|backtoback|all> [size]");
        return;
    }

    char *sub  = strtok(args, " \t");
    char *rest = strtok(nullptr, " \t");

    if (strcasecmp(sub, "all") == 0) {
        _rfc.runFullSuite();
        return;
    }

    uint16_t sz = _parseFrameSize(rest, 64);

    if      (strcasecmp(sub, "throughput")  == 0) _rfc.testThroughput(sz, RFC2544_TEST_SEC);
    else if (strcasecmp(sub, "latency")     == 0) _rfc.testLatency(sz, 0);
    else if (strcasecmp(sub, "frameloss")   == 0) _rfc.testFrameLoss(sz, RFC2544_TEST_SEC);
    else if (strcasecmp(sub, "backtoback")  == 0) _rfc.testBackToBack(sz);
    else Serial.printf("Unknown test: '%s'\r\n", sub);
}

// =============================================================================
// discover — listen for and decode LLDP/CDP neighbour frames
// =============================================================================
void CLI::_cmdDiscover(char *args)
{
    uint32_t secs = 65;   // covers both LLDP (~30 s) and CDP (~60 s) intervals
    if (args && *args != '\0') {
        uint32_t v = (uint32_t)atol(args);
        if (v > 0) secs = v;
    }
    discoveryListen(_eth, secs);
}

// =============================================================================
// advertise — configure and toggle LLDP/CDP transmission
// =============================================================================
void CLI::advertiseTick()
{
    discoveryAdvertTick(_eth, _src, _advert);
}

static void _printAdvert(const DiscoveryAdvert &a)
{
    Serial.println("\r\nAdvertisement config:");
    Serial.printf("  LLDP      : %s\r\n", a.lldpEnabled ? "on" : "off");
    Serial.printf("  CDP       : %s\r\n", a.cdpEnabled  ? "on" : "off");
    Serial.printf("  Name      : %s\r\n", a.sysName);
    Serial.printf("  Port ID   : %s\r\n", a.portId);
    Serial.printf("  Platform  : %s\r\n", a.platform);
    if (a.mgmtIp)
        Serial.printf("  Mgmt IP   : %u.%u.%u.%u\r\n",
                      (a.mgmtIp >> 24) & 0xFF, (a.mgmtIp >> 16) & 0xFF,
                      (a.mgmtIp >>  8) & 0xFF,  a.mgmtIp        & 0xFF);
    else
        Serial.println("  Mgmt IP   : (none)");
    if (a.vlan) Serial.printf("  VLAN      : %u\r\n", a.vlan);
    else        Serial.println("  VLAN      : (none)");
    Serial.printf("  TTL       : %u s\r\n",  a.ttl);
    Serial.printf("  Interval  : %lu s\r\n", (unsigned long)(a.intervalMs / 1000));
}

void CLI::_cmdAdvertise(char *args)
{
    if (!args || *args == '\0') {
        _printAdvert(_advert);
        return;
    }

    char *sub = strtok(args, " \t");
    char *val = strtok(nullptr, "");        // rest of line (may be nullptr)
    if (val) while (*val == ' ') val++;

    if (strcasecmp(sub, "off") == 0) {
        _advert.lldpEnabled = false;
        _advert.cdpEnabled  = false;
        Serial.println("Advertisement disabled (LLDP + CDP).");
        return;
    }

    if (strcasecmp(sub, "lldp") == 0 || strcasecmp(sub, "cdp") == 0) {
        bool on = (val && strcasecmp(val, "on") == 0);
        bool ok = (val && (on || strcasecmp(val, "off") == 0));
        if (!ok) { Serial.printf("Usage: advertise %s on|off\r\n", sub); return; }
        if (strcasecmp(sub, "lldp") == 0) _advert.lldpEnabled = on;
        else                              _advert.cdpEnabled  = on;
        Serial.printf("%s advertisement %s.\r\n",
                      (strcasecmp(sub, "lldp") == 0) ? "LLDP" : "CDP",
                      on ? "enabled" : "disabled");
        return;
    }

    if (!val || *val == '\0') {
        Serial.printf("Missing value for 'advertise %s'.\r\n", sub);
        return;
    }

    if (strcasecmp(sub, "name") == 0) {
        strncpy(_advert.sysName, val, sizeof(_advert.sysName) - 1);
        _advert.sysName[sizeof(_advert.sysName) - 1] = '\0';
        Serial.printf("Name set to '%s'.\r\n", _advert.sysName);
    } else if (strcasecmp(sub, "port") == 0) {
        strncpy(_advert.portId, val, sizeof(_advert.portId) - 1);
        _advert.portId[sizeof(_advert.portId) - 1] = '\0';
        Serial.printf("Port ID set to '%s'.\r\n", _advert.portId);
    } else if (strcasecmp(sub, "platform") == 0) {
        strncpy(_advert.platform, val, sizeof(_advert.platform) - 1);
        _advert.platform[sizeof(_advert.platform) - 1] = '\0';
        Serial.printf("Platform set to '%s'.\r\n", _advert.platform);
    } else if (strcasecmp(sub, "ip") == 0) {
        unsigned a, b, c, d;
        if (sscanf(val, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
            a < 256 && b < 256 && c < 256 && d < 256) {
            _advert.mgmtIp = ((uint32_t)a << 24) | (b << 16) | (c << 8) | d;
            Serial.printf("Mgmt IP set to %u.%u.%u.%u%s.\r\n", a, b, c, d,
                          _advert.mgmtIp ? "" : " (none)");
        } else {
            Serial.println("Invalid IPv4 address.");
        }
    } else if (strcasecmp(sub, "vlan") == 0) {
        _advert.vlan = (uint16_t)atoi(val);
        Serial.printf("VLAN set to %u.\r\n", _advert.vlan);
    } else if (strcasecmp(sub, "ttl") == 0) {
        uint32_t v = (uint32_t)atol(val);
        if (v < 1) v = 1;
        if (v > 65535) v = 65535;
        _advert.ttl = (uint16_t)v;
        Serial.printf("TTL set to %u s.\r\n", _advert.ttl);
    } else if (strcasecmp(sub, "interval") == 0) {
        uint32_t v = (uint32_t)atol(val);
        if (v < 1) v = 1;
        _advert.intervalMs = v * 1000UL;
        Serial.printf("Interval set to %lu s.\r\n", (unsigned long)v);
    } else {
        Serial.printf("Unknown advertise option: '%s'\r\n", sub);
    }
}

// =============================================================================
// Helpers for IP parsing / printing
// =============================================================================
static bool parseIp(const char *s, uint32_t *out)
{
    unsigned a, b, c, d;
    if (!s || sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *out = ((uint32_t)a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

static void ipStr(uint32_t ip, char *out)
{
    sprintf(out, "%u.%u.%u.%u",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

// =============================================================================
// ip — IP stack address configuration
// =============================================================================
void CLI::_cmdIp(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub || strcasecmp(sub, "show") == 0) {
        char a[16], m[16], g[16];
        ipStr(_ip.ip(), a); ipStr(_ip.mask(), m); ipStr(_ip.gw(), g);
        Serial.printf("\r\nIP:      %s\r\nMask:    %s\r\nGateway: %s\r\n", a, m, g);
        return;
    }

    if (strcasecmp(sub, "dhcp") == 0) {
        _cfg.useDhcp = true;
        netConfigSave(_cfg);
        DhcpLease lease;
        _dhcp.discover(lease, true);
        return;
    }

    if (strcasecmp(sub, "static") == 0) {
        uint32_t ip, mask, gw;
        char *aip  = strtok(nullptr, " \t");
        char *amsk = strtok(nullptr, " \t");
        char *agw  = strtok(nullptr, " \t");
        if (!parseIp(aip, &ip) || !parseIp(amsk, &mask) || !parseIp(agw, &gw)) {
            Serial.println("Usage: ip static <ip> <mask> <gw>");
            return;
        }
        _ip.setAddress(ip, mask, gw);
        _cfg.useDhcp = false;
        _cfg.staticIp = ip; _cfg.staticMask = mask; _cfg.staticGw = gw;
        netConfigSave(_cfg);
        Serial.println("Static IP applied and saved.");
        return;
    }

    Serial.println("Usage: ip <show|dhcp|static <ip> <mask> <gw>>");
}

// =============================================================================
// dhcp — DHCP server verification / failure scenarios
// =============================================================================
void CLI::_cmdDhcp(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) {
        Serial.println("Usage: dhcp <discover|detect|flood [n]|decline|nak [ip]|malformed|renew [secs]>");
        return;
    }
    char *rest = strtok(nullptr, " \t");

    if (strcasecmp(sub, "discover") == 0) {
        DhcpLease lease;
        _dhcp.discover(lease, true);
    } else if (strcasecmp(sub, "detect") == 0) {
        _dhcp.detectServer();
    } else if (strcasecmp(sub, "flood") == 0) {
        uint32_t n = rest ? (uint32_t)atol(rest) : 50;
        if (n == 0) n = 50;
        _dhcp.floodDiscover(n);
    } else if (strcasecmp(sub, "decline") == 0) {
        _dhcp.declineTest();
    } else if (strcasecmp(sub, "nak") == 0) {
        uint32_t bogus = ipv4(192, 0, 2, 123);   // TEST-NET-1, unlikely in pool
        if (rest) parseIp(rest, &bogus);
        _dhcp.nakTest(bogus);
    } else if (strcasecmp(sub, "malformed") == 0) {
        _dhcp.malformedTest();
    } else if (strcasecmp(sub, "renew") == 0) {
        uint32_t secs = rest ? (uint32_t)atol(rest) : 60;
        if (secs == 0) secs = 60;
        _dhcp.renewTest(secs);
    } else if (strcasecmp(sub, "rogue") == 0) {
        if (!_requireArmed()) return;
        char *t2 = strtok(nullptr, " \t");
        char *t3 = strtok(nullptr, " \t");
        char *t4 = strtok(nullptr, " \t");
        char *t5 = strtok(nullptr, " \t");
        uint32_t pool = 0, mask = 0xFFFFFF00UL, gw = 0, dns = 0, secs = 120;
        if (!rest || !parseIp(rest, &pool)) {
            Serial.println("Usage: dhcp rogue <pool-start-ip> [mask] [gw] [dns] [secs]");
            return;
        }
        if (t2) parseIp(t2, &mask);
        if (t3) parseIp(t3, &gw);
        if (t4) parseIp(t4, &dns);
        if (t5) secs = (uint32_t)atol(t5);
        _dhcp.rogueServer(pool, mask, gw, dns, secs);
    } else {
        Serial.printf("Unknown dhcp subcommand: '%s'\r\n", sub);
    }
}

// =============================================================================
// probe — resolve a .local hostname via mDNS and ping it
// =============================================================================
void CLI::_cmdProbe(char *args)
{
    if (!args || *args == '\0') {
        Serial.println("Usage: probe <hostname>");
        return;
    }
    if (!_requireIp()) return;
    char *name = strtok(args, " \t");
    probeHostname(_ip, name, 4);
}

// =============================================================================
// wifi — Wi-Fi credential / enable configuration (persisted to NVS)
// =============================================================================
void CLI::_cmdWifi(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    char *val = strtok(nullptr, "");
    if (val) while (*val == ' ') val++;

    if (!sub) {
        Serial.printf("\r\nWi-Fi enabled : %s\r\n", _cfg.wifiEnabled ? "yes" : "no");
        Serial.printf("Mgmt mode     : %s\r\n", _cfg.apMode ? "access point (field)" : "infrastructure (station)");
        Serial.printf("SSID          : %s\r\n", _cfg.wifiSsid[0] ? _cfg.wifiSsid : "(unset)");
        Serial.printf("Password      : %s\r\n", _cfg.wifiPass[0] ? "(set)" : "(unset)");
        Serial.printf("AP SSID       : %s\r\n", _cfg.apSsid[0] ? _cfg.apSsid : "(hostname)");
        Serial.printf("AP password   : %s\r\n",
                      (strlen(_cfg.apPass) >= 8) ? "(WPA2 set)" : "(open)");
        Serial.printf("Hostname      : %s\r\n", _cfg.hostname);

        // Live management interface status
        wifi_mode_t mode = WiFi.getMode();
        if (WiFi.status() == WL_CONNECTED) {
            Serial.printf("State         : station connected\r\n");
            Serial.printf("Mgmt IP       : %s\r\n", WiFi.localIP().toString().c_str());
            Serial.printf("Netmask       : %s\r\n", WiFi.subnetMask().toString().c_str());
            Serial.printf("Gateway       : %s\r\n", WiFi.gatewayIP().toString().c_str());
            Serial.printf("RSSI          : %d dBm\r\n", WiFi.RSSI());
            Serial.printf("URL           : http://%s/  (or http://%s.local/)\r\n",
                          WiFi.localIP().toString().c_str(), _cfg.hostname);
        } else if (mode == WIFI_AP || mode == WIFI_AP_STA) {
            Serial.printf("State         : access point (%d client(s))\r\n", WiFi.softAPgetStationNum());
            Serial.printf("AP SSID (live): %s\r\n", WiFi.softAPSSID().c_str());
            Serial.printf("Mgmt IP       : %s\r\n", WiFi.softAPIP().toString().c_str());
            Serial.printf("URL           : http://%s/\r\n", WiFi.softAPIP().toString().c_str());
        } else {
            Serial.printf("State         : not connected\r\n");
        }
        Serial.println("(reboot to apply saved changes)");
        return;
    }

    if (strcasecmp(sub, "ssid") == 0 && val) {
        strncpy(_cfg.wifiSsid, val, sizeof(_cfg.wifiSsid) - 1);
        _cfg.wifiSsid[sizeof(_cfg.wifiSsid) - 1] = '\0';
        netConfigSave(_cfg);
        Serial.printf("SSID saved: '%s'.\r\n", _cfg.wifiSsid);
    } else if (strcasecmp(sub, "pass") == 0 && val) {
        strncpy(_cfg.wifiPass, val, sizeof(_cfg.wifiPass) - 1);
        _cfg.wifiPass[sizeof(_cfg.wifiPass) - 1] = '\0';
        netConfigSave(_cfg);
        Serial.println("Password saved.");
    } else if (strcasecmp(sub, "on") == 0) {
        _cfg.wifiEnabled = true; netConfigSave(_cfg);
        Serial.println("Wi-Fi enabled on boot (reboot to apply).");
    } else if (strcasecmp(sub, "off") == 0) {
        _cfg.wifiEnabled = false; netConfigSave(_cfg);
        Serial.println("Wi-Fi disabled on boot (reboot to apply).");
    } else if (strcasecmp(sub, "mode") == 0 && val) {
        if (strcasecmp(val, "ap") == 0) {
            _cfg.apMode = true; netConfigSave(_cfg);
            Serial.println("Mgmt mode: access point (field use). Reboot to apply.");
        } else if (strcasecmp(val, "sta") == 0 || strcasecmp(val, "station") == 0) {
            _cfg.apMode = false; netConfigSave(_cfg);
            Serial.println("Mgmt mode: infrastructure (station). Reboot to apply.");
        } else {
            Serial.println("Usage: wifi mode ap|sta");
        }
    } else if (strcasecmp(sub, "apssid") == 0 && val) {
        strncpy(_cfg.apSsid, val, sizeof(_cfg.apSsid) - 1);
        _cfg.apSsid[sizeof(_cfg.apSsid) - 1] = '\0';
        netConfigSave(_cfg);
        Serial.printf("AP SSID saved: '%s'.\r\n", _cfg.apSsid);
    } else if (strcasecmp(sub, "appass") == 0) {
        if (val && strlen(val) > 0 && strlen(val) < 8) {
            Serial.println("AP password must be >= 8 chars (WPA2) or empty for an open network.");
        } else {
            if (val) { strncpy(_cfg.apPass, val, sizeof(_cfg.apPass) - 1); _cfg.apPass[sizeof(_cfg.apPass) - 1] = '\0'; }
            else     { _cfg.apPass[0] = '\0'; }
            netConfigSave(_cfg);
            Serial.printf("AP password %s.\r\n", _cfg.apPass[0] ? "saved (WPA2)" : "cleared (open network)");
        }
    } else if (strcasecmp(sub, "scan") == 0) {
        Serial.println("\r\nScanning for Wi-Fi networks (rogue-AP / evil-twin recon)...");
        int n = WiFi.scanNetworks();
        if (n <= 0) { Serial.println("No networks found (or scan unavailable in current mode)."); return; }
        Serial.printf("%d network(s):\r\n", n);
        Serial.println("  SSID                              CH  RSSI  ENC  BSSID");
        for (int i = 0; i < n; i++) {
            const char *enc;
            switch (WiFi.encryptionType(i)) {
                case WIFI_AUTH_OPEN:        enc = "OPEN"; break;
                case WIFI_AUTH_WEP:         enc = "WEP "; break;
                case WIFI_AUTH_WPA_PSK:     enc = "WPA "; break;
                case WIFI_AUTH_WPA2_PSK:    enc = "WPA2"; break;
                case WIFI_AUTH_WPA_WPA2_PSK:enc = "W12 "; break;
                case WIFI_AUTH_WPA3_PSK:    enc = "WPA3"; break;
                default:                    enc = "?   "; break;
            }
            Serial.printf("  %-32s  %2d  %4d  %s %s\r\n",
                          WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i),
                          enc, WiFi.BSSIDstr(i).c_str());
        }
        // Flag duplicate-SSID / different-BSSID (possible evil twin) against our config.
        if (_cfg.wifiSsid[0]) {
            int seen = 0;
            for (int i = 0; i < n; i++) if (WiFi.SSID(i) == _cfg.wifiSsid) seen++;
            if (seen > 1)
                Serial.printf("WARNING: %d APs advertise your SSID '%s' -- possible evil twin.\r\n",
                              seen, _cfg.wifiSsid);
        }
        WiFi.scanDelete();
    } else {
        Serial.println("Usage: wifi [ssid <s> | pass <p> | on | off | scan |");
        Serial.println("            mode ap|sta | apssid <s> | appass <p>]");
    }
}

// =============================================================================
// host — set device hostname (persisted to NVS)
// =============================================================================
void CLI::_cmdHost(char *args)
{
    if (!args || *args == '\0') {
        Serial.printf("Hostname: %s\r\n", _cfg.hostname);
        return;
    }
    char *name = strtok(args, " \t");
    strncpy(_cfg.hostname, name, sizeof(_cfg.hostname) - 1);
    _cfg.hostname[sizeof(_cfg.hostname) - 1] = '\0';
    netConfigSave(_cfg);
    Serial.printf("Hostname saved: '%s' (reboot to apply to mDNS responder).\r\n",
                  _cfg.hostname);
}

// =============================================================================
// dot1x — 802.1X (EAPOL) supplicant / AAA port authentication test
// =============================================================================
static void _printCertLine(const char *label, CertKind kind)
{
    if (certStoreExists(kind))
        Serial.printf("%s: present (%u bytes)\r\n", label, (unsigned)certStoreSize(kind));
    else
        Serial.printf("%s: (none)\r\n", label);
}

void CLI::_cmdDot1x(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    char *val = strtok(nullptr, "");
    if (val) while (*val == ' ') val++;

    if (!sub || strcasecmp(sub, "status") == 0) {
        const char *mname = _cfg.dot1xMethod == 1 ? "EAP-TLS (certificate)"
                          : _cfg.dot1xMethod == 2 ? "PEAPv0/EAP-MSCHAPv2 (password)"
                          : _cfg.dot1xMethod == 3 ? "EAP-TTLS/PAP (password)"
                          : _cfg.dot1xMethod == 4 ? "EAP-TTLS/MSCHAPv2 (password)"
                          :                         "EAP-MD5 (password)";
        Serial.printf("\r\nEAP method      : %s\r\n", mname);
        Serial.printf("802.1X identity : %s\r\n",
                      _cfg.dot1xUser[0] ? _cfg.dot1xUser : "(unset)");
        Serial.printf("802.1X password : %s\r\n",
                      _cfg.dot1xPass[0] ? "(set)" : "(unset)");
        Serial.printf("Key passphrase  : %s\r\n",
                      _cfg.dot1xKeyPass[0] ? "(set)" : "(none)");
        // Show target if set
        {
            bool hasMac = false;
            for (int i = 0; i < 6; i++) if (_cfg.dot1xTarget[i]) { hasMac = true; break; }
            if (hasMac)
                Serial.printf("Target MAC      : %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                    _cfg.dot1xTarget[0], _cfg.dot1xTarget[1], _cfg.dot1xTarget[2],
                    _cfg.dot1xTarget[3], _cfg.dot1xTarget[4], _cfg.dot1xTarget[5]);
            else
                Serial.println("Target MAC      : (PAE multicast)");
            if (_cfg.dot1xTargetIp) {
                char tbuf[16]; ipToStr(_cfg.dot1xTargetIp, tbuf);
                Serial.printf("Target IP       : %s\r\n", tbuf);
            }
        }
        _printCertLine("CA certificate  ", CertKind::CA);
        _printCertLine("Client cert     ", CertKind::CLIENT);
        _printCertLine("Client key      ", CertKind::KEY);
        Serial.println("Subcommands: method md5|tls|peap|ttls-pap|ttls-mschap | probe |");
        Serial.println("             auth [user] [pass] | user <name> | pass <pw> |");
        Serial.println("             keypass <pw> | target <MAC|IP|clear> |");
        Serial.println("             cert [clear ca|client|key|all] | logoff");
        return;
    }

    if (strcasecmp(sub, "method") == 0) {
        if (val && strcasecmp(val, "tls") == 0) {
            _cfg.dot1xMethod = 1; netConfigSave(_cfg);
            Serial.println("EAP method set to EAP-TLS (certificate based).");
        } else if (val && strcasecmp(val, "peap") == 0) {
            _cfg.dot1xMethod = 2; netConfigSave(_cfg);
            Serial.println("EAP method set to PEAPv0/EAP-MSCHAPv2 (password based).");
        } else if (val && strcasecmp(val, "ttls-pap") == 0) {
            _cfg.dot1xMethod = 3; netConfigSave(_cfg);
            Serial.println("EAP method set to EAP-TTLS / PAP (password based).");
        } else if (val && strcasecmp(val, "ttls-mschap") == 0) {
            _cfg.dot1xMethod = 4; netConfigSave(_cfg);
            Serial.println("EAP method set to EAP-TTLS / MS-CHAPv2 (password based).");
        } else if (val && (strcasecmp(val, "md5") == 0)) {
            _cfg.dot1xMethod = 0; netConfigSave(_cfg);
            Serial.println("EAP method set to EAP-MD5 (password based).");
        } else {
            Serial.println("Usage: dot1x method md5|tls|peap|ttls-pap|ttls-mschap");
        }

    } else if (strcasecmp(sub, "user") == 0 && val) {
        strncpy(_cfg.dot1xUser, val, sizeof(_cfg.dot1xUser) - 1);
        _cfg.dot1xUser[sizeof(_cfg.dot1xUser) - 1] = '\0';
        netConfigSave(_cfg);
        Serial.printf("802.1X username saved: '%s'.\r\n", _cfg.dot1xUser);

    } else if (strcasecmp(sub, "pass") == 0 && val) {
        strncpy(_cfg.dot1xPass, val, sizeof(_cfg.dot1xPass) - 1);
        _cfg.dot1xPass[sizeof(_cfg.dot1xPass) - 1] = '\0';
        netConfigSave(_cfg);
        Serial.println("802.1X password saved.");

    } else if (strcasecmp(sub, "keypass") == 0) {
        if (val) { strncpy(_cfg.dot1xKeyPass, val, sizeof(_cfg.dot1xKeyPass) - 1);
                   _cfg.dot1xKeyPass[sizeof(_cfg.dot1xKeyPass) - 1] = '\0'; }
        else     { _cfg.dot1xKeyPass[0] = '\0'; }
        netConfigSave(_cfg);
        Serial.printf("Private-key passphrase %s.\r\n",
                      _cfg.dot1xKeyPass[0] ? "saved" : "cleared");

    } else if (strcasecmp(sub, "target") == 0) {
        if (!val || strcasecmp(val, "clear") == 0 || strcasecmp(val, "none") == 0) {
            memset(_cfg.dot1xTarget, 0, 6);
            _cfg.dot1xTargetIp = 0;
            netConfigSave(_cfg);
            Serial.println("802.1X target cleared (using PAE multicast).");
        } else {
            // Try MAC first, then IP
            uint8_t tmac[6];
            uint32_t tip;
            if (strToMac(val, tmac)) {
                memcpy(_cfg.dot1xTarget, tmac, 6);
                netConfigSave(_cfg);
                Serial.printf("802.1X target MAC set: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                    tmac[0], tmac[1], tmac[2], tmac[3], tmac[4], tmac[5]);
            } else if (strToIp(val, &tip)) {
                _cfg.dot1xTargetIp = tip;
                netConfigSave(_cfg);
                char buf[16]; ipToStr(tip, buf);
                Serial.printf("802.1X target IP set: %s\r\n", buf);
                // Also try to resolve MAC via ARP
                Serial.println("Use 'arp resolve <ip>' to populate the target MAC if needed.");
            } else {
                Serial.println("Usage: dot1x target <MAC|IP|clear>");
            }
        }

    } else if (strcasecmp(sub, "cert") == 0) {
        char *op   = val ? strtok(val, " \t") : nullptr;
        char *what = strtok(nullptr, " \t");
        if (!op) {
            _printCertLine("CA certificate ", CertKind::CA);
            _printCertLine("Client cert    ", CertKind::CLIENT);
            _printCertLine("Client key     ", CertKind::KEY);
            Serial.println("Upload certificates from the web UI. 'dot1x cert clear ca|client|key|all'.");
        } else if (strcasecmp(op, "clear") == 0 && what) {
            if (strcasecmp(what, "ca") == 0)       { certStoreDelete(CertKind::CA);     Serial.println("CA certificate removed."); }
            else if (strcasecmp(what, "client") == 0) { certStoreDelete(CertKind::CLIENT); Serial.println("Client certificate removed."); }
            else if (strcasecmp(what, "key") == 0) { certStoreDelete(CertKind::KEY);    Serial.println("Client key removed."); }
            else if (strcasecmp(what, "all") == 0) {
                certStoreDelete(CertKind::CA); certStoreDelete(CertKind::CLIENT); certStoreDelete(CertKind::KEY);
                Serial.println("All certificates removed.");
            } else Serial.println("Usage: dot1x cert clear ca|client|key|all");
        } else {
            Serial.println("Usage: dot1x cert [clear ca|client|key|all]");
        }

    } else if (strcasecmp(sub, "probe") == 0) {
        Dot1xTest d1x(_eth, _src);
        d1x.setTarget(_cfg.dot1xTarget);
        d1x.probe();

    } else if (strcasecmp(sub, "auth") == 0) {
        if (_cfg.dot1xMethod == 1) {
            // EAP-TLS: load the uploaded certificate material.
            String ca, cert, key;
            bool haveCa = certStoreRead(CertKind::CA, ca);
            if (!certStoreRead(CertKind::CLIENT, cert) || !certStoreRead(CertKind::KEY, key)) {
                Serial.println("EAP-TLS: upload a client certificate and key first (see web UI).");
                return;
            }
            Dot1xTest d1x(_eth, _src);
            d1x.setTarget(_cfg.dot1xTarget);
            d1x.authenticateTls(_cfg.dot1xUser,
                                haveCa ? ca.c_str() : nullptr,
                                cert.c_str(), key.c_str(),
                                _cfg.dot1xKeyPass[0] ? _cfg.dot1xKeyPass : nullptr);
        } else if (_cfg.dot1xMethod == 2) {
            // PEAPv0 / EAP-MSCHAPv2: username + password, optional CA cert.
            const char *user = _cfg.dot1xUser;
            const char *pass = _cfg.dot1xPass;
            char u[33] = {0}, p[65] = {0};
            if (val && *val) {                   // optional inline "user pass"
                char *a1 = strtok(val, " \t");
                char *a2 = strtok(nullptr, " \t");
                if (a1) { strncpy(u, a1, sizeof(u) - 1); user = u; }
                if (a2) { strncpy(p, a2, sizeof(p) - 1); pass = p; }
            }
            if (!user[0] || !pass[0]) {
                Serial.println("PEAP: set 'dot1x user' and 'dot1x pass' (or pass them inline).");
                return;
            }
            String ca;
            bool haveCa = certStoreRead(CertKind::CA, ca);
            Dot1xTest d1x(_eth, _src);
            d1x.setTarget(_cfg.dot1xTarget);
            d1x.authenticatePeap("anonymous", user, pass,
                                 haveCa ? ca.c_str() : nullptr);
        } else if (_cfg.dot1xMethod == 3 || _cfg.dot1xMethod == 4) {
            // EAP-TTLS: inner PAP (3) or MS-CHAPv2 (4).
            const char *user = _cfg.dot1xUser;
            const char *pass = _cfg.dot1xPass;
            char u[33] = {0}, p[65] = {0};
            if (val && *val) {                   // optional inline "user pass"
                char *a1 = strtok(val, " \t");
                char *a2 = strtok(nullptr, " \t");
                if (a1) { strncpy(u, a1, sizeof(u) - 1); user = u; }
                if (a2) { strncpy(p, a2, sizeof(p) - 1); pass = p; }
            }
            if (!user[0] || !pass[0]) {
                Serial.println("EAP-TTLS: set 'dot1x user' and 'dot1x pass' (or pass them inline).");
                return;
            }
            String ca;
            bool haveCa = certStoreRead(CertKind::CA, ca);
            Dot1xTest d1x(_eth, _src);
            d1x.setTarget(_cfg.dot1xTarget);
            d1x.authenticateTtls("anonymous", user, pass,
                                 haveCa ? ca.c_str() : nullptr,
                                 _cfg.dot1xMethod == 4);
        } else {
            const char *user = _cfg.dot1xUser;
            const char *pass = _cfg.dot1xPass;
            char u[33] = {0}, p[65] = {0};
            if (val && *val) {                   // optional inline "user pass"
                char *a1 = strtok(val, " \t");
                char *a2 = strtok(nullptr, " \t");
                if (a1) { strncpy(u, a1, sizeof(u) - 1); user = u; }
                if (a2) { strncpy(p, a2, sizeof(p) - 1); pass = p; }
            }
            Dot1xTest d1x(_eth, _src);
            d1x.setTarget(_cfg.dot1xTarget);
            d1x.authenticate(user, pass);
        }

    } else if (strcasecmp(sub, "logoff") == 0) {
        Dot1xTest d1x(_eth, _src);
        d1x.setTarget(_cfg.dot1xTarget);
        d1x.logoff();

    } else if (strcasecmp(sub, "startflood") == 0) {
        if (!_requireArmed()) return;
        char *a1 = val ? strtok(val, " \t") : nullptr;
        uint32_t cnt = a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 1000;
        Dot1xTest d1x(_eth, _src);
        d1x.setTarget(_cfg.dot1xTarget);
        d1x.startFlood(cnt, true);

    } else if (strcasecmp(sub, "logoffmac") == 0) {
        if (!_requireArmed()) return;
        uint8_t vm[6];
        if (!val || !strToMac(val, vm)) { Serial.println("Usage: dot1x logoffmac <XX:XX:XX:XX:XX:XX>"); return; }
        Dot1xTest d1x(_eth, _src);
        d1x.setTarget(_cfg.dot1xTarget);
        d1x.logoffSpoof(vm);

    } else if (strcasecmp(sub, "mab") == 0) {
        char *a1 = val ? strtok(val, " \t") : nullptr;
        Dot1xTest d1x(_eth, _src);
        d1x.setTarget(_cfg.dot1xTarget);
        d1x.mabProbe(a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 15);

    } else if (strcasecmp(sub, "rogue") == 0) {
        if (!_requireArmed()) return;
        char *a1 = val ? strtok(val, " \t") : nullptr;
        char *a2 = a1 ? strtok(nullptr, " \t") : nullptr;
        uint32_t secs = a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 60;
        bool mschap = true;
        if (a2 && strcasecmp(a2, "md5") == 0) mschap = false;
        rogueAuthStart(_eth, _src, mschap, secs);

    } else {
        Serial.println("Usage: dot1x [method md5|tls|peap|ttls-pap|ttls-mschap | probe |");
        Serial.println("             auth [user] [pass] | user <name> | pass <pw> |");
        Serial.println("             keypass <pw> | cert [clear ca|client|key|all] | logoff |");
        Serial.println("             rogue [secs] [md5]]");
    }
}

// =============================================================================
// Authorized (lab) mode gate for offensive / DoS tests
// =============================================================================
void CLI::_cmdArm(char *args)
{
    if (args && (strcasecmp(args, "on") == 0 || strcasecmp(args, "yes") == 0)) {
        _cfg.authorizedMode = true; netConfigSave(_cfg);
        Serial.println("Authorized (lab) mode ENABLED.");
        Serial.println("Offensive tests (l2/arp/scan storms, spoofing, floods) are now permitted.");
        Serial.println("Use only on networks you are explicitly authorized to test. 'disarm' to revoke.");
        return;
    }
    Serial.printf("\r\nAuthorized (lab) mode: %s\r\n", _cfg.authorizedMode ? "ENABLED" : "disabled");
    Serial.println("Type 'arm on' to enable disruptive/offensive tests (authorized use only).");
}

bool CLI::_requireArmed()
{
    if (_cfg.authorizedMode) return true;
    Serial.println("Refused: this is a disruptive/offensive test.");
    Serial.println("Enable authorized lab mode first with 'arm on' (authorized networks only).");
    return false;
}

bool CLI::_requireIp()
{
    if (_ip.ip() != 0) return true;
    Serial.println("No IP address configured. Run 'ip dhcp' or 'ip static <ip> <mask> <gw>' first.");
    return false;
}

// =============================================================================
// l2 -- Layer-2 switch assessment / attacks
// =============================================================================
void CLI::_cmdL2(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) {
        Serial.println("Usage: l2 vlan|dtag|dtp|macflood|stp|lldpflood|cdpflood ...");
        return;
    }

    if (strcasecmp(sub, "vlan") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        char *a3 = strtok(nullptr, " \t");
        uint16_t vid = a1 ? (uint16_t)atoi(a1) : 0;
        uint8_t pcp  = a2 ? (uint8_t)atoi(a2) : 0;
        uint32_t cnt = a3 ? (uint32_t)strtoul(a3, nullptr, 10) : 5;
        if (!vid) { Serial.println("Usage: l2 vlan <vid> [pcp] [count]"); return; }
        l2VlanSingle(_eth, _src, vid, pcp, cnt);

    } else if (strcasecmp(sub, "dtag") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        char *a3 = strtok(nullptr, " \t");
        if (!a1 || !a2) { Serial.println("Usage: l2 dtag <native> <target> [count]"); return; }
        uint32_t cnt = a3 ? (uint32_t)strtoul(a3, nullptr, 10) : 5;
        l2VlanDouble(_eth, _src, (uint16_t)atoi(a1), (uint16_t)atoi(a2), cnt);

    } else if (strcasecmp(sub, "dtp") == 0) {
        if (!_requireArmed()) return;
        l2DtpTrunk(_eth, _src);

    } else if (strcasecmp(sub, "macflood") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint32_t cnt  = a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 10000;
        uint32_t rate = a2 ? (uint32_t)strtoul(a2, nullptr, 10) : 0;
        l2MacFlood(_eth, cnt, rate);

    } else if (strcasecmp(sub, "stp") == 0) {
        char *op = strtok(nullptr, " \t");
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        if (op && strcasecmp(op, "listen") == 0) {
            l2StpListen(_eth, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 35);
        } else if (op && strcasecmp(op, "root") == 0) {
            if (!_requireArmed()) return;
            uint16_t prio = a1 ? (uint16_t)atoi(a1) : 0;
            uint32_t secs = a2 ? (uint32_t)strtoul(a2, nullptr, 10) : 30;
            l2StpRoot(_eth, _src, prio, secs);
        } else if (op && strcasecmp(op, "tcn") == 0) {
            if (!_requireArmed()) return;
            l2StpTcn(_eth, _src, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 50);
        } else {
            Serial.println("Usage: l2 stp listen [secs] | root [prio] [secs] | tcn [count]");
        }

    } else if (strcasecmp(sub, "lldpflood") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t");
        l2LldpFlood(_eth, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 500);

    } else if (strcasecmp(sub, "cdpflood") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t");
        l2CdpFlood(_eth, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 500);

    } else {
        Serial.println("Usage: l2 vlan|dtag|dtp|macflood|stp|lldpflood|cdpflood ...");
    }
}

// =============================================================================
// arp -- ARP assessment toolkit
// =============================================================================
void CLI::_cmdArp(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: arp scan|gratuitous|spoof|storm ..."); return; }

    if (strcasecmp(sub, "scan") == 0) {
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint32_t s, e;
        if (!a1 || !a2 || !strToIp(a1, &s) || !strToIp(a2, &e)) {
            Serial.println("Usage: arp scan <start-ip> <end-ip>"); return;
        }
        arpScan(_eth, _src, _ip.ip(), s, e);

    } else if (strcasecmp(sub, "gratuitous") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint32_t ip;
        if (!a1 || !strToIp(a1, &ip)) { Serial.println("Usage: arp gratuitous <ip> [count]"); return; }
        arpGratuitous(_eth, _src, ip, a2 ? (uint32_t)strtoul(a2, nullptr, 10) : 5);

    } else if (strcasecmp(sub, "spoof") == 0) {
        if (!_requireArmed()) return;
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        char *a3 = strtok(nullptr, " \t");
        uint32_t v, g;
        if (!a1 || !a2 || !strToIp(a1, &v) || !strToIp(a2, &g)) {
            Serial.println("Usage: arp spoof <victim-ip> <gateway-ip> [secs]"); return;
        }
        arpSpoof(_eth, _ip, _src, v, g, a3 ? (uint32_t)strtoul(a3, nullptr, 10) : 60);

    } else if (strcasecmp(sub, "storm") == 0) {
        if (!_requireArmed()) return;
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint32_t cnt  = a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 10000;
        uint32_t rate = a2 ? (uint32_t)strtoul(a2, nullptr, 10) : 0;
        arpStorm(_eth, _src, _ip.ip(), cnt, rate);

    } else {
        Serial.println("Usage: arp scan|gratuitous|spoof|storm ...");
    }
}

// =============================================================================
// scan -- TCP port scanner / banner grabber
// =============================================================================
void CLI::_cmdScan(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: scan common|ports|banner ..."); return; }
    if (!_requireIp()) return;

    if (strcasecmp(sub, "common") == 0) {
        char *a1 = strtok(nullptr, " \t");
        uint32_t t;
        if (!a1 || !strToIp(a1, &t)) { Serial.println("Usage: scan common <ip>"); return; }
        tcpScanCommon(_eth, _ip, t);

    } else if (strcasecmp(sub, "ports") == 0) {
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        char *a3 = strtok(nullptr, " \t");
        uint32_t t;
        if (!a1 || !a2 || !a3 || !strToIp(a1, &t)) {
            Serial.println("Usage: scan ports <ip> <first> <last>"); return;
        }
        tcpSynScan(_eth, _ip, t, (uint16_t)atoi(a2), (uint16_t)atoi(a3));

    } else if (strcasecmp(sub, "banner") == 0) {
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        char *probe = strtok(nullptr, "");      // remainder = optional probe string
        uint32_t t;
        if (!a1 || !a2 || !strToIp(a1, &t)) {
            Serial.println("Usage: scan banner <ip> <port> [probe-string]"); return;
        }
        if (probe) while (*probe == ' ') probe++;
        tcpBannerGrab(_eth, _ip, t, (uint16_t)atoi(a2), probe);

    } else {
        Serial.println("Usage: scan common|ports|banner ...");
    }
}

// =============================================================================
// recon -- reconnaissance (passive map / ping sweep / traceroute)
// =============================================================================
void CLI::_cmdRecon(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: recon passive|sweep|trace ..."); return; }

    if (strcasecmp(sub, "passive") == 0) {
        char *a1 = strtok(nullptr, " \t");
        reconPassive(_eth, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 30);

    } else if (strcasecmp(sub, "sweep") == 0) {
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint32_t s, e;
        if (!a1 || !a2 || !strToIp(a1, &s) || !strToIp(a2, &e)) {
            Serial.println("Usage: recon sweep <start-ip> <end-ip>"); return;
        }
        reconSweep(_eth, _ip, s, e);

    } else if (strcasecmp(sub, "trace") == 0) {
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint32_t t;
        if (!a1 || !strToIp(a1, &t)) { Serial.println("Usage: recon trace <ip> [maxhops]"); return; }
        reconTrace(_eth, _ip, t, a2 ? (uint8_t)atoi(a2) : 20);

    } else {
        Serial.println("Usage: recon passive|sweep|trace ...");
    }
}

// =============================================================================
// ipv6 -- IPv6 / NDP assessment
// =============================================================================
void CLI::_cmdIpv6(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: ipv6 listen [secs] | rogue [lifetime] [count]"); return; }

    if (strcasecmp(sub, "listen") == 0) {
        char *a1 = strtok(nullptr, " \t");
        ipv6Listen(_eth, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 30);

    } else if (strcasecmp(sub, "rogue") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint16_t life = a1 ? (uint16_t)atoi(a1) : 1800;
        uint32_t cnt  = a2 ? (uint32_t)strtoul(a2, nullptr, 10) : 10;
        ipv6RogueRa(_eth, _src, life, cnt);

    } else {
        Serial.println("Usage: ipv6 listen [secs] | rogue [lifetime] [count]");
    }
}

// =============================================================================
// pcap -- packet capture to LittleFS
// =============================================================================
void CLI::_cmdPcap(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub || strcasecmp(sub, "status") == 0) {
        uint32_t sz = pcapSize();
        if (sz) Serial.printf("\r\nStored capture: %s (%s), %lu bytes. Download from the web UI.\r\n",
                              pcapPath(), pcapSdAvailable() ? "SD card" : "LittleFS",
                              (unsigned long)sz);
        else    Serial.println("\r\nNo capture stored. Use 'pcap start [secs] [maxframes]'.");
        Serial.printf("Storage: %s\r\n", pcapSdAvailable() ? "TF/SD card" : "internal flash (LittleFS)");
        Serial.println("Subcommands: start [secs] [maxframes] | status | delete");
        return;
    }

    if (strcasecmp(sub, "start") == 0) {
        char *a1 = strtok(nullptr, " \t");
        char *a2 = strtok(nullptr, " \t");
        uint32_t secs = a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 10;
        uint32_t maxf = a2 ? (uint32_t)strtoul(a2, nullptr, 10) : 0;
        pcapCapture(_eth, secs, maxf);

    } else if (strcasecmp(sub, "delete") == 0) {
        pcapDelete();
        Serial.println("Capture file deleted.");

    } else {
        Serial.println("Usage: pcap start [secs] [maxframes] | status | delete");
    }
}

// =============================================================================
// sd -- SD/TF card management
// =============================================================================
void CLI::_cmdSd(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub || strcasecmp(sub, "info") == 0) {
        if (pcapSdAvailable()) {
            Serial.printf("  SD card: mounted, %llu MB total, %llu MB used, %llu MB free\r\n",
                          SD.totalBytes() / (1024*1024),
                          SD.usedBytes()  / (1024*1024),
                          (SD.totalBytes() - SD.usedBytes()) / (1024*1024));
            Serial.printf("  Card type: ");
            switch (SD.cardType()) {
                case CARD_MMC:  Serial.println("MMC"); break;
                case CARD_SD:   Serial.println("SD"); break;
                case CARD_SDHC: Serial.println("SDHC"); break;
                default:        Serial.println("Unknown"); break;
            }
        } else {
            Serial.println("  SD card: not mounted");
            Serial.println("  Try: sd init | sd format");
        }
        return;
    }
    if (strcasecmp(sub, "init") == 0) {
        pcapSdInit();
        return;
    }
    if (strcasecmp(sub, "format") == 0) {
        Serial.println("WARNING: This will erase ALL data on the SD card!");
        Serial.println("Formatting...");
        if (pcapSdFormat()) {
            Serial.println("SD card formatted successfully.");
        } else {
            Serial.println("SD format failed.");
        }
        return;
    }
    if (strcasecmp(sub, "ls") == 0 || strcasecmp(sub, "list") == 0) {
        char *path = strtok(nullptr, " \t");
        if (!path) path = (char *)"/";
        if (!pcapSdAvailable()) { Serial.println("  SD not available."); return; }
        File dir = SD.open(path);
        if (!dir || !dir.isDirectory()) {
            Serial.printf("  Cannot open directory: %s\r\n", path);
            return;
        }
        Serial.printf("  Directory: %s\r\n", path);
        int count = 0;
        File f = dir.openNextFile();
        while (f) {
            if (f.isDirectory()) {
                Serial.printf("    [DIR]  %s/\r\n", f.name());
            } else {
                Serial.printf("    %8u  %s\r\n", (uint32_t)f.size(), f.name());
            }
            count++;
            f = dir.openNextFile();
        }
        dir.close();
        if (count == 0) Serial.println("    (empty)");
        return;
    }
    if (strcasecmp(sub, "cat") == 0 || strcasecmp(sub, "read") == 0) {
        char *path = strtok(nullptr, " \t");
        if (!path) { Serial.println("Usage: sd cat <filepath>"); return; }
        if (!pcapSdAvailable()) { Serial.println("  SD not available."); return; }
        File f = SD.open(path, FILE_READ);
        if (!f) { Serial.printf("  Cannot open: %s\r\n", path); return; }
        Serial.printf("--- %s (%u bytes) ---\r\n", path, (uint32_t)f.size());
        while (f.available()) {
            char buf[128];
            int n = f.readBytes(buf, sizeof(buf) - 1);
            buf[n] = '\0';
            Serial.print(buf);
        }
        Serial.println("\r\n--- end ---");
        f.close();
        return;
    }
    if (strcasecmp(sub, "rm") == 0 || strcasecmp(sub, "delete") == 0) {
        char *path = strtok(nullptr, " \t");
        if (!path) { Serial.println("Usage: sd rm <filepath>"); return; }
        if (!pcapSdAvailable()) { Serial.println("  SD not available."); return; }
        if (SD.remove(path)) Serial.printf("  Deleted: %s\r\n", path);
        else Serial.printf("  Failed to delete: %s\r\n", path);
        return;
    }
    if (strcasecmp(sub, "rename") == 0 || strcasecmp(sub, "mv") == 0) {
        char *src = strtok(nullptr, " \t");
        char *dst = strtok(nullptr, " \t");
        if (!src || !dst) { Serial.println("Usage: sd rename <old_path> <new_path>"); return; }
        if (!pcapSdAvailable()) { Serial.println("  SD not available."); return; }
        if (SD.rename(src, dst)) Serial.printf("  Renamed: %s -> %s\r\n", src, dst);
        else Serial.printf("  Rename failed.\r\n");
        return;
    }
    if (strcasecmp(sub, "mkdir") == 0) {
        char *path = strtok(nullptr, " \t");
        if (!path) { Serial.println("Usage: sd mkdir <path>"); return; }
        if (!pcapSdAvailable()) { Serial.println("  SD not available."); return; }
        if (SD.mkdir(path)) Serial.printf("  Created: %s/\r\n", path);
        else Serial.printf("  mkdir failed.\r\n");
        return;
    }
    if (strcasecmp(sub, "write") == 0) {
        char *path = strtok(nullptr, " \t");
        char *text = strtok(nullptr, "");
        if (!path) { Serial.println("Usage: sd write <filepath> <text>"); return; }
        if (!pcapSdAvailable()) { Serial.println("  SD not available."); return; }
        File f = SD.open(path, FILE_APPEND);
        if (!f) { Serial.printf("  Cannot open: %s\r\n", path); return; }
        if (text && text[0]) {
            f.println(text);
        }
        f.close();
        Serial.printf("  Appended to %s\r\n", path);
        return;
    }
    Serial.println("Usage: sd [info|init|format|ls [path]|cat <file>|rm <file>|rename <old> <new>|mkdir <path>|write <file> <text>]");
}

// =============================================================================
// wg -- WireGuard VPN tunnel configuration
// =============================================================================
void CLI::_cmdWg(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;

    // wg (no args) or wg status — show current state
    if (!sub || strcasecmp(sub, "status") == 0) {
        const WgConfig &c = wgGetConfig();
        Serial.printf("  WireGuard: %s\r\n", wgIsActive() ? "ACTIVE" : "inactive");
        Serial.printf("  Enabled:   %s\r\n", c.enabled ? "yes" : "no");
        Serial.printf("  Local IP:  %s\r\n", c.localIp[0] ? c.localIp : "(not set)");
        Serial.printf("  Endpoint:  %s:%u\r\n", c.endpoint[0] ? c.endpoint : "(not set)", c.endpointPort);
        Serial.printf("  Peer key:  %s\r\n", c.peerPubKey[0] ? c.peerPubKey : "(not set)");
        Serial.printf("  Priv key:  %s\r\n", c.privateKey[0] ? "(set)" : "(not set)");
        Serial.printf("  PSK:       %s\r\n", c.presharedKey[0] ? "(set)" : "none");
        Serial.printf("  TCP CLI:   port %d\r\n", WG_TCP_PORT);
        return;
    }

    if (strcasecmp(sub, "set") == 0) {
        char *field = strtok(nullptr, " \t");
        char *value = strtok(nullptr, "");  // rest of line
        if (!field || !value) {
            Serial.println("Usage: wg set <field> <value>");
            Serial.println("  Fields: localip, privkey, pubkey, endpoint, port, psk");
            return;
        }
        // Trim leading whitespace from value
        while (*value == ' ' || *value == '\t') value++;

        WgConfig cfg = wgGetConfig();
        if (strcasecmp(field, "localip") == 0) {
            strlcpy(cfg.localIp, value, sizeof(cfg.localIp));
        } else if (strcasecmp(field, "privkey") == 0) {
            strlcpy(cfg.privateKey, value, sizeof(cfg.privateKey));
        } else if (strcasecmp(field, "pubkey") == 0) {
            strlcpy(cfg.peerPubKey, value, sizeof(cfg.peerPubKey));
        } else if (strcasecmp(field, "endpoint") == 0) {
            strlcpy(cfg.endpoint, value, sizeof(cfg.endpoint));
        } else if (strcasecmp(field, "port") == 0) {
            cfg.endpointPort = (uint16_t)atoi(value);
        } else if (strcasecmp(field, "psk") == 0) {
            strlcpy(cfg.presharedKey, value, sizeof(cfg.presharedKey));
        } else if (strcasecmp(field, "weboff") == 0) {
            cfg.webOff = (strcasecmp(value, "on") == 0 || strcasecmp(value, "1") == 0 || strcasecmp(value, "true") == 0);
        } else {
            Serial.printf("Unknown field: %s\r\n", field);
            return;
        }
        wgSaveConfig(cfg);
        Serial.printf("  %s = %s (saved)\r\n", field,
                      (strcasecmp(field, "privkey") == 0 || strcasecmp(field, "psk") == 0)
                          ? "(hidden)" : value);
        return;
    }

    if (strcasecmp(sub, "enable") == 0) {
        WgConfig cfg = wgGetConfig();
        cfg.enabled = true;
        wgSaveConfig(cfg);
        Serial.println("[WG] Enabled. Tunnel will auto-start when Wi-Fi connects.");
        Serial.println("     Run 'wg start' to start now, or reboot.");
        return;
    }

    if (strcasecmp(sub, "disable") == 0) {
        WgConfig cfg = wgGetConfig();
        cfg.enabled = false;
        wgSaveConfig(cfg);
        wgStop();
        Serial.println("[WG] Disabled and stopped.");
        return;
    }

    if (strcasecmp(sub, "start") == 0) {
        if (wgStart()) {
            wgTcpListenerStart();
        }
        return;
    }

    if (strcasecmp(sub, "stop") == 0) {
        wgStop();
        return;
    }

    if (strcasecmp(sub, "clear") == 0) {
        wgStop();
        wgClearConfig();
        Serial.println("[WG] Config cleared.");
        return;
    }

    Serial.println("Usage: wg [status] | set <field> <value> | enable | disable | start | stop | clear");
    Serial.println("  Fields: localip, privkey, pubkey, endpoint, port, psk");
}

// =============================================================================
// web -- Web server control, auth, HTTPS
// =============================================================================
extern WebControl web;

void CLI::_cmdWeb(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;

    // No subcommand: show status
    if (!sub) {
        Serial.printf("  Server:  %s\r\n", web.isServerRunning() ? "RUNNING" : "STOPPED");
        Serial.printf("  Auth:    %s\r\n", web.isAuthEnabled() ? "ENABLED" : "DISABLED");
        Serial.printf("  HTTPS:   %s\r\n", web.isHttpsEnabled() ? "ENABLED" : "DISABLED");
        return;
    }

    if (strcasecmp(sub, "on") == 0) {
        web.startServer();
        return;
    }
    if (strcasecmp(sub, "off") == 0) {
        web.stopServer();
        return;
    }
    if (strcasecmp(sub, "auth") == 0) {
        char *action = strtok(nullptr, " \t");
        if (!action) { Serial.println("Usage: web auth set <user> <pass> | web auth clear"); return; }
        if (strcasecmp(action, "set") == 0) {
            char *user = strtok(nullptr, " \t");
            char *pass = strtok(nullptr, " \t");
            if (!user || !pass) { Serial.println("Usage: web auth set <username> <password>"); return; }
            web.setAuthCredentials(user, pass);
            Serial.printf("[WEB] Auth set: user=%s\r\n", user);
            return;
        }
        if (strcasecmp(action, "clear") == 0) {
            web.clearAuth();
            Serial.println("[WEB] Auth cleared.");
            return;
        }
        Serial.println("Usage: web auth set <user> <pass> | web auth clear");
        return;
    }
    if (strcasecmp(sub, "https") == 0) {
        char *val = strtok(nullptr, " \t");
        if (!val) { Serial.println("Usage: web https on|off"); return; }
        bool on = (strcasecmp(val, "on") == 0 || strcasecmp(val, "1") == 0);
        web.enableHttps(on);
        Serial.printf("[WEB] HTTPS %s\r\n", on ? "enabled" : "disabled");
        return;
    }

    Serial.println("Usage: web [on|off] | auth set <user> <pass> | auth clear | https on|off");
}

// =============================================================================
// fhrp -- HSRP / VRRP listen and hijack
// =============================================================================
void CLI::_cmdFhrp(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: fhrp listen [secs] | hsrp <group> <vip> [prio] [count] | vrrp <vrid> <vip> [prio] [count]"); return; }

    if (strcasecmp(sub, "listen") == 0) {
        char *a1 = strtok(nullptr, " \t");
        fhrpListen(_eth, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 30);

    } else if (strcasecmp(sub, "hsrp") == 0) {
        if (!_requireArmed()) return;
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t"); // group
        char *a2 = strtok(nullptr, " \t"); // virtualIp
        char *a3 = strtok(nullptr, " \t"); // priority
        char *a4 = strtok(nullptr, " \t"); // count
        uint32_t vip;
        if (!a1 || !a2 || !strToIp(a2, &vip)) {
            Serial.println("Usage: fhrp hsrp <group> <virtual-ip> [priority] [count]"); return;
        }
        uint8_t grp = (uint8_t)atoi(a1);
        uint8_t prio = a3 ? (uint8_t)atoi(a3) : 255;
        uint32_t cnt = a4 ? (uint32_t)strtoul(a4, nullptr, 10) : 10;
        hsrpHijack(_eth, _src, _ip.ip(), grp, vip, prio, cnt);

    } else if (strcasecmp(sub, "vrrp") == 0) {
        if (!_requireArmed()) return;
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t"); // vrid
        char *a2 = strtok(nullptr, " \t"); // virtualIp
        char *a3 = strtok(nullptr, " \t"); // priority
        char *a4 = strtok(nullptr, " \t"); // count
        uint32_t vip;
        if (!a1 || !a2 || !strToIp(a2, &vip)) {
            Serial.println("Usage: fhrp vrrp <vrid> <virtual-ip> [priority] [count]"); return;
        }
        uint8_t vrid = (uint8_t)atoi(a1);
        uint8_t prio = a3 ? (uint8_t)atoi(a3) : 255;
        uint32_t cnt = a4 ? (uint32_t)strtoul(a4, nullptr, 10) : 10;
        vrrpHijack(_eth, _src, _ip.ip(), vrid, vip, prio, cnt);

    } else {
        Serial.println("Usage: fhrp listen [secs] | hsrp <group> <vip> [prio] [count] | vrrp <vrid> <vip> [prio] [count]");
    }
}

// =============================================================================
// dhcpv6 -- DHCPv6 probe and rogue server
// =============================================================================
void CLI::_cmdDhcpv6(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: dhcpv6 probe [secs] | rogue <prefix> <dns> [secs]"); return; }

    if (strcasecmp(sub, "probe") == 0) {
        char *a1 = strtok(nullptr, " \t");
        dhcpv6Probe(_eth, _src, a1 ? (uint32_t)strtoul(a1, nullptr, 10) : 10);

    } else if (strcasecmp(sub, "rogue") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t"); // prefix (e.g. "2001:db8:1::1")
        char *a2 = strtok(nullptr, " \t"); // dns    (e.g. "2001:db8:1::53")
        char *a3 = strtok(nullptr, " \t"); // seconds
        if (!a1 || !a2) {
            Serial.println("Usage: dhcpv6 rogue <prefix-ipv6> <dns-ipv6> [secs]");
            Serial.println("  e.g. dhcpv6 rogue 2001:db8:1::1 2001:db8:1::53 60");
            return;
        }
        // Parse IPv6 addresses using lwIP-style or simple colon-hex
        uint8_t prefix[16], dns[16];
        memset(prefix, 0, 16); memset(dns, 0, 16);
        // Simple IPv6 parser: delegate to inet_pton-equivalent
        struct in6_addr p6, d6;
        if (!inet_pton(AF_INET6, a1, &p6) || !inet_pton(AF_INET6, a2, &d6)) {
            Serial.println("Invalid IPv6 address format.");
            return;
        }
        memcpy(prefix, &p6, 16);
        memcpy(dns, &d6, 16);
        uint32_t secs = a3 ? (uint32_t)strtoul(a3, nullptr, 10) : 60;
        dhcpv6Rogue(_eth, _src, prefix, dns, secs);

    } else {
        Serial.println("Usage: dhcpv6 probe [secs] | rogue <prefix> <dns> [secs]");
    }
}

// =============================================================================
// dns -- unicast DNS resolve and DNS spoof
// =============================================================================
void CLI::_cmdDns(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: dns resolve <hostname> [server-ip] | spoof <ip> [secs]"); return; }

    if (strcasecmp(sub, "resolve") == 0) {
        if (!_requireIp()) return;
        char *a1 = strtok(nullptr, " \t"); // hostname
        char *a2 = strtok(nullptr, " \t"); // optional DNS server IP
        if (!a1) { Serial.println("Usage: dns resolve <hostname> [dns-server-ip]"); return; }
        uint32_t srv = 0;
        if (a2) strToIp(a2, &srv);
        dnsResolve(_eth, _ip, a1, srv);

    } else if (strcasecmp(sub, "spoof") == 0) {
        if (!_requireArmed()) return;
        char *a1 = strtok(nullptr, " \t"); // spoof IP
        char *a2 = strtok(nullptr, " \t"); // seconds
        uint32_t sip;
        if (!a1 || !strToIp(a1, &sip)) {
            Serial.println("Usage: dns spoof <spoofed-ip> [secs]"); return;
        }
        uint32_t secs = a2 ? (uint32_t)strtoul(a2, nullptr, 10) : 60;
        dnsSpoof(_eth, _src, sip, secs);

    } else {
        Serial.println("Usage: dns resolve <hostname> [server-ip] | spoof <ip> [secs]");
    }
}

// =============================================================================
// snmp -- SNMP reconnaissance
// =============================================================================
void CLI::_cmdSnmp(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub) { Serial.println("Usage: snmp probe <ip> [comm1 comm2 ...] | sweep <cidr|start> [end] [community]"); return; }
    if (!_requireIp()) return;

    if (strcasecmp(sub, "probe") == 0) {
        char *a1 = strtok(nullptr, " \t"); // target IP
        uint32_t t;
        if (!a1 || !strToIp(a1, &t)) { Serial.println("Usage: snmp probe <ip> [community ...]"); return; }
        // Collect optional community strings
        const char *comms[16];
        uint8_t nComms = 0;
        char *c = strtok(nullptr, " \t");
        while (c && nComms < 16) { comms[nComms++] = c; c = strtok(nullptr, " \t"); }
        snmpProbe(_eth, _ip, t, nComms > 0 ? comms : nullptr, nComms);

    } else if (strcasecmp(sub, "sweep") == 0) {
        char *a1 = strtok(nullptr, " \t"); // CIDR or start IP
        char *a2 = strtok(nullptr, " \t"); // end IP or community (if CIDR)
        char *a3 = strtok(nullptr, " \t"); // community (if start/end)
        uint32_t s, e;
        if (!a1) {
            Serial.println("Usage: snmp sweep <cidr|start-ip> [end-ip] [community]"); return;
        }
        const char *comm = "public";
        if (strchr(a1, '/')) {
            // CIDR notation
            if (!cidrToRange(a1, &s, &e)) {
                Serial.println("Invalid CIDR. Example: snmp sweep 192.168.1.0/24"); return;
            }
            if (a2) comm = a2;  // community follows CIDR
        } else {
            if (!a2 || !strToIp(a1, &s) || !strToIp(a2, &e)) {
                Serial.println("Usage: snmp sweep <cidr|start-ip> [end-ip] [community]"); return;
            }
            if (a3) comm = a3;
        }
        snmpSweep(_eth, _ip, s, e, comm);

    } else if (strcasecmp(sub, "writetest") == 0 || strcasecmp(sub, "write") == 0) {
        char *a1 = strtok(nullptr, " \t"); // target IP
        char *a2 = strtok(nullptr, " \t"); // optional write community
        uint32_t t;
        if (!a1 || !strToIp(a1, &t)) {
            Serial.println("Usage: snmp writetest <ip> [write-community]"); return;
        }
        snmpWriteTest(_eth, _ip, t, a2 ? a2 : "private");

    } else {
        Serial.println("Usage: snmp probe <ip> [comm...] | sweep <cidr|start> [end] [comm] | writetest <ip> [comm]");
    }
}

// =============================================================================
// assess -- combined network assessment (ping + ARP + port scan)
// =============================================================================
void CLI::_cmdAssess(char *args)
{
    if (!_requireIp()) return;

    char *a1 = args ? strtok(args, " \t") : nullptr;
    if (!a1) {
        Serial.println("Usage: assess <start-ip> <end-ip> [ports] [-r] [-m]");
        Serial.println("       assess <cidr> [ports] [-r] [-m]");
        Serial.println("Ports: comma-separated (default: 21,22,80,443)");
        Serial.println("  -r   Randomize host/port scan order");
        Serial.println("  -m   Randomize source MAC per target host");
        Serial.println("Example: assess 192.168.1.0/24 80,443,8080 -r -m");
        return;
    }

    uint32_t startIp, endIp;
    char *portArg = nullptr;
    uint8_t flags = 0;

    // Try CIDR first
    if (strchr(a1, '/')) {
        if (!cidrToRange(a1, &startIp, &endIp)) {
            Serial.println("Invalid CIDR notation. Example: 192.168.1.0/24");
            return;
        }
        portArg = strtok(nullptr, " \t");
    } else {
        // start-ip end-ip format
        char *a2 = strtok(nullptr, " \t");
        if (!a2 || !strToIp(a1, &startIp) || !strToIp(a2, &endIp)) {
            Serial.println("Usage: assess <start-ip> <end-ip> [ports] [-r] [-m]");
            Serial.println("       assess <cidr> [ports] [-r] [-m]");
            return;
        }
        portArg = strtok(nullptr, " \t");
    }

    // Parse remaining tokens: port list and flags
    uint16_t ports[64];
    uint32_t nPorts = 0;

    // Process portArg and any further tokens
    while (portArg) {
        if (strcmp(portArg, "-r") == 0) {
            flags |= ASSESS_RANDOMIZE_ORDER;
        } else if (strcmp(portArg, "-m") == 0) {
            flags |= ASSESS_RANDOMIZE_MAC;
        } else if (nPorts == 0 && portArg[0] != '-') {
            // Parse comma-separated port numbers
            char portBuf[256];
            strncpy(portBuf, portArg, sizeof(portBuf) - 1);
            portBuf[sizeof(portBuf) - 1] = '\0';
            char *tok = strtok(portBuf, ",");
            while (tok && nPorts < 64) {
                int p = atoi(tok);
                if (p > 0 && p <= 65535) {
                    ports[nPorts++] = (uint16_t)p;
                }
                tok = strtok(nullptr, ",");
            }
        }
        portArg = strtok(nullptr, " \t");
    }

    netAssess(_eth, _ip, _src, startIp, endIp,
              nPorts > 0 ? ports : nullptr, nPorts, flags);
}

// =============================================================================
// OTA update
// =============================================================================
void CLI::_cmdOta(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;
    if (!sub || strcasecmp(sub, "tftp") != 0) {
        Serial.println("Usage: ota tftp <server-ip> [filename]");
        Serial.println("  Default filename: firmware.bin");
        return;
    }

    char *ip = strtok(nullptr, " \t");
    char *fn = strtok(nullptr, " \t");

    if (!ip) {
        Serial.println("Usage: ota tftp <server-ip> [filename]");
        return;
    }

    if (!_requireIp()) return;

    otaTftp(ip, fn ? fn : "firmware.bin");
}

// =============================================================================
// reboot / reset
// =============================================================================
void CLI::_cmdReboot()
{
    Serial.println("Rebooting...");
    Serial.flush();
    delay(500);            // allow serial + web capture to flush before reset
    ESP.restart();
}

// =============================================================================
// Web control interface helpers
// =============================================================================
void CLI::runCommand(const String &line)
{
    char tmp[CLI_BUF_SIZE];
    strncpy(tmp, line.c_str(), sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    _dispatch(tmp);
}

String CLI::statusJson()
{
    uint8_t phy  = _eth.phyCfgr();
    const EthStats &s = _eth.stats();
    char ipS[16], mS[16], gS[16], srcStr[18];
    ipStr(_ip.ip(), ipS); ipStr(_ip.mask(), mS); ipStr(_ip.gw(), gS);
    macToStr(_src, srcStr);

    String j = "{";
    j += "\"link\":\"";   j += (phy & PHYCFGR_LNK) ? "UP" : "DOWN"; j += "\",";
    j += "\"speed\":\"";  j += (phy & PHYCFGR_SPD) ? "100M" : "10M"; j += "\",";
    j += "\"duplex\":\""; j += (phy & PHYCFGR_DPX) ? "full" : "half"; j += "\",";
    j += "\"mac\":\"";    j += srcStr; j += "\",";
    j += "\"ip\":\"";     j += ipS; j += "\",";
    j += "\"mask\":\"";   j += mS; j += "\",";
    j += "\"gateway\":\"";j += gS; j += "\",";
    j += "\"tx_frames\":"; j += s.txFrames; j += ",";
    j += "\"rx_frames\":"; j += s.rxFrames; j += ",";
    j += "\"tx_errors\":"; j += s.txErrors; j += ",";
    j += "\"rx_dropped\":";j += s.rxDropped; j += ",";
    j += "\"storm\":\"";      j += _inj.isStormActive() ? "active" : "idle"; j += "\",";
    j += "\"continuous\":\""; j += _inj.isContinuousActive() ? _inj.continuousName() : "idle"; j += "\",";
    // System info
    j += "\"heap_free\":"; j += ESP.getFreeHeap(); j += ",";
    j += "\"heap_min\":";  j += ESP.getMinFreeHeap(); j += ",";
    j += "\"psram_free\":"; j += ESP.getFreePsram(); j += ",";
    j += "\"uptime_s\":";  j += (uint32_t)(esp_timer_get_time() / 1000000ULL); j += ",";
    // SD card storage
    j += "\"sd_present\":"; j += pcapSdAvailable() ? "true" : "false"; j += ",";
    if (pcapSdAvailable()) {
        j += "\"sd_total_mb\":"; j += (uint32_t)(SD.totalBytes() / (1024 * 1024)); j += ",";
        j += "\"sd_used_mb\":";  j += (uint32_t)(SD.usedBytes()  / (1024 * 1024)); j += ",";
    }
    // LittleFS (internal flash)
    j += "\"fs_total_kb\":"; j += (uint32_t)(LittleFS.totalBytes() / 1024); j += ",";
    j += "\"fs_used_kb\":";  j += (uint32_t)(LittleFS.usedBytes()  / 1024); j += ",";
    // PCAP file
    j += "\"pcap_size\":"; j += pcapSize(); j += ",";
    // Armed status
    j += "\"armed\":"; j += _cfg.authorizedMode ? "true" : "false"; j += ",";
    // Mgmt IP (Wi-Fi)
    j += "\"mgmt_ip\":\""; j += WiFi.localIP().toString(); j += "\",";
    // Version
    j += "\"version\":\""; j += FW_VERSION; j += "\"";
    j += "}";
    return j;
}

// =============================================================================
// script -- Run CLI command scripts from SD card
// =============================================================================
void CLI::_cmdScript(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;

    if (!sub) {
        Serial.println("  Script engine status:");
        Serial.printf("    Running: %s\r\n", scriptIsRunning() ? "YES" : "no");
        if (scriptIsRunning())
            Serial.printf("    File:    %s\r\n", scriptCurrentFile());
        Serial.println("\r\n  Usage: script run <file> [logname]");
        Serial.println("         script list");
        Serial.println("         script stop");
        Serial.println("         script create <file>");
        return;
    }

    if (strcasecmp(sub, "run") == 0) {
        char *path = strtok(nullptr, " \t");
        char *logName = strtok(nullptr, " \t");
        if (!path) { Serial.println("Usage: script run <path> [logname]"); return; }
        // Prepend /scripts/ if no leading /
        char fullPath[80];
        if (path[0] == '/') {
            strlcpy(fullPath, path, sizeof(fullPath));
        } else {
            snprintf(fullPath, sizeof(fullPath), "/scripts/%s", path);
        }
        scriptRun(fullPath, logName);
        return;
    }

    if (strcasecmp(sub, "list") == 0) {
        if (!pcapSdAvailable()) { Serial.println("  SD card not available."); return; }
        if (!SD.exists("/scripts")) { Serial.println("  /scripts/ directory not found."); return; }
        File dir = SD.open("/scripts");
        if (!dir || !dir.isDirectory()) { Serial.println("  Cannot open /scripts/"); return; }
        Serial.println("  Scripts on SD:");
        int count = 0;
        File f = dir.openNextFile();
        while (f) {
            if (!f.isDirectory()) {
                Serial.printf("    %-30s %8u bytes\r\n", f.name(), (uint32_t)f.size());
                count++;
            }
            f = dir.openNextFile();
        }
        dir.close();
        if (count == 0) Serial.println("    (empty -- put .txt files in /scripts/)");
        return;
    }

    if (strcasecmp(sub, "stop") == 0) {
        if (scriptIsRunning()) {
            scriptAbort();
            Serial.println("[SCRIPT] Abort requested.");
        } else {
            Serial.println("  No script is running.");
        }
        return;
    }

    if (strcasecmp(sub, "create") == 0) {
        char *name = strtok(nullptr, " \t");
        if (!name) { Serial.println("Usage: script create <filename>"); return; }
        if (!pcapSdAvailable()) { Serial.println("  SD card not available."); return; }
        if (!SD.exists("/scripts")) SD.mkdir("/scripts");
        char path[80];
        snprintf(path, sizeof(path), "/scripts/%s", name);
        if (SD.exists(path)) {
            Serial.printf("  %s already exists.\r\n", path);
            return;
        }
        File f = SD.open(path, FILE_WRITE);
        if (!f) { Serial.printf("  Cannot create %s\r\n", path); return; }
        f.println("# Script: " + String(name));
        f.println("# Lines starting with # are comments");
        f.println("# Available directives: delay <ms>, wait <sec>, echo <msg>,");
        f.println("#   log start [name], log stop, set <var> <val>,");
        f.println("#   if_time HH:MM-HH:MM, if_day MON,TUE,...,");
        f.println("#   upload log <name> <url>, upload pcap <url>,");
        f.println("#   repeat <N> ... end_repeat, abort");
        f.println("# Any other line is executed as a CLI command.");
        f.println("");
        f.println("echo Script started");
        f.println("status");
        f.println("echo Script complete");
        f.close();
        Serial.printf("  Created %s (template). Edit on SD card.\r\n", path);
        return;
    }

    Serial.println("Usage: script run <file> [logname] | list | stop | create <file>");
}

// =============================================================================
// log -- Output logger control
// =============================================================================
void CLI::_cmdLog(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;

    if (!sub) {
        Serial.println("  Logger status:");
        Serial.printf("    Active: %s\r\n", logIsActive() ? "YES" : "no");
        if (logIsActive()) {
            Serial.printf("    File:   %s\r\n", logCurrentFile());
            Serial.printf("    Size:   %u bytes\r\n", logSize());
        }
        return;
    }

    if (strcasecmp(sub, "start") == 0) {
        char *name = strtok(nullptr, " \t");
        logStart(name);
        return;
    }
    if (strcasecmp(sub, "stop") == 0) {
        logStop();
        return;
    }
    if (strcasecmp(sub, "list") == 0) {
        logList();
        return;
    }
    if (strcasecmp(sub, "delete") == 0) {
        char *name = strtok(nullptr, " \t");
        if (!name) { Serial.println("Usage: log delete <filename>"); return; }
        if (logDelete(name)) Serial.printf("  Deleted %s\r\n", name);
        else Serial.printf("  Failed to delete %s\r\n", name);
        return;
    }
    if (strcasecmp(sub, "flush") == 0) {
        logFlush();
        Serial.println("  Log flushed.");
        return;
    }

    Serial.println("Usage: log [start [name] | stop | list | delete <file> | flush]");
}

// =============================================================================
// cron -- Scheduled task management
// =============================================================================
void CLI::_cmdCron(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;

    if (!sub || strcasecmp(sub, "list") == 0) {
        cronList();
        return;
    }

    if (strcasecmp(sub, "reload") == 0) {
        cronReload();
        Serial.println("  Cron entries reloaded from /cron.txt");
        return;
    }

    if (strcasecmp(sub, "add") == 0) {
        char *entry = strtok(nullptr, "");
        if (!entry) {
            Serial.println("Usage: cron add <min> <hour> <dom> <mon> <dow> <command>");
            Serial.println("  Example: cron add */5 * * * * status");
            Serial.println("  Example: cron add 0 8 * * 1-5 /scripts/morning.txt");
            return;
        }
        if (cronAdd(entry)) Serial.println("  Entry added.");
        else Serial.println("  Failed to add entry.");
        return;
    }

    if (strcasecmp(sub, "remove") == 0) {
        char *idx = strtok(nullptr, " \t");
        if (!idx) { Serial.println("Usage: cron remove <index>"); return; }
        int i = atoi(idx);
        if (cronRemove(i)) Serial.println("  Entry removed.");
        else Serial.println("  Invalid index.");
        return;
    }

    if (strcasecmp(sub, "clear") == 0) {
        cronClear();
        Serial.println("  All cron entries cleared.");
        return;
    }

    Serial.println("Usage: cron [list | reload | add <spec> <cmd> | remove <#> | clear]");
}

// =============================================================================
// upload -- File upload to remote server
// =============================================================================
void CLI::_cmdUpload(char *args)
{
    char *sub = args ? strtok(args, " \t") : nullptr;

    if (!sub) {
        char url[128], user[33], pass[65];
        uploadGetDefault(url, sizeof(url), user, sizeof(user), pass, sizeof(pass));
        Serial.println("  Upload configuration:");
        Serial.printf("    URL:  %s\r\n", url[0] ? url : "(not set)");
        Serial.printf("    User: %s\r\n", user[0] ? user : "(none)");
        return;
    }

    if (strcasecmp(sub, "set") == 0) {
        char *url  = strtok(nullptr, " \t");
        char *user = strtok(nullptr, " \t");
        char *pass = strtok(nullptr, " \t");
        if (!url) { Serial.println("Usage: upload set <url> [user] [pass]"); return; }
        uploadSetDefault(url, user, pass);
        return;
    }

    if (strcasecmp(sub, "clear") == 0) {
        uploadSetDefault("", nullptr, nullptr);
        Serial.println("  Upload destination cleared.");
        return;
    }

    if (strcasecmp(sub, "log") == 0) {
        char *name = strtok(nullptr, " \t");
        char *url  = strtok(nullptr, " \t");
        if (!name) { Serial.println("Usage: upload log <name> [url]"); return; }
        char logPath[80];
        snprintf(logPath, sizeof(logPath), "/logs/%s", name);
        if (!strstr(name, ".log")) strlcat(logPath, ".log", sizeof(logPath));
        if (url) {
            uploadFileHttp(logPath, url);
        } else {
            char defUrl[128], defUser[33], defPass[65];
            uploadGetDefault(defUrl, sizeof(defUrl), defUser, sizeof(defUser), defPass, sizeof(defPass));
            if (!defUrl[0]) { Serial.println("  No URL specified and no default set."); return; }
            uploadFileHttpAuth(logPath, defUrl, defUser, defPass);
        }
        return;
    }

    if (strcasecmp(sub, "pcap") == 0) {
        char *url = strtok(nullptr, " \t");
        const char *path = pcapPath();
        if (!path || pcapSize() == 0) { Serial.println("  No pcap file available."); return; }
        if (url) {
            uploadFileHttp(path, url);
        } else {
            char defUrl[128], defUser[33], defPass[65];
            uploadGetDefault(defUrl, sizeof(defUrl), defUser, sizeof(defUser), defPass, sizeof(defPass));
            if (!defUrl[0]) { Serial.println("  No URL specified and no default set."); return; }
            uploadFileHttpAuth(path, defUrl, defUser, defPass);
        }
        return;
    }

    if (strcasecmp(sub, "file") == 0) {
        char *path = strtok(nullptr, " \t");
        char *url  = strtok(nullptr, " \t");
        if (!path) { Serial.println("Usage: upload file <sd_path> [url]"); return; }
        if (url) {
            uploadFileHttp(path, url);
        } else {
            char defUrl[128], defUser[33], defPass[65];
            uploadGetDefault(defUrl, sizeof(defUrl), defUser, sizeof(defUser), defPass, sizeof(defPass));
            if (!defUrl[0]) { Serial.println("  No URL specified and no default set."); return; }
            uploadFileHttpAuth(path, defUrl, defUser, defPass);
        }
        return;
    }

    Serial.println("Usage: upload [set <url> [user pass] | clear | log <name> [url] | pcap [url] | file <path> [url]]");
}

// =============================================================================
// Argument parsers
// =============================================================================
uint16_t CLI::_parseFrameSize(const char *arg, uint16_t defaultSize)
{
    if (!arg || *arg == '\0') return defaultSize;
    uint16_t sz = (uint16_t)atoi(arg);
    if (sz < 64)   sz = 64;
    if (sz > 9000) sz = 9000;
    return sz;
}

uint32_t CLI::_parseCount(const char *arg, uint32_t defaultVal)
{
    if (!arg || *arg == '\0') return defaultVal;
    uint32_t v = (uint32_t)atol(arg);
    return (v == 0) ? defaultVal : v;
}

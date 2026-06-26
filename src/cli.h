#pragma once

#include <Arduino.h>
#include "../include/config.h"
#include "w5500_raw.h"
#include "error_inject.h"
#include "rfc2544.h"
#include "discovery.h"
#include "ip_stack.h"
#include "dhcp_test.h"
#include "net_config.h"

// =============================================================================
// Serial Command-Line Interface
//
// Commands (type `help` for the full list):
//
//   status                        Device / link status
//   stats                         Packet counters
//   stats clear                   Reset counters
//   mac <XX:XX:XX:XX:XX:XX>       Set source MAC
//   target <XX:XX:XX:XX:XX:XX>    Set destination MAC
//   loopback on|off               Enable/disable reflector mode
//   send <count> [size]           Send test frames
//
//   inject runt    [count]         Runt frames (<64 bytes on wire)
//   inject giant   [count]         Giant frames (>1518 bytes on wire)
//   inject badtype [count]         Frames with reserved EtherType
//   inject pause   [count [q]]     802.3x PAUSE frames
//   inject pattern <pat> [len] [count]
//                                  Stress pattern (zeros/ones/alt/incr/random)
//   inject storm   <rate_hz>       Broadcast storm (0 = stop)
//   inject stop                    Stop continuous injection
//
//   test throughput [size]         RFC 2544 throughput
//   test latency    [size]         RFC 2544 latency
//   test frameloss  [size]         RFC 2544 frame loss
//   test backtoback [size]         RFC 2544 back-to-back
//   test all                       Full RFC 2544 suite
// =============================================================================

class CLI {
public:
    CLI(W5500Raw    &eth,
        ErrorInject &inj,
        RFC2544     &rfc,
        IpStack     &ip,
        DhcpTest    &dhcp,
        NetConfig   &cfg,
        uint8_t     srcMac[6],
        uint8_t     dstMac[6]);

    void begin();
    void process();            // Call from loop()
    void loopbackTick();       // Call from loop() to drive reflector mode
    void advertiseTick();      // Call from loop() to drive LLDP/CDP advertisement

    // Execute a single command line (used by the web control interface).
    void runCommand(const String &line);

    // Build a JSON status object for the web UI.
    String statusJson();

private:
    W5500Raw    &_eth;
    ErrorInject &_inj;
    RFC2544     &_rfc;
    IpStack     &_ip;
    DhcpTest    &_dhcp;
    NetConfig   &_cfg;
    uint8_t     *_src;
    uint8_t     *_dst;

    char    _buf[CLI_BUF_SIZE];
    uint8_t _pos;
    bool    _loopback;
    DiscoveryAdvert _advert;
    void _printPrompt();
    void _dispatch(char *line);

    void _cmdHelp();
    void _cmdStatus();
    void _cmdStats(char *args);
    void _cmdMac(char *args);
    void _cmdTarget(char *args);
    void _cmdLoopback(char *args);
    void _cmdSend(char *args);
    void _cmdInject(char *args);
    void _cmdTest(char *args);
    void _cmdDiscover(char *args);
    void _cmdAdvertise(char *args);
    void _cmdWifi(char *args);
    void _cmdHost(char *args);
    void _cmdIp(char *args);
    void _cmdDhcp(char *args);
    void _cmdProbe(char *args);
    void _cmdDot1x(char *args);
    void _cmdArm(char *args);
    void _cmdL2(char *args);
    void _cmdArp(char *args);
    void _cmdScan(char *args);
    void _cmdRecon(char *args);
    void _cmdIpv6(char *args);
    void _cmdPcap(char *args);
    void _cmdSd(char *args);
    void _cmdWg(char *args);
    void _cmdWeb(char *args);
    void _cmdFhrp(char *args);
    void _cmdDhcpv6(char *args);
    void _cmdDns(char *args);
    void _cmdSnmp(char *args);
    bool _requireArmed();
    void _cmdReboot();

    static uint16_t _parseFrameSize(const char *arg, uint16_t defaultSize = 64);
    static uint32_t _parseCount(const char *arg, uint32_t defaultVal = INJECT_DEFAULT_COUNT);
};

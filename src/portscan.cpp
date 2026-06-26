#include "portscan.h"
#include "../include/config.h"
#include "net_util.h"
#include "weblog.h"
#include <esp_random.h>
#include <string.h>

#define Serial Out

// Module-level flag: whether to randomize port scan order
static bool s_randomize = false;

void tcpScanSetRandomize(bool enable) { s_randomize = enable; }

// TCP flag bits
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

// Build an Ethernet+IPv4+TCP frame. Returns total frame length (>=60).
static uint16_t buildTcp(uint8_t *f, const uint8_t dstMac[6], const uint8_t srcMac[6],
                         uint32_t srcIp, uint32_t dstIp, uint16_t srcPort, uint16_t dstPort,
                         uint32_t seq, uint32_t ack, uint8_t flags,
                         const uint8_t *data, uint16_t dataLen)
{
    memcpy(f, dstMac, 6);
    memcpy(f + 6, srcMac, 6);
    put16(f + 12, ETHERTYPE_IPV4);

    uint8_t *ipw = f + 14;
    uint16_t tcpLen = 20 + dataLen;
    uint16_t totalLen = 20 + tcpLen;
    ipw[0] = 0x45; ipw[1] = 0x00;
    put16(ipw + 2, totalLen);
    put16(ipw + 4, (uint16_t)(esp_random() & 0xFFFF));   // id
    put16(ipw + 6, 0x4000);                              // DF
    ipw[8] = 64; ipw[9] = 6;                             // TTL, proto=TCP
    put16(ipw + 10, 0);                                  // checksum (fill below)
    put32(ipw + 12, srcIp);
    put32(ipw + 16, dstIp);
    put16(ipw + 10, inetChecksum(ipw, 20));

    uint8_t *t = ipw + 20;
    put16(t + 0, srcPort);
    put16(t + 2, dstPort);
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = 0x50;          // data offset = 5 (20 bytes), no options
    t[13] = flags;
    put16(t + 14, 8192);   // window
    put16(t + 16, 0);      // checksum (fill below)
    put16(t + 18, 0);      // urgent
    if (dataLen) memcpy(t + 20, data, dataLen);

    // TCP checksum over pseudo-header + segment.
    uint8_t ph[12];
    put32(ph + 0, srcIp); put32(ph + 4, dstIp);
    ph[8] = 0; ph[9] = 6; put16(ph + 10, tcpLen);
    uint32_t sum = 0;
    for (int i = 0; i < 12; i += 2) sum += get16(ph + i);
    put16(t + 16, inetChecksum(t, tcpLen, sum));

    uint16_t flen = 14 + totalLen;
    if (flen < 60) { memset(f + flen, 0, 60 - flen); flen = 60; }
    return flen;
}

// Wait for a TCP segment from `fromIp:fromPort` to our `toPort`. On match,
// returns the TCP flags byte (>=0) and fills seq/ack; returns -1 on timeout.
static int waitTcp(W5500Raw &eth, uint32_t fromIp, uint16_t fromPort, uint16_t toPort,
                   uint32_t *rseq, uint32_t *rack, uint8_t *payload, uint16_t *payLen,
                   uint16_t payMax, uint32_t timeoutMs)
{
    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = eth.recvFrame(buf, sizeof(buf));
        if (len < 54 || get16(buf + 12) != ETHERTYPE_IPV4) { delay(1); continue; }
        const uint8_t *ipw = buf + 14;
        if ((ipw[0] >> 4) != 4 || ipw[9] != 6) continue;
        uint8_t ihl = (ipw[0] & 0x0F) * 4;
        if (get32(ipw + 12) != fromIp || get32(ipw + 16) == 0) continue;
        const uint8_t *t = ipw + ihl;
        if (get16(t + 0) != fromPort || get16(t + 2) != toPort) continue;
        if (rseq) *rseq = get32(t + 4);
        if (rack) *rack = get32(t + 8);
        uint8_t off = (t[12] >> 4) * 4;
        uint16_t ipTotal = get16(ipw + 2);
        int plen = (int)ipTotal - ihl - off;
        if (payload && payLen) {
            *payLen = 0;
            if (plen > 0) { if (plen > payMax) plen = payMax; memcpy(payload, t + off, plen); *payLen = plen; }
        }
        return t[13];   // flags
    }
    return -1;
}

static const char *stateStr(int flags)
{
    if (flags < 0) return "filtered";
    if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) return "open";
    if (flags & TCP_RST) return "closed";
    return "unknown";
}

static bool prep(IpStack &ip, uint32_t target, uint8_t dstMac[6], uint32_t *srcIp)
{
    *srcIp = ip.ip();
    if (*srcIp == 0) { Serial.println("No local IP configured (run DHCP or set static)."); return false; }
    bool needArp = false;
    ip.destMacFor(target, dstMac, &needArp);
    if (needArp) {
        uint32_t a = target;
        if (((target ^ ip.ip()) & ip.mask()) != 0) a = ip.gw();   // off-subnet -> gw
        if (!ip.arpResolve(a, dstMac, 1500)) { Serial.println("ARP resolve failed for next hop."); return false; }
    }
    return true;
}

// Fisher-Yates shuffle for uint16_t arrays (randomize scan order)
static void shufflePorts(uint16_t *arr, uint32_t n)
{
    for (uint32_t i = n - 1; i > 0; i--) {
        uint32_t j = esp_random() % (i + 1);
        uint16_t tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

static uint32_t scanList(W5500Raw &eth, IpStack &ip, uint32_t target,
                         const uint16_t *ports, uint32_t nPorts, uint32_t perPortMs)
{
    uint8_t dstMac[6]; uint32_t srcIp;
    if (!prep(ip, target, dstMac, &srcIp)) return 0;
    char ts[16]; ipToStr(target, ts);
    Serial.printf("\r\nTCP SYN scan of %s (%lu ports)...\r\n", ts, (unsigned long)nPorts);

    // Optionally randomize port order to reduce detectability
    static uint16_t shuffled[2049];
    uint32_t n = (nPorts <= 2049) ? nPorts : 2049;
    memcpy(shuffled, ports, n * sizeof(uint16_t));
    if (s_randomize) shufflePorts(shuffled, n);

    uint16_t srcPort = 40000 + (esp_random() & 0x3FFF);
    uint32_t open = 0;
    uint8_t f[60];
    for (uint32_t i = 0; i < n; i++) {
        uint16_t p = shuffled[i];
        uint32_t seq = esp_random();
        uint16_t flen = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, p,
                                 seq, 0, TCP_SYN, nullptr, 0);
        eth.sendFrame(f, flen);
        uint32_t rseq, rack;
        int flags = waitTcp(eth, target, p, srcPort, &rseq, &rack, nullptr, nullptr, 0, perPortMs);
        if (flags >= 0 && (flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
            Serial.printf("  %5u/tcp  open\r\n", p);
            open++;
            // Be polite: tear down with RST.
            uint16_t rl = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, p,
                                   seq + 1, rseq + 1, TCP_RST, nullptr, 0);
            eth.sendFrame(f, rl);
        }
        if (Serial.available()) { while (Serial.available()) Serial.read();
            Serial.println("Aborted."); break; }
        srcPort++; if (srcPort < 40000) srcPort = 40000;
    }
    Serial.printf("Scan complete: %lu open port(s).\r\n", (unsigned long)open);
    return open;
}

uint32_t tcpSynScan(W5500Raw &eth, IpStack &ip, uint32_t target,
                    uint16_t first, uint16_t last, uint32_t perPortMs)
{
    if (last < first) { uint16_t t = first; first = last; last = t; }
    if ((uint32_t)(last - first) > 2048) { Serial.println("Range too large (max 2048 ports)."); return 0; }
    uint32_t n = (uint32_t)(last - first) + 1;
    static uint16_t list[2049];
    for (uint32_t i = 0; i < n; i++) list[i] = (uint16_t)(first + i);
    return scanList(eth, ip, target, list, n, perPortMs);
}

uint32_t tcpScanCommon(W5500Raw &eth, IpStack &ip, uint32_t target, uint32_t perPortMs)
{
    static const uint16_t common[] = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
        465, 514, 515, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049,
        3000, 3128, 3306, 3389, 4444, 5432, 5060, 5900, 5985, 6379, 8000, 8008,
        8080, 8443, 8888, 9000, 9090, 9200, 10000, 27017
    };
    return scanList(eth, ip, target, common, sizeof(common) / sizeof(common[0]), perPortMs);
}

uint32_t tcpScanPortList(W5500Raw &eth, IpStack &ip, uint32_t target,
                         const uint16_t *ports, uint32_t nPorts, uint32_t perPortMs)
{
    return scanList(eth, ip, target, ports, nPorts, perPortMs);
}

// Probes for common services: send a small request to elicit a response.
// nullptr = service sends banner on connect (just read); empty string = send
// a newline nudge after a short wait if no banner arrives.
static const char *probeForPort(uint16_t port)
{
    switch (port) {
        // HTTP / web services
        case 80: case 8080: case 8000: case 8008: case 8888: case 3000:
        case 9090: case 9000: case 3128: case 8081: case 8443:
            return "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n";
        case 443:
            return nullptr;  // TLS — can't banner without handshake
        // SSH / SFTP (port 22 sends version string on connect)
        case 22: case 2222:
            return nullptr;
        // FTP (sends 220 banner on connect)
        case 21: case 990:
            return nullptr;
        // Telnet (send newline to nudge prompt)
        case 23: case 2323:
            return "\r\n";
        // SMTP
        case 25: case 587: case 465:
            return "EHLO scanner\r\n";
        // POP3 (sends +OK banner)
        case 110: case 995:
            return nullptr;
        // IMAP (sends * OK banner)
        case 143: case 993:
            return nullptr;
        // DNS over TCP (version.bind query not practical here)
        case 53:
            return nullptr;
        // MySQL (sends handshake packet)
        case 3306:
            return nullptr;
        // PostgreSQL (send startup cancel — elicits error with version)
        case 5432:
            return nullptr;
        // Redis (INFO command)
        case 6379:
            return "INFO server\r\n";
        // MongoDB (sends ismaster reply to empty command)
        case 27017:
            return nullptr;
        // MSSQL (sends pre-login response)
        case 1433:
            return nullptr;
        // RDP / Remote Desktop (sends X.224 negotiation)
        case 3389:
            return nullptr;
        // VNC (sends RFB version string)
        case 5900: case 5901:
            return nullptr;
        // SIP
        case 5060:
            return "OPTIONS sip:test@target SIP/2.0\r\n\r\n";
        // SNMP (TCP variant — rare)
        case 161:
            return nullptr;
        // LDAP
        case 389: case 636:
            return nullptr;
        // Elasticsearch
        case 9200:
            return "GET / HTTP/1.0\r\n\r\n";
        // Docker API
        case 2375: case 2376:
            return "GET /version HTTP/1.0\r\n\r\n";
        // Kubernetes API
        case 6443: case 10250:
            return "GET / HTTP/1.0\r\n\r\n";
        // RTSP
        case 554:
            return "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        // Memcached
        case 11211:
            return "version\r\n";
        // Generic — try a newline nudge
        default:
            return "\r\n";
    }
}

uint32_t tcpScanAndBanner(W5500Raw &eth, IpStack &ip, uint32_t target,
                          const uint16_t *ports, uint32_t nPorts,
                          uint16_t *openPorts, uint32_t maxOpen,
                          uint32_t perPortMs)
{
    uint8_t dstMac[6]; uint32_t srcIp;
    if (!prep(ip, target, dstMac, &srcIp)) return 0;
    char ts[16]; ipToStr(target, ts);
    Serial.printf("\r\nScan+Banner %s (%lu ports)...\r\n", ts, (unsigned long)nPorts);

    // Optionally randomize port scan order
    uint16_t shuffled[64];
    uint32_t n = (nPorts <= 64) ? nPorts : 64;
    memcpy(shuffled, ports, n * sizeof(uint16_t));
    if (s_randomize) shufflePorts(shuffled, n);

    uint16_t srcPort = 40000 + (esp_random() & 0x3FFF);
    uint32_t open = 0;
    uint8_t f[60];

    // Phase A: SYN scan to find open ports (randomized order)
    uint16_t foundPorts[64];
    uint32_t nFound = 0;

    for (uint32_t i = 0; i < n; i++) {
        uint16_t p = shuffled[i];
        uint32_t seq = esp_random();
        uint16_t flen = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, p,
                                 seq, 0, TCP_SYN, nullptr, 0);
        eth.sendFrame(f, flen);
        uint32_t rseq, rack;
        int flags = waitTcp(eth, target, p, srcPort, &rseq, &rack, nullptr, nullptr, 0, perPortMs);
        if (flags >= 0 && (flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
            Serial.printf("  %5u/tcp  open\r\n", p);
            if (nFound < 64) foundPorts[nFound++] = p;
            if (openPorts && open < maxOpen) openPorts[open] = p;
            open++;
            // RST to clean up
            uint16_t rl = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, p,
                                   seq + 1, rseq + 1, TCP_RST, nullptr, 0);
            eth.sendFrame(f, rl);
        }
        if (Serial.available()) { while (Serial.available()) Serial.read();
            Serial.println("Aborted."); return open; }
        srcPort++; if (srcPort < 40000) srcPort = 40000;
    }

    if (nFound == 0) {
        Serial.println("No open ports found.");
        return 0;
    }

    // Phase B: Banner grab on each open port
    Serial.printf("\r\n--- Banner collection (%lu open ports) ---\r\n", (unsigned long)nFound);
    for (uint32_t i = 0; i < nFound; i++) {
        if (Serial.available()) { while (Serial.available()) Serial.read();
            Serial.println("Aborted."); break; }
        uint16_t p = foundPorts[i];
        const char *probe = probeForPort(p);
        // Skip TLS ports for banner (can't negotiate without TLS)
        if (p == 443 || p == 8443) {
            Serial.printf("  %5u/tcp  (TLS - banner grab skipped)\r\n", p);
            continue;
        }
        tcpBannerGrab(eth, ip, target, p, probe, 256, 2000);
    }

    return open;
}

bool tcpBannerGrab(W5500Raw &eth, IpStack &ip, uint32_t target, uint16_t port,
                   const char *probe, uint32_t maxBytes, uint32_t timeoutMs)
{
    uint8_t dstMac[6]; uint32_t srcIp;
    if (!prep(ip, target, dstMac, &srcIp)) return false;
    char ts[16]; ipToStr(target, ts);
    Serial.printf("\r\nBanner grab %s:%u ...\r\n", ts, port);

    uint16_t srcPort = 40000 + (esp_random() & 0x3FFF);
    uint32_t seq = esp_random();
    uint8_t f[1600];

    // SYN
    uint16_t flen = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, port,
                             seq, 0, TCP_SYN, nullptr, 0);
    eth.sendFrame(f, flen);
    uint32_t rseq, rack;
    int flags = waitTcp(eth, target, port, srcPort, &rseq, &rack, nullptr, nullptr, 0, timeoutMs);
    if (flags < 0 || (flags & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK)) {
        Serial.printf("Port %u is %s.\r\n", port, stateStr(flags));
        return false;
    }
    seq += 1;
    uint32_t myAck = rseq + 1;
    // ACK to finish handshake
    flen = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, port, seq, myAck, TCP_ACK, nullptr, 0);
    eth.sendFrame(f, flen);

    // Optional application probe (e.g. "HEAD / HTTP/1.0\r\n\r\n")
    if (probe && *probe) {
        uint16_t pl = strlen(probe);
        flen = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, port, seq, myAck,
                        TCP_PSH | TCP_ACK, (const uint8_t *)probe, pl);
        eth.sendFrame(f, flen);
        seq += pl;
    }

    // Read banner payload.
    uint8_t pay[512]; uint16_t payLen = 0;
    uint32_t got = 0;
    Serial.println("---- banner ----");
    uint32_t deadline = millis() + timeoutMs;
    while ((int32_t)(deadline - millis()) > 0 && got < maxBytes) {
        int fl = waitTcp(eth, target, port, srcPort, &rseq, &rack, pay, &payLen,
                         sizeof(pay), 400);
        if (fl < 0) break;
        if (payLen > 0) {
            for (uint16_t i = 0; i < payLen; i++) {
                char c = (char)pay[i];
                Serial.write((c >= 32 && c < 127) || c == '\r' || c == '\n' ? c : '.');
            }
            got += payLen;
            myAck = rseq + payLen;
            uint16_t al = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, port,
                                   seq, myAck, TCP_ACK, nullptr, 0);
            eth.sendFrame(f, al);
        }
        if (fl & (TCP_FIN | TCP_RST)) break;
    }
    Serial.printf("\r\n---- %lu byte(s) ----\r\n", (unsigned long)got);

    // Tear down.
    flen = buildTcp(f, dstMac, ip.mac(), srcIp, target, srcPort, port, seq, myAck,
                    TCP_FIN | TCP_ACK, nullptr, 0);
    eth.sendFrame(f, flen);
    return true;
}

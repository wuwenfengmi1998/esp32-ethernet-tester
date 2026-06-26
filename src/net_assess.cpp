#include "net_assess.h"
#include "recon.h"
#include "arp_tool.h"
#include "portscan.h"
#include "snmp_recon.h"
#include "net_util.h"
#include "weblog.h"
#include <string.h>
#include <esp_random.h>

#define Serial Out

// Fisher-Yates shuffle for uint32_t arrays (randomize host scan order)
static void shuffleHosts(uint32_t *arr, uint32_t n)
{
    for (uint32_t i = n - 1; i > 0; i--) {
        uint32_t j = esp_random() % (i + 1);
        uint32_t tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

// =============================================================================
// CIDR to IP range conversion
// =============================================================================

bool cidrToRange(const char *cidr, uint32_t *startIp, uint32_t *endIp)
{
    if (!cidr || !startIp || !endIp) return false;

    // Copy so we can modify (split at '/')
    char buf[32];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) return false;
    *slash = '\0';
    const char *prefixStr = slash + 1;

    uint32_t ip;
    if (!strToIp(buf, &ip)) return false;

    int prefix = atoi(prefixStr);
    if (prefix < 1 || prefix > 30) return false;  // /31 and /32 not useful for scanning

    uint32_t mask = 0xFFFFFFFF << (32 - prefix);
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;

    // Exclude network and broadcast addresses
    *startIp = network + 1;
    *endIp   = broadcast - 1;
    return true;
}

// =============================================================================
// Combined network assessment
// =============================================================================

// Default ports when none specified
static const uint16_t DEFAULT_PORTS[] = { 21, 22, 80, 443 };
static const uint32_t DEFAULT_NPORTS  = sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]);

uint32_t netAssess(W5500Raw &eth, IpStack &ip, const uint8_t srcMac[6],
                   uint32_t startIp, uint32_t endIp,
                   const uint16_t *ports, uint32_t nPorts, uint8_t flags)
{
    if (!ports || nPorts == 0) {
        ports  = DEFAULT_PORTS;
        nPorts = DEFAULT_NPORTS;
    }

    bool randomizeOrder = (flags & ASSESS_RANDOMIZE_ORDER) != 0;
    bool randomizeMac   = (flags & ASSESS_RANDOMIZE_MAC) != 0;

    // Configure port scan randomization
    tcpScanSetRandomize(randomizeOrder);

    char sStr[16], eStr[16];
    ipToStr(startIp, sStr);
    ipToStr(endIp, eStr);
    uint32_t rangeSize = endIp - startIp + 1;

    Serial.println("\r\n============================================");
    Serial.println("  Combined Network Assessment");
    Serial.println("============================================");
    Serial.printf("Range: %s - %s (%lu hosts)\r\n", sStr, eStr, (unsigned long)rangeSize);
    Serial.printf("Ports: ");
    for (uint32_t i = 0; i < nPorts; i++) {
        Serial.printf("%u%s", ports[i], (i < nPorts - 1) ? "," : "");
    }
    Serial.println("\r\n");

    // Track discovered hosts (bitmap for ranges up to 1024)
    static const uint32_t MAX_HOSTS = 1024;
    if (rangeSize > MAX_HOSTS) {
        Serial.printf("Range too large (max %lu hosts). Narrow the range.\r\n",
                      (unsigned long)MAX_HOSTS);
        return 0;
    }

    // --- Phase 1: Ping Sweep ---
    Serial.println("--- Phase 1: Ping Sweep ---");
    Serial.printf("Sweeping %s - %s (any key aborts)...\r\n", sStr, eStr);
    uint32_t pingCount = reconSweep(eth, ip, startIp, endIp);
    Serial.printf("Ping sweep found %lu host(s).\r\n\r\n", (unsigned long)pingCount);

    if (Serial.available()) { while (Serial.available()) Serial.read();
        Serial.println("Aborted."); return 0; }

    // --- Phase 2: ARP Scan ---
    Serial.println("--- Phase 2: ARP Scan ---");
    Serial.printf("ARP scanning %s - %s (any key aborts)...\r\n", sStr, eStr);
    uint32_t arpCount = arpScan(eth, srcMac, ip.ip(), startIp, endIp);
    Serial.printf("ARP scan found %lu host(s).\r\n\r\n", (unsigned long)arpCount);

    if (Serial.available()) { while (Serial.available()) Serial.read();
        Serial.println("Aborted."); return 0; }

    // --- Phase 3: Port Scan + Banner Grab ---
    Serial.println("--- Phase 3: Port Scan + Banner Grab ---");
    Serial.printf("Scanning %lu port(s) per host with banner collection (any key aborts)...\r\n",
                  (unsigned long)nPorts);
    if (randomizeOrder) Serial.println("  [Randomized host/port order]");
    if (randomizeMac)   Serial.println("  [Randomized source MAC per host]");

    uint32_t hostsWithOpenPorts = 0;
    uint32_t totalOpen = 0;

    // Build host offset list (optionally randomized)
    uint32_t *hostOrder = (uint32_t *)malloc(rangeSize * sizeof(uint32_t));
    if (!hostOrder) {
        Serial.println("Out of memory for host list.");
        goto summary;
    }
    for (uint32_t i = 0; i < rangeSize; i++) hostOrder[i] = i;
    if (randomizeOrder) shuffleHosts(hostOrder, rangeSize);

    for (uint32_t idx = 0; idx < rangeSize; idx++) {
        if (Serial.available()) { while (Serial.available()) Serial.read();
            Serial.println("Aborted."); break; }

        // Randomize source MAC for each target if enabled
        if (randomizeMac) {
            uint8_t rndMac[6];
            uint32_t r1 = esp_random(), r2 = esp_random();
            rndMac[0] = (uint8_t)((r1 & 0xFC) | 0x02); // locally administered, unicast
            rndMac[1] = (uint8_t)(r1 >> 8);
            rndMac[2] = (uint8_t)(r1 >> 16);
            rndMac[3] = (uint8_t)(r1 >> 24);
            rndMac[4] = (uint8_t)(r2 & 0xFF);
            rndMac[5] = (uint8_t)(r2 >> 8);
            ip.setMac(rndMac);
        }

        uint32_t target = startIp + hostOrder[idx];
        uint32_t found = tcpScanAndBanner(eth, ip, target, ports, nPorts,
                                          nullptr, 0, 200);
        if (found > 0) {
            hostsWithOpenPorts++;
            totalOpen += found;
        }
    }
    free(hostOrder);

    // Restore original MAC if we randomized
    if (randomizeMac) {
        ip.setMac(srcMac);
    }

    if (Serial.available()) { while (Serial.available()) Serial.read();
        Serial.println("Aborted."); goto summary; }

    // --- Phase 4: SNMP Discovery ---
    {
        Serial.println("\r\n--- Phase 4: SNMP System Information ---");
        Serial.printf("Probing %s - %s for SNMP (any key aborts)...\r\n", sStr, eStr);
        uint32_t snmpCount = snmpSweep(eth, ip, startIp, endIp, "public", 1500);
        Serial.printf("SNMP responded: %lu host(s).\r\n", (unsigned long)snmpCount);
    }

summary:
    // Restore scan settings
    tcpScanSetRandomize(false);

    Serial.println("\r\n============================================");
    Serial.println("  Assessment Summary");
    Serial.println("============================================");
    Serial.printf("Ping responders:       %lu\r\n", (unsigned long)pingCount);
    Serial.printf("ARP responders:        %lu\r\n", (unsigned long)arpCount);
    Serial.printf("Hosts with open ports: %lu\r\n", (unsigned long)hostsWithOpenPorts);
    Serial.printf("Total open ports:      %lu\r\n", (unsigned long)totalOpen);
    Serial.println("============================================\r\n");

    return (pingCount > arpCount) ? pingCount : arpCount;
}

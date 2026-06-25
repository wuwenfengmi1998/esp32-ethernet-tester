#pragma once

#include <Arduino.h>
#include "w5500_raw.h"

// =============================================================================
// IEEE 802.1X (EAPOL) supplicant test  --  AAA / NAC port authentication
//
// Acts as an 802.1X supplicant on the wired port to verify whether a switch
// port enforces network access control (dot1x) and, optionally, to attempt a
// full authentication using EAP-MD5 credentials.
//
// All exchange happens at L2 over the W5500 in MACRAW mode:
//   EtherType : 0x888E (EAPOL)
//   PAE group : 01:80:C2:00:00:03 (nearest-non-TPMR-bridge group address)
//
// Supported EAP methods: Identity, EAP-MD5 (challenge/response) and EAP-TLS
// (certificate-based mutual authentication via mbedTLS). When the authenticator
// offers a method the tester cannot perform it sends a legacy NAK requesting
// the configured method and reports what was offered.
//
// EAP-TLS performs a full TLS 1.2 handshake fragmented across EAPOL frames per
// RFC 5216, using a CA certificate (to validate the RADIUS server), a client
// certificate and a client private key uploaded to the device.
// =============================================================================

struct Dot1xResult {
    bool    portEnforced;     // an EAP-Request was seen => port runs 802.1X
    bool    identitySent;     // we transmitted an EAP-Response/Identity
    bool    authenticated;    // EAP-Success received
    bool    rejected;         // EAP-Failure received
    bool    authenticatorVerifyFailed; // PEAP: server MS-CHAPv2 S= did not verify
    uint8_t offeredMethod;    // last EAP method the authenticator requested
    char    detail[64];       // human-readable summary
};

class Dot1xTest {
public:
    Dot1xTest(W5500Raw &eth, const uint8_t mac[6]);

    // Probe the port: send EAPOL-Start and wait for an EAP-Request/Identity.
    // Does NOT transmit any credentials. Returns true if the port enforces
    // 802.1X (i.e. an EAP-Request was observed). Fills `res` if non-null.
    bool probe(uint32_t timeoutMs = 5000, Dot1xResult *res = nullptr);

    // Full supplicant authentication using EAP-MD5. Sends identity then answers
    // an MD5 challenge. Returns true on EAP-Success. Fills `res` if non-null.
    bool authenticate(const char *username, const char *password,
                      uint32_t timeoutMs = 8000, Dot1xResult *res = nullptr);

    // Full supplicant authentication using EAP-TLS (certificate based). All PEM
    // buffers must be NUL-terminated. `caPem` may be null/empty to skip server
    // certificate validation (the result still reports what was presented).
    // `clientPem` and `keyPem` are required; `keyPwd` may be null. Returns true
    // on EAP-Success. Fills `res` if non-null.
    bool authenticateTls(const char *identity,
                         const char *caPem,
                         const char *clientPem,
                         const char *keyPem,
                         const char *keyPwd,
                         uint32_t timeoutMs = 20000,
                         Dot1xResult *res = nullptr);

    // Full supplicant authentication using PEAPv0 with inner EAP-MSCHAPv2
    // (RFC 2759). Establishes a server-authenticated TLS tunnel (no client
    // certificate) and runs username/password MS-CHAPv2 inside it. `identity`
    // is the outer (cleartext) identity, typically "anonymous"; `username` and
    // `password` are the inner credentials. `caPem` may be null/empty to skip
    // server certificate validation. Returns true on EAP-Success.
    bool authenticatePeap(const char *identity,
                          const char *username,
                          const char *password,
                          const char *caPem,
                          uint32_t timeoutMs = 20000,
                          Dot1xResult *res = nullptr);

    // Full supplicant authentication using EAP-TTLS (RFC 5281). Establishes a
    // server-authenticated TLS tunnel (no client certificate) and runs an inner
    // legacy method carried as Diameter/RADIUS AVPs: PAP (cleartext inside the
    // tunnel) or MS-CHAPv2. `identity` is the outer identity ("anonymous");
    // `username`/`password` are the inner credentials. `innerMschap` selects
    // MS-CHAPv2 (true) or PAP (false). Returns true on EAP-Success.
    bool authenticateTtls(const char *identity,
                          const char *username,
                          const char *password,
                          const char *caPem,
                          bool innerMschap,
                          uint32_t timeoutMs = 20000,
                          Dot1xResult *res = nullptr);

    // Send an EAPOL-Logoff to deauthenticate the port.
    void logoff();

    // --- Offensive EAPOL extras (authorized lab use only) ---

    // Flood `count` EAPOL-Start frames. When `randomMac` is true each frame uses
    // a fresh random source MAC (stresses the authenticator / RADIUS server).
    void startFlood(uint32_t count, bool randomMac, uint32_t intervalMs = 0);

    // Spoof an EAPOL-Logoff as `victimMac` to forcibly deauthenticate that
    // client from the port (802.1X denial-of-service test).
    void logoffSpoof(const uint8_t victimMac[6]);

    // MAC Authentication Bypass detection: send EAPOL-Start and observe whether
    // the port ever issues an EAP-Request/Identity within `seconds`. If the
    // link is up but no EAP challenge appears, the port likely uses MAB or is
    // open. Returns true if 802.1X enforcement was observed.
    bool mabProbe(uint32_t seconds);

private:
    W5500Raw &_eth;
    uint8_t   _mac[6];

    bool _sendEapolStart();
    bool _sendEapolLogoff();
    // Send an EAP packet (code/id/type + data) wrapped in EAPOL.
    bool _sendEap(uint8_t code, uint8_t id, uint8_t type,
                  const uint8_t *data, uint16_t dataLen);

    // Send an EAP-Response/EAP-TLS packet (flags + optional 4-byte TLS length +
    // a fragment of TLS record data) wrapped in EAPOL. Supports frames larger
    // than the small EAP buffer used by EAP-MD5.
    bool _sendEapTls(uint8_t id, uint8_t flags, bool includeLen,
                     uint32_t totalLen, const uint8_t *data, uint16_t dataLen,
                     uint8_t methodType = 13 /* EAP-TLS */);

    // Wait for an EAPOL EAP-Packet. Copies the EAP payload into eap[] and
    // returns its length, 0 on timeout, -1 if aborted from the serial console.
    int  _recvEap(uint8_t *eap, uint16_t maxLen, uint32_t timeoutMs);

    static const char *_methodName(uint8_t type);
};

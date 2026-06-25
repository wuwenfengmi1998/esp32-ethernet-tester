#include "mschapv2.h"
#include <string.h>
#include <mbedtls/sha1.h>

// =============================================================================
// Self-contained DES (single-block ECB encrypt) -- ESP-IDF mbedTLS builds
// normally disable MBEDTLS_DES_C, so DES is implemented here for MS-CHAPv2.
// =============================================================================
namespace {

const uint8_t DES_IP[64] = {
    58,50,42,34,26,18,10, 2, 60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6, 64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7 };
const uint8_t DES_FP[64] = {
    40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25 };
const uint8_t DES_E[48] = {
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1 };
const uint8_t DES_P[32] = {
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25 };
const uint8_t DES_S[8][64] = {
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
      4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
      0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
      13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
      10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
      4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
      9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
      1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
      7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} };
const uint8_t DES_PC1[56] = {
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4 };
const uint8_t DES_PC2[48] = {
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,
    23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32 };
const uint8_t DES_SHIFTS[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

inline int getBit(const uint8_t *src, int pos) {        // 1-based MSB-first
    return (src[(pos - 1) >> 3] >> (7 - ((pos - 1) & 7))) & 1;
}
inline void setBit(uint8_t *dst, int pos, int val) {
    int idx = (pos - 1) >> 3, off = 7 - ((pos - 1) & 7);
    if (val) dst[idx] |= (1 << off); else dst[idx] &= ~(1 << off);
}
void permute(const uint8_t *in, uint8_t *out, const uint8_t *table, int n) {
    memset(out, 0, (n + 7) / 8);
    for (int i = 0; i < n; i++) setBit(out, i + 1, getBit(in, table[i]));
}

// DES-ECB encrypt one 8-byte block with an 8-byte (parity-bearing) key.
void desEncryptBlock(const uint8_t key8[8], const uint8_t in8[8], uint8_t out8[8])
{
    // Key schedule.
    uint8_t pc1[7];
    permute(key8, pc1, DES_PC1, 56);
    uint32_t C = 0, D = 0;
    for (int i = 1; i <= 28; i++) C = (C << 1) | getBit(pc1, i);
    for (int i = 29; i <= 56; i++) D = (D << 1) | getBit(pc1, i);

    uint8_t subkeys[16][6];
    for (int r = 0; r < 16; r++) {
        int s = DES_SHIFTS[r];
        C = ((C << s) | (C >> (28 - s))) & 0x0FFFFFFF;
        D = ((D << s) | (D >> (28 - s))) & 0x0FFFFFFF;
        uint8_t cd[7];
        memset(cd, 0, 7);
        for (int i = 0; i < 28; i++) setBit(cd, i + 1, (C >> (27 - i)) & 1);
        for (int i = 0; i < 28; i++) setBit(cd, 28 + i + 1, (D >> (27 - i)) & 1);
        permute(cd, subkeys[r], DES_PC2, 48);
    }

    // Initial permutation.
    uint8_t ip[8];
    permute(in8, ip, DES_IP, 64);
    uint32_t L = 0, R = 0;
    for (int i = 1; i <= 32; i++) L = (L << 1) | getBit(ip, i);
    for (int i = 33; i <= 64; i++) R = (R << 1) | getBit(ip, i);

    for (int r = 0; r < 16; r++) {
        // Expansion of R (32 -> 48).
        uint8_t rb[4];
        for (int i = 0; i < 4; i++) rb[i] = (R >> (24 - i * 8)) & 0xFF;
        uint8_t e[6];
        permute(rb, e, DES_E, 48);
        for (int i = 0; i < 6; i++) e[i] ^= subkeys[r][i];
        // S-boxes (48 -> 32).
        uint32_t sout = 0;
        for (int b = 0; b < 8; b++) {
            int base = b * 6;
            int b1 = getBit(e, base + 1), b6 = getBit(e, base + 6);
            int row = (b1 << 1) | b6;
            int col = (getBit(e, base + 2) << 3) | (getBit(e, base + 3) << 2)
                    | (getBit(e, base + 4) << 1) | getBit(e, base + 5);
            sout = (sout << 4) | DES_S[b][row * 16 + col];
        }
        uint8_t sb[4];
        for (int i = 0; i < 4; i++) sb[i] = (sout >> (24 - i * 8)) & 0xFF;
        uint8_t pb[4];
        permute(sb, pb, DES_P, 32);
        uint32_t f = ((uint32_t)pb[0] << 24) | ((uint32_t)pb[1] << 16)
                   | ((uint32_t)pb[2] << 8) | pb[3];
        uint32_t newL = R;
        R = L ^ f;
        L = newL;
    }

    // Preoutput is R||L, then final permutation.
    uint8_t pre[8];
    for (int i = 0; i < 4; i++) pre[i]     = (R >> (24 - i * 8)) & 0xFF;
    for (int i = 0; i < 4; i++) pre[4 + i] = (L >> (24 - i * 8)) & 0xFF;
    permute(pre, out8, DES_FP, 64);
}

inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void md4(const uint8_t *msg, size_t len, uint8_t digest[16])
{
    uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

    size_t newlen = ((len + 8) / 64 + 1) * 64;
    uint8_t *m = (uint8_t *)calloc(newlen, 1);
    if (!m) { memset(digest, 0, 16); return; }
    memcpy(m, msg, len);
    m[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) m[newlen - 8 + i] = (uint8_t)(bits >> (8 * i));

    for (size_t off = 0; off < newlen; off += 64) {
        uint32_t X[16];
        for (int i = 0; i < 16; i++)
            X[i] =  (uint32_t)m[off + i * 4]
                 | ((uint32_t)m[off + i * 4 + 1] << 8)
                 | ((uint32_t)m[off + i * 4 + 2] << 16)
                 | ((uint32_t)m[off + i * 4 + 3] << 24);

        uint32_t A = a, B = b, C = c, D = d;
#define MD4_F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD4_FF(w, x, y, z, k, s) w = rol32(w + MD4_F(x, y, z) + X[k], s)
#define MD4_GG(w, x, y, z, k, s) w = rol32(w + MD4_G(x, y, z) + X[k] + 0x5a827999UL, s)
#define MD4_HH(w, x, y, z, k, s) w = rol32(w + MD4_H(x, y, z) + X[k] + 0x6ed9eba1UL, s)
        MD4_FF(A, B, C, D, 0, 3);  MD4_FF(D, A, B, C, 1, 7);  MD4_FF(C, D, A, B, 2, 11);  MD4_FF(B, C, D, A, 3, 19);
        MD4_FF(A, B, C, D, 4, 3);  MD4_FF(D, A, B, C, 5, 7);  MD4_FF(C, D, A, B, 6, 11);  MD4_FF(B, C, D, A, 7, 19);
        MD4_FF(A, B, C, D, 8, 3);  MD4_FF(D, A, B, C, 9, 7);  MD4_FF(C, D, A, B, 10, 11); MD4_FF(B, C, D, A, 11, 19);
        MD4_FF(A, B, C, D, 12, 3); MD4_FF(D, A, B, C, 13, 7); MD4_FF(C, D, A, B, 14, 11); MD4_FF(B, C, D, A, 15, 19);

        MD4_GG(A, B, C, D, 0, 3);  MD4_GG(D, A, B, C, 4, 5);  MD4_GG(C, D, A, B, 8, 9);   MD4_GG(B, C, D, A, 12, 13);
        MD4_GG(A, B, C, D, 1, 3);  MD4_GG(D, A, B, C, 5, 5);  MD4_GG(C, D, A, B, 9, 9);   MD4_GG(B, C, D, A, 13, 13);
        MD4_GG(A, B, C, D, 2, 3);  MD4_GG(D, A, B, C, 6, 5);  MD4_GG(C, D, A, B, 10, 9);  MD4_GG(B, C, D, A, 14, 13);
        MD4_GG(A, B, C, D, 3, 3);  MD4_GG(D, A, B, C, 7, 5);  MD4_GG(C, D, A, B, 11, 9);  MD4_GG(B, C, D, A, 15, 13);

        MD4_HH(A, B, C, D, 0, 3);  MD4_HH(D, A, B, C, 8, 9);  MD4_HH(C, D, A, B, 4, 11);  MD4_HH(B, C, D, A, 12, 15);
        MD4_HH(A, B, C, D, 2, 3);  MD4_HH(D, A, B, C, 10, 9); MD4_HH(C, D, A, B, 6, 11);  MD4_HH(B, C, D, A, 14, 15);
        MD4_HH(A, B, C, D, 1, 3);  MD4_HH(D, A, B, C, 9, 9);  MD4_HH(C, D, A, B, 5, 11);  MD4_HH(B, C, D, A, 13, 15);
        MD4_HH(A, B, C, D, 3, 3);  MD4_HH(D, A, B, C, 11, 9); MD4_HH(C, D, A, B, 7, 11);  MD4_HH(B, C, D, A, 15, 15);
#undef MD4_F
#undef MD4_G
#undef MD4_H
#undef MD4_FF
#undef MD4_GG
#undef MD4_HH
        a += A; b += B; c += C; d += D;
    }
    free(m);

    uint32_t hv[4] = { a, b, c, d };
    for (int i = 0; i < 4; i++) {
        digest[i * 4]     = (uint8_t)(hv[i]);
        digest[i * 4 + 1] = (uint8_t)(hv[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(hv[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(hv[i] >> 24);
    }
}

// Expand a 7-byte chunk into an 8-byte DES key (7 bits per byte + parity LSB).
void desAddParity(const uint8_t in[7], uint8_t out[8])
{
    out[0] =  in[0] & 0xFE;
    out[1] = (uint8_t)((in[0] << 7) | (in[1] >> 1));
    out[2] = (uint8_t)((in[1] << 6) | (in[2] >> 2));
    out[3] = (uint8_t)((in[2] << 5) | (in[3] >> 3));
    out[4] = (uint8_t)((in[3] << 4) | (in[4] >> 4));
    out[5] = (uint8_t)((in[4] << 3) | (in[5] >> 5));
    out[6] = (uint8_t)((in[5] << 2) | (in[6] >> 6));
    out[7] = (uint8_t)( in[6] << 1);
    // The low bit of each output byte is a parity bit; DES ignores its value.
}

// DES-ECB encrypt one 8-byte block with a 7-byte key.
void desHash(const uint8_t key7[7], const uint8_t in8[8], uint8_t out8[8])
{
    uint8_t key8[8];
    desAddParity(key7, key8);
    desEncryptBlock(key8, in8, out8);
}

// ChallengeHash (RFC 2759 sec 8.2): SHA1(peer||auth||user)[0:8].
void challengeHash(const uint8_t peerChallenge[16],
                   const uint8_t authChallenge[16],
                   const char *username, uint8_t challenge[8])
{
    // Username is the bare account name without any domain prefix.
    const char *bare = strrchr(username, '\\');
    bare = bare ? bare + 1 : username;

    mbedtls_sha1_context sha;
    mbedtls_sha1_init(&sha);
    mbedtls_sha1_starts(&sha);
    mbedtls_sha1_update(&sha, peerChallenge, 16);
    mbedtls_sha1_update(&sha, authChallenge, 16);
    mbedtls_sha1_update(&sha, (const uint8_t *)bare, strlen(bare));
    uint8_t digest[20];
    mbedtls_sha1_finish(&sha, digest);
    mbedtls_sha1_free(&sha);
    memcpy(challenge, digest, 8);
}

// ChallengeResponse (RFC 2759 sec 8.5): three DES blocks from the NT hash.
void challengeResponse(const uint8_t challenge[8], const uint8_t pwHash[16],
                       uint8_t response[24])
{
    uint8_t zpw[21];
    memset(zpw, 0, sizeof(zpw));
    memcpy(zpw, pwHash, 16);
    desHash(zpw + 0,  challenge, response + 0);
    desHash(zpw + 7,  challenge, response + 8);
    desHash(zpw + 14, challenge, response + 16);
}

} // namespace

// =============================================================================
// Public API
// =============================================================================
void mschapNtPasswordHash(const char *password, uint8_t hash[16])
{
    size_t n = strlen(password);
    uint8_t *uni = (uint8_t *)malloc(n * 2 + 2);
    if (!uni) { memset(hash, 0, 16); return; }
    for (size_t i = 0; i < n; i++) {
        uni[i * 2]     = (uint8_t)password[i];
        uni[i * 2 + 1] = 0x00;
    }
    md4(uni, n * 2, hash);
    free(uni);
}

void mschapGenerateNTResponse(const uint8_t authChallenge[16],
                              const uint8_t peerChallenge[16],
                              const char *username, const char *password,
                              uint8_t ntResponse[24])
{
    uint8_t challenge[8];
    challengeHash(peerChallenge, authChallenge, username, challenge);
    uint8_t pwHash[16];
    mschapNtPasswordHash(password, pwHash);
    challengeResponse(challenge, pwHash, ntResponse);
}

void mschapGenerateAuthenticatorResponse(const char *password,
                                         const uint8_t ntResponse[24],
                                         const uint8_t peerChallenge[16],
                                         const uint8_t authChallenge[16],
                                         const char *username,
                                         char out[43])
{
    static const uint8_t magic1[39] = {
        0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
        0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74 };
    static const uint8_t magic2[41] = {
        0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
        0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
        0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
        0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
        0x6E };

    uint8_t pwHash[16], pwHashHash[16];
    mschapNtPasswordHash(password, pwHash);
    md4(pwHash, 16, pwHashHash);

    uint8_t digest[20];
    {
        mbedtls_sha1_context sha;
        mbedtls_sha1_init(&sha);
        mbedtls_sha1_starts(&sha);
        mbedtls_sha1_update(&sha, pwHashHash, 16);
        mbedtls_sha1_update(&sha, ntResponse, 24);
        mbedtls_sha1_update(&sha, magic1, sizeof(magic1));
        mbedtls_sha1_finish(&sha, digest);
        mbedtls_sha1_free(&sha);
    }

    uint8_t challenge[8];
    challengeHash(peerChallenge, authChallenge, username, challenge);

    uint8_t authResp[20];
    {
        mbedtls_sha1_context sha;
        mbedtls_sha1_init(&sha);
        mbedtls_sha1_starts(&sha);
        mbedtls_sha1_update(&sha, digest, 20);
        mbedtls_sha1_update(&sha, challenge, 8);
        mbedtls_sha1_update(&sha, magic2, sizeof(magic2));
        mbedtls_sha1_finish(&sha, authResp);
        mbedtls_sha1_free(&sha);
    }

    static const char hex[] = "0123456789ABCDEF";
    out[0] = 'S';
    out[1] = '=';
    for (int i = 0; i < 20; i++) {
        out[2 + i * 2]     = hex[authResp[i] >> 4];
        out[2 + i * 2 + 1] = hex[authResp[i] & 0x0F];
    }
    out[42] = '\0';
}

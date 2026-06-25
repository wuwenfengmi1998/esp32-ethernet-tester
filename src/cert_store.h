#pragma once

#include <Arduino.h>

// =============================================================================
// Certificate store (LittleFS-backed)
//
// Persists the X.509 material used by the EAP-TLS (802.1X) supplicant test:
//   - CA certificate    : trust anchor used to validate the RADIUS server cert
//   - Client certificate : the supplicant identity certificate
//   - Client private key : the matching private key (optionally passphrase
//                          protected -- the passphrase lives in NVS, not here)
//
// All files are stored as PEM text on a dedicated LittleFS partition so that
// multi-kilobyte certificates can be uploaded over the web UI without bloating
// the small NVS key/value store.
// =============================================================================

enum class CertKind {
    CA,        // /ca.pem
    CLIENT,    // /client.pem
    KEY        // /client.key
};

// Mount the LittleFS partition (formats it on first use). Returns true on
// success. Safe to call once at boot.
bool certStoreBegin();

// Path on the filesystem for the given kind (e.g. "/ca.pem").
const char *certStorePath(CertKind kind);

// True if a non-empty file for the given kind exists.
bool certStoreExists(CertKind kind);

// Size in bytes of the stored file (0 if absent).
size_t certStoreSize(CertKind kind);

// Read the entire PEM into `out`. Returns false if absent or on error.
bool certStoreRead(CertKind kind, String &out);

// Remove the stored file for the given kind. Returns true if it no longer
// exists afterwards (including the case where it was already absent).
bool certStoreDelete(CertKind kind);

// ---- Chunked upload helpers (used by the async web upload handler) ----
// beginWrite truncates/creates the file; writeChunk appends; endWrite closes.
bool certStoreBeginWrite(CertKind kind);
bool certStoreWriteChunk(const uint8_t *data, size_t len);
bool certStoreEndWrite();
void certStoreAbortWrite();

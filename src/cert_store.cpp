#include "cert_store.h"
#include "weblog.h"
#include <LittleFS.h>

// Tee informational output to the web capture buffer (matches other modules).
#define Serial Out

static bool   s_mounted = false;
static File   s_upload;          // active chunked-upload handle (one at a time)

const char *certStorePath(CertKind kind)
{
    switch (kind) {
        case CertKind::CA:     return "/ca.pem";
        case CertKind::CLIENT: return "/client.pem";
        case CertKind::KEY:    return "/client.key";
    }
    return "/unknown";
}

bool certStoreBegin()
{
    if (s_mounted) return true;
    // format-on-fail = true: a blank/garbage partition is reformatted once.
    if (!LittleFS.begin(true)) {
        Serial.println("cert: LittleFS mount failed.");
        return false;
    }
    s_mounted = true;
    Serial.printf("cert: LittleFS mounted (%u KB total, %u KB used).\r\n",
                  (unsigned)(LittleFS.totalBytes() / 1024),
                  (unsigned)(LittleFS.usedBytes()  / 1024));
    return true;
}

bool certStoreExists(CertKind kind)
{
    if (!s_mounted) return false;
    return LittleFS.exists(certStorePath(kind)) && certStoreSize(kind) > 0;
}

size_t certStoreSize(CertKind kind)
{
    if (!s_mounted) return 0;
    File f = LittleFS.open(certStorePath(kind), "r");
    if (!f) return 0;
    size_t n = f.size();
    f.close();
    return n;
}

bool certStoreRead(CertKind kind, String &out)
{
    if (!s_mounted) return false;
    File f = LittleFS.open(certStorePath(kind), "r");
    if (!f || f.size() == 0) { if (f) f.close(); return false; }
    out.reserve(f.size() + 1);
    out = "";
    while (f.available()) out += (char)f.read();
    f.close();
    return true;
}

bool certStoreDelete(CertKind kind)
{
    if (!s_mounted) return false;
    const char *p = certStorePath(kind);
    if (LittleFS.exists(p)) LittleFS.remove(p);
    return !LittleFS.exists(p);
}

// ---- chunked upload ----------------------------------------------------------
bool certStoreBeginWrite(CertKind kind)
{
    if (!s_mounted) return false;
    if (s_upload) s_upload.close();
    s_upload = LittleFS.open(certStorePath(kind), "w");
    return (bool)s_upload;
}

bool certStoreWriteChunk(const uint8_t *data, size_t len)
{
    if (!s_upload) return false;
    return s_upload.write(data, len) == len;
}

bool certStoreEndWrite()
{
    if (!s_upload) return false;
    s_upload.close();
    return true;
}

void certStoreAbortWrite()
{
    if (s_upload) s_upload.close();
}

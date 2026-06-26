#pragma once

// =============================================================================
// Self-signed TLS certificate for the HTTPS web interface.
// EC P-256, valid 10 years. CN=Ethernet Tester, O=Self-Signed.
// Generated for embedded default use. Users can upload a custom cert via CLI.
// =============================================================================

static const char HTTPS_CERT_PEM[] PROGMEM = R"PEM(-----BEGIN CERTIFICATE-----
MIIBtDCCAVugAwIBAgIUR3XxsK3OvF/lJxgWEBhWV6t2l3EwCgYIKoZIzj0EAwIw
MDEYMBYGA1UEAwwPRXRoZXJuZXQgVGVzdGVyMRQwEgYDVQQKDAtTZWxmLVNpZ25l
ZDAeFw0yNjA2MjUyMzUyMzdaFw0zNjA2MjIyMzUyMzdaMDAxGDAWBgNVBAMMD0V0
aGVybmV0IFRlc3RlcjEUMBIGA1UECgwLU2VsZi1TaWduZWQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQkcXgP48c3usL+hPK3tQDTgE9ixHwJRa/jZaJLO7VxNnyl
a8TxO2xDNT7jlUdfkRTBsJnVzwFt1gvn3prfeAYao1MwUTAdBgNVHQ4EFgQUSjHe
hV85x2QYZ7uQWAb2zGOO7YwwHwYDVR0jBBgwFoAUSjHehV85x2QYZ7uQWAb2zGOO
7YwwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAHOUwzg5MzARZb
rLFb/We3Ge4JsCENTPDDcIasUowWrwIgNb9cn4LXA2rBiEzviXAvaDIY7p2j3dP+
0AVYg4EXLOg=
-----END CERTIFICATE-----
)PEM";

static const char HTTPS_KEY_PEM[] PROGMEM = R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfJdrYlCqbUDh0b9+
TPn0eJGqBDqep2NRUJP2SMItoBShRANCAAQkcXgP48c3usL+hPK3tQDTgE9ixHwJ
Ra/jZaJLO7VxNnyla8TxO2xDNT7jlUdfkRTBsJnVzwFt1gvn3prfeAYa
-----END PRIVATE KEY-----
)PEM";

#include "https_srv.h"
#include "https_cert.h"
#include <esp_https_server.h>
#include <WiFi.h>
#include <mbedtls/base64.h>

static httpd_handle_t _handle = nullptr;
static HttpsStatusFn  _statusFn;
static const char    *_html = nullptr;
static char           _authUser[33] = "admin";
static char           _authPass[65] = "admin";

void httpsSetStatusProvider(HttpsStatusFn fn) { _statusFn = fn; }
void httpsSetAuth(const char *user, const char *pass)
{
    strlcpy(_authUser, user, sizeof(_authUser));
    strlcpy(_authPass, pass, sizeof(_authPass));
}

// --- auth helper -------------------------------------------------------------
static bool _checkAuth(httpd_req_t *req)
{
    // If auth is cleared (empty user), allow all
    if (_authUser[0] == '\0') return true;

    char authBuf[128] = {0};
    if (httpd_req_get_hdr_value_str(req, "Authorization", authBuf, sizeof(authBuf)) != ESP_OK) {
        return false;
    }
    // Expect "Basic <base64(user:pass)>"
    if (strncmp(authBuf, "Basic ", 6) != 0) return false;

    // Decode base64
    unsigned char decoded[96];
    size_t decodedLen = 0;
    if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decodedLen,
                              (const unsigned char *)(authBuf + 6), strlen(authBuf + 6)) != 0) {
        return false;
    }
    decoded[decodedLen] = '\0';

    // Compare "user:pass"
    char expected[100];
    snprintf(expected, sizeof(expected), "%s:%s", _authUser, _authPass);
    return strcmp((const char *)decoded, expected) == 0;
}

static esp_err_t _sendUnauthorized(httpd_req_t *req)
{
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Ethernet Tester\"");
    httpd_resp_send(req, "Unauthorized", 12);
    return ESP_OK;
}

// --- handlers ----------------------------------------------------------------
static esp_err_t _rootHandler(httpd_req_t *req)
{
    if (!_checkAuth(req)) return _sendUnauthorized(req);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, _html, strlen(_html));
    return ESP_OK;
}

static esp_err_t _statusHandler(httpd_req_t *req)
{
    if (!_checkAuth(req)) return _sendUnauthorized(req);
    String json = _statusFn ? _statusFn() : String("{}");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json.c_str(), json.length());
    return ESP_OK;
}

// --- public API --------------------------------------------------------------
bool httpsStart(const char *indexHtml)
{
    if (_handle) return true;
    _html = indexHtml;

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.servercert     = (const uint8_t *)HTTPS_CERT_PEM;
    conf.servercert_len = strlen(HTTPS_CERT_PEM) + 1;
    conf.prvtkey_pem    = (const uint8_t *)HTTPS_KEY_PEM;
    conf.prvtkey_len    = strlen(HTTPS_KEY_PEM) + 1;
    conf.port_secure    = 443;
    conf.httpd.max_uri_handlers = 8;
    conf.httpd.stack_size = 8192;

    esp_err_t ret = httpd_ssl_start(&_handle, &conf);
    if (ret != ESP_OK) {
        Serial.printf("HTTPS: start failed (0x%x)\r\n", ret);
        _handle = nullptr;
        return false;
    }

    httpd_uri_t uri_root = {
        .uri = "/", .method = HTTP_GET,
        .handler = _rootHandler, .user_ctx = nullptr
    };
    httpd_register_uri_handler(_handle, &uri_root);

    httpd_uri_t uri_status = {
        .uri = "/api/status", .method = HTTP_GET,
        .handler = _statusHandler, .user_ctx = nullptr
    };
    httpd_register_uri_handler(_handle, &uri_status);

    Serial.println("HTTPS: server started on port 443 (self-signed cert).");
    return true;
}

void httpsStop()
{
    if (!_handle) return;
    httpd_ssl_stop(_handle);
    _handle = nullptr;
    Serial.println("HTTPS: server stopped.");
}

bool httpsIsRunning() { return _handle != nullptr; }

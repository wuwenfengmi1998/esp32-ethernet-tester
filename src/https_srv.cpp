#include "https_srv.h"
#include "https_cert.h"
#include <esp_https_server.h>
#include <WiFi.h>

static httpd_handle_t _handle = nullptr;
static HttpsStatusFn  _statusFn;
static const char    *_html = nullptr;

void httpsSetStatusProvider(HttpsStatusFn fn) { _statusFn = fn; }

// --- handlers ----------------------------------------------------------------
static esp_err_t _rootHandler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, _html, strlen(_html));
    return ESP_OK;
}

static esp_err_t _statusHandler(httpd_req_t *req)
{
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

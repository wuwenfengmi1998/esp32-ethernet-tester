#pragma once
#include <Arduino.h>
#include <functional>

// Thin wrapper around ESP-IDF httpd_ssl to avoid header conflicts with
// ESPAsyncWebServer (both define HTTP_GET etc. as incompatible enums).

using HttpsStatusFn = std::function<String()>;

void  httpsSetStatusProvider(HttpsStatusFn fn);
bool  httpsStart(const char *indexHtml);
void  httpsStop();
bool  httpsIsRunning();

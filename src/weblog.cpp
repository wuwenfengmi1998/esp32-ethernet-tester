#include "weblog.h"

TeeStream Out;

void TeeStream::_ensureMutex()
{
    if (!_mtx) _mtx = xSemaphoreCreateMutex();
}

size_t TeeStream::write(uint8_t c)
{
    ::Serial.write(c);
    if (_capturing) {
        _ensureMutex();
        if (_mtx && xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
            if (_len < CAP) _buf[_len++] = (char)c;
            else            _overflow = true;
            xSemaphoreGive(_mtx);
        }
    }
    return 1;
}

size_t TeeStream::write(const uint8_t *buf, size_t size)
{
    ::Serial.write(buf, size);
    if (_capturing) {
        _ensureMutex();
        if (_mtx && xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
            size_t room = (CAP > _len) ? (CAP - _len) : 0;
            size_t n    = (size < room) ? size : room;
            if (n) { memcpy(_buf + _len, buf, n); _len += n; }
            if (n < size) _overflow = true;
            xSemaphoreGive(_mtx);
        }
    }
    return size;
}

void TeeStream::beginCapture()
{
    _ensureMutex();
    if (_mtx && xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
        _len = 0;
        _overflow = false;
        _capturing = true;
        xSemaphoreGive(_mtx);
    } else {
        _len = 0; _overflow = false; _capturing = true;
    }
}

void TeeStream::endCapture()
{
    _capturing = false;
}

void TeeStream::snapshot(String &out)
{
    _ensureMutex();
    out = "";
    if (_mtx && xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
        out.reserve(_len + 24);
        for (size_t i = 0; i < _len; i++) out += _buf[i];
        if (_overflow) out += "\r\n...[output truncated]\r\n";
        xSemaphoreGive(_mtx);
    }
}

#include "weblog.h"
#include "logger.h"
#include <esp_heap_caps.h>

TeeStream Out;

void TeeStream::_ensureMutex()
{
    if (!_mtx) _mtx = xSemaphoreCreateMutex();
}

void TeeStream::_ensureBuf()
{
    if (!_buf) {
        _buf = (char *)heap_caps_malloc(CAP, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!_buf) _buf = (char *)malloc(CAP);  // fallback to internal RAM
    }
}

size_t TeeStream::write(uint8_t c)
{
    ::Serial.write(c);
    logWrite(&c, 1);
    if (_capturing) {
        _ensureMutex();
        _ensureBuf();
        if (_buf && _mtx && xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
            _buf[_head] = (char)c;
            _head = (_head + 1) % CAP;
            if (_count < CAP) _count++;
            xSemaphoreGive(_mtx);
        }
    }
    return 1;
}

size_t TeeStream::write(const uint8_t *buf, size_t size)
{
    ::Serial.write(buf, size);
    logWrite(buf, size);
    if (_capturing) {
        _ensureMutex();
        _ensureBuf();
        if (_buf && _mtx && xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
            for (size_t i = 0; i < size; i++) {
                _buf[_head] = (char)buf[i];
                _head = (_head + 1) % CAP;
            }
            _count += size;
            if (_count > CAP) _count = CAP;
            xSemaphoreGive(_mtx);
        }
    }
    return size;
}

void TeeStream::beginCapture()
{
    _ensureMutex();
    _ensureBuf();
    if (_mtx && xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
        _head = 0;
        _count = 0;
        _capturing = true;
        xSemaphoreGive(_mtx);
    } else {
        _head = 0; _count = 0; _capturing = true;
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
    if (!_buf || !_mtx) return;
    if (xSemaphoreTake(_mtx, portMAX_DELAY) == pdTRUE) {
        out.reserve(_count + 1);
        if (_count < CAP) {
            // Buffer hasn't wrapped - data is at [0 .. _head)
            size_t start = (_head >= _count) ? (_head - _count) : (CAP - (_count - _head));
            for (size_t i = 0; i < _count; i++)
                out += _buf[(start + i) % CAP];
        } else {
            // Ring wrapped - oldest byte is at _head
            for (size_t i = 0; i < CAP; i++)
                out += _buf[(_head + i) % CAP];
        }
        xSemaphoreGive(_mtx);
    }
}

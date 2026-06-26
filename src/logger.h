#pragma once
#include <Arduino.h>

// =============================================================================
// SD Card Logger -- tees all Serial/Out output to a timestamped log file on SD.
//
// When enabled, every byte written through TeeStream (Out) is also appended
// to /logs/<name>.log on the SD card. Lines are auto-prefixed with an ISO
// timestamp when a newline follows.
//
// Usage:
//   logStart("mytest");          // opens /logs/mytest.log
//   logStop();                   // flushes and closes
//   logIsActive();               // check state
//   logWrite(buf, len);          // called from TeeStream::write()
//   logList();                   // list log files on SD
//   logDelete("mytest.log");     // remove a log file
// =============================================================================

bool        logStart(const char *name = nullptr);   // nullptr = auto-name with timestamp
void        logStop();
bool        logIsActive();
const char *logCurrentFile();                       // returns path or ""
void        logWrite(const uint8_t *buf, size_t len);
void        logFlush();                             // force flush to SD
void        logList();                              // print log directory listing
bool        logDelete(const char *filename);        // delete a log file
uint32_t    logSize();                              // current log file size

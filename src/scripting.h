#pragma once
#include <Arduino.h>

// =============================================================================
// Scripting Engine — run CLI command sequences from SD card scripts, with a
// cron-like scheduler, result collection, and file upload capabilities.
//
// Script language (one statement per line):
//   # comment
//   <any CLI command>            Run a CLI command
//   delay <ms>                   Pause for N milliseconds
//   wait <seconds>               Pause for N seconds
//   echo <message>               Print a message to output
//   log start [name]             Start logging output to SD
//   log stop                     Stop logging
//   if_time HH:MM-HH:MM         Skip rest of script if outside time window
//   if_day MON,TUE,...           Skip rest of script if not matching day
//   if_link up|down              Skip rest of script if link state doesn't match
//   set <VAR> <value>            Set a variable (up to 8 vars)
//   upload log <name> <url>      HTTP POST a log file to url
//   upload pcap <url>            HTTP POST the current pcap to url
//   upload log <name> sftp://user:pass@host/path   SFTP upload
//   repeat <count>               Repeat the following block N times
//   end_repeat                   End of repeat block
//   abort                        Stop script execution
//
// Cron entries stored in /cron.txt on SD:
//   MIN HOUR DOM MON DOW  command_or_script_path
//   */5  *   *   *   *    status
//   0    8   *   *   1-5  /scripts/morning.txt
//
// Script files stored in /scripts/ on SD.
// =============================================================================

// --- Script runner -----------------------------------------------------------
// Callback type: the scripting engine calls this to execute CLI commands.
typedef void (*ScriptCmdFn)(const String &cmd);

void scriptSetCommandHandler(ScriptCmdFn fn);

// Run a script file from SD. Returns true if started OK.
// If logName is non-null, logging starts automatically.
bool scriptRun(const char *path, const char *logName = nullptr);

// Run a script from a string buffer (for ad-hoc / web use).
bool scriptRunInline(const char *scriptText, const char *logName = nullptr);

// Stop a running script.
void scriptAbort();

// Is a script currently running?
bool scriptIsRunning();

// Get the currently running script name (or "").
const char *scriptCurrentFile();

// --- Cron scheduler ----------------------------------------------------------
void cronInit();                // Load /cron.txt from SD
void cronTick();                // Call from loop() every second or so
void cronReload();              // Re-read /cron.txt
void cronList();                // Print loaded cron entries
bool cronAdd(const char *entry);    // Add a cron entry (appends to file)
bool cronRemove(int index);         // Remove entry by index (rewrites file)
bool cronClear();                   // Remove all cron entries

// --- File upload -------------------------------------------------------------
// HTTP POST upload: sends file as multipart/form-data
bool uploadFileHttp(const char *sdPath, const char *url);

// Upload with HTTP Basic auth
bool uploadFileHttpAuth(const char *sdPath, const char *url,
                        const char *user, const char *pass);

// Configure default upload destination (stored in NVS)
void uploadSetDefault(const char *url, const char *user = nullptr,
                      const char *pass = nullptr);
void uploadGetDefault(char *url, size_t urlLen,
                      char *user, size_t userLen,
                      char *pass, size_t passLen);

/*
 * Logging framework
 */

#ifndef LOGGING_H
#define LOGGING_H

#include <stdarg.h>

enum log_level {
    LOG_ERROR = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
};

extern enum log_level current_log_level;

void simple_connection_log(enum log_level level, const char *format, ...);

#define log_error(...) simple_connection_log(LOG_ERROR, __VA_ARGS__)
#define log_warn(...) simple_connection_log(LOG_WARN, __VA_ARGS__)
#define log_info(...) simple_connection_log(LOG_INFO, __VA_ARGS__)
#define log_debug(...) simple_connection_log(LOG_DEBUG, __VA_ARGS__)

#endif

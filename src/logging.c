/*
 * Logging implementation
 */

#include <stdio.h>
#include <stdarg.h>

#include "logging.h"

enum log_level current_log_level = LOG_INFO;

void simple_connection_log(enum log_level level, const char *format, ...)
{
    if (level > current_log_level) {
        return;
    }

    const char *level_str[] = {"ERROR", "WARN", "INFO", "DEBUG"};
    fprintf(stderr, "[%s] ", level_str[level]);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
}

/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the declarations of functions and structs
 * implemented in log.c
 */

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * Enumeration for logging levels that can used.
 */
enum log_level {
    VERBOSE = 1,      // Lowest logging level
    INFO = 2,         // general logging level
    WARNING = 4,      // warning logging level
    ERROR = 8         // Highest logging level
};

void
info_log(const char *, ...);

void
verbose_log(const char *, ...);

void
error_log(const char *, ...);

void
warning_log(const char *, ...);

void
LOG(enum log_level, const char *, ...);

bool
is_log_level_configured(enum log_level);

void
set_log_level(enum log_level);

int
init_log(enum log_level, const char *);

void
close_log(void);

#endif /* LOG_H */

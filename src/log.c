/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the logging module.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#include "log.h"

#define MAX_BUF_LEN 1024

/**
 * Represents the config to be used while logging any message.
 */
struct log_config {
    int level;              // logging level to use
    const char *helper_id;  // helper_id to be used a filename
    pid_t pid;              // pid to be used in the log message
    int fd;                 // file descriptor for the log file
};

static const char *level2str[] = {
    [VERBOSE] = "VERBOSE",
    [INFO] = "INFO",
    [WARNING] = "WARNING",
    [ERROR] = "ERROR"
};

static struct log_config *config = NULL;
const char *log_dir = "/var/log/conntrack_migrator";

/**
 * Writes the timestamp to the buffer.
 *
 * Timestamp format YYYY-MM-DD HH:MM:SS.uS where uS is microseconds.
 *
 * Args:
 *   @buf buffer to which timestamp needs to be written.
 *
 * Returns:
 *   number of bytes written in buffer.
 */
static int
put_timestamp(char *buf)
{
    struct timespec tp;
    int ret;

    ret = clock_gettime(CLOCK_REALTIME, &tp);
    if (ret == -1) {
        printf("ERROR: can't get the clock time. \n");
        return 0;
    }
    ret = strftime(buf, 100, "%F %T", gmtime(&tp.tv_sec));
    ret += snprintf(buf + ret, 100, ".%06u", tp.tv_nsec/1000);
    return ret;
}

/**
 * Prepares the log message in the buffer and then write it to the file.
 *
 * Log format is as follows:
 * - YYYY-MM-DD HH:MM:SS.uS pid level log_message
 *
 * Args:
 *   @buf buffer in which message is written.
 *   @level  log level
 *   @format format string for the message
 *   @ap variable argument list corresponding to the format.
 *
 * Returns:
 *   number of bytes written.
 */
static int
putbuf(char *buf, int level, const char *format,  va_list ap)
{
    int _written = 0;
    _written += put_timestamp(buf);
    _written += snprintf(buf + _written,
                         MAX_BUF_LEN - _written,
                         " %7ld %7s ",
                         (long)config->pid, level2str[level]);
    _written += vsnprintf(buf + _written,
                          MAX_BUF_LEN - _written,
                          format, ap);
    _written += snprintf(buf + _written, MAX_BUF_LEN - _written, "\n");

    return write(config->fd, buf, _written);
}

/**
 * Logs message at INFO log level.
 *
 * Args:
 *   @format format specifier for the message.
 *   @... arguments corresponding to format.
 */
void
info_log(const char *format, ...)
{
    char buf[MAX_BUF_LEN];
    va_list args;

    if ((config->level & INFO) == 0) {
        return;
    }

    va_start(args, format);
    putbuf(buf, INFO, format, args);
    va_end(args);
}

/**
 * Logs message at WARNING log level.
 *
 * Args:
 *   @format format specifier for the message.
 *   @... arguments corresponding to format.
 */
void
warning_log(const char *format, ...)
{
    char buf[MAX_BUF_LEN];
    va_list args;

    if ((config->level & WARNING) == 0) {
        return;
    }

    va_start(args, format);
    putbuf(buf, WARNING, format, args);
    va_end(args);
}

/**
 * Logs message at ERROR log level.
 *
 * Args:
 *   @format format specifier for the message.
 *   @... arguments corresponding to format.
 */
void
error_log(const char *format, ...)
{
    char buf[MAX_BUF_LEN];
    va_list args;

    if ((config->level & ERROR) == 0) {
        return;
    }

    va_start(args, format);
    putbuf(buf, ERROR, format, args);
    va_end(args);
}

/**
 * Logs message at VERBOSE log level.
 *
 * Args:
 *   @format format specifier for the message.
 *   @... arguments corresponding to format.
 */
void
verbose_log(const char *format, ...)
{
    char buf[MAX_BUF_LEN];
    va_list args;

    if ((config->level & VERBOSE) == 0) {
        return;
    }

    va_start(args, format);
    putbuf(buf, VERBOSE, format, args);
    va_end(args);
}

/**
 * Logs message at the specified level.
 *
 * Level specified should be one of the VERBOSE, INFO, WARNING, or
 * ERROR. The reason for adding this function is have single point of control.
 *
 * Args:
 *   @level level at which message needs to be logged.
 *   @format format specifier for the message.
 *   @... arguments corresponding to format.
 */
void
LOG(enum log_level level, const char *format, ...)
{
    char buf[MAX_BUF_LEN];
    va_list args;

    if ((config->level & level) == 0) {
        return;
    }

    va_start(args, format);
    putbuf(buf, level, format, args);
    va_end(args);
}

/**
 * Converts the string level to logging flags.
 *
 * Args:
 *   @lvl : level string.
 *
 * Returns:
 *   logging level flags.
 */
static int
parse_log_level(enum log_level lvl)
{
    int log_level = 0;

    switch(lvl) {
    case VERBOSE:
        log_level |= VERBOSE;
    case INFO:
        log_level |= INFO;
    case WARNING:
        log_level |= WARNING;
    case ERROR:
        log_level |= ERROR;
        break;
    default:
        log_level = INFO|WARNING|ERROR;
    }

    return log_level;
}

/**
 * Checks if specified level configured for logging.
 *
 * Args:
 *   @level logging level to be checked.
 *
 * Returns:
 *   true if the message at the specified logging level is configured to be
 *   logged to the log file, false otherwise.
 */
bool
is_log_level_configured(enum log_level level)
{
    if ((config->level & level) == 0) {
        return false;
    }

    return true;
}

void
set_log_level(enum log_level level)
{
    config->level = parse_log_level(level);
}

/**
 * Initialises the logging module.
 *
 * Log file path is as follows:
 *    /var/log/lmct/<helper_id>.out
 *
 * Args:
 *   @lvl logging level to be used.
 *   @helper_id to be used as filename
 *
 * Returns:
 *   0 on sucess, -1 otherwise
 */
int
init_log(enum log_level lvl, const char *helper_id)
{
    struct stat st = { 0 };
    char *log_file_path;
    int level, fd;

    if (stat(log_dir, &st) == -1) {
        mkdir(log_dir, 0700);
    }

    log_file_path = g_malloc0(sizeof(char) * 512);
    snprintf(log_file_path, 512, "%s/%s.out", log_dir, helper_id);

    level = parse_log_level(lvl);

    fd = open(log_file_path, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
    if (fd == -1) {
        goto err;
    }

    config = g_malloc0(sizeof(struct log_config));
    config->level = level;
    config->helper_id = helper_id;
    config->pid = getpid();
    config->fd = fd;

    return 0;

err:
    g_free(log_file_path);
    g_free(config);
    return -1;
}

/**
 * Closes the log file descriptors.
 */
void
close_log(void)
{
    if (config != NULL) {
        close(config->fd);
        g_free(config);
    }
}

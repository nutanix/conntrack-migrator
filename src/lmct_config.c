/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the functionality for parsing user configurable parameters from a
 * config file. Currently only 2 parameters are configurable:
 *   1. Logging level
 *   2. Maximum number of conntrack entries to migrate.
 */

#include <stdbool.h>
#include <stdint.h>

#include <gio/gio.h>
#include <glib.h>

#include "common.h"
#include "lmct_config.h"
#include "log.h"

#define MAX_ENTRIES_TO_MIGRATE 10000 // 10K

struct lmct_config lmct_conf = {
    .log_lvl = INFO,
    .max_entries_to_migrate = MAX_ENTRIES_TO_MIGRATE
};

/**
 * Validate the level option read from config file.
 *
 * Args:
 *   @val log level string
 * Returns:
 *   int log level representation if success in parsing,
 *   -1 otherwise
 */
static int
parse_log_level_str(const char *val)
{
    if (strcmp(val, "VERBOSE") == 0) {
       return VERBOSE;
    }
    if (strcmp(val, "INFO") == 0) {
        return INFO;
    }
    if (strcmp(val, "WARNING") == 0) {
        return WARNING;
    }
    if (strcmp(val, "ERROR") == 0) {
        return ERROR;
    }
    return -1;
}

/**
 * Reads the "level" option from the config file.
 *
 * This function reads the "level" option from the configuration file and sets
 * the "log_lvl" member of the lmct_config struct. If the option is not found
 * then it initializes it with the default value.
 *
 * Args:
 *   @key_file pointer to the configuration file.
 *   @conf struct to be populated with the configuration.
 */
static void
populate_log_level(GKeyFile *key_file, struct lmct_config *conf)
{
    g_autoptr(GError) error = NULL;
    const gchar *val;

    val = g_key_file_get_string(key_file, "LOG", "level", &error);
    if (val != NULL) {
        int lvl;

        lvl = parse_log_level_str(val);
        if (lvl == -1) {
            LOG(ERROR, "%s: Unable to parse log level in config.", __func__);
            exit(EXIT_FAILURE);
        }

        conf->log_lvl = lvl;
        return;
    }

    LOG(INFO, "%s: Log level not found in config.", __func__);
    conf->log_lvl = INFO;
}

/**
 * Reads the "max_entries_to_migrate" option from the config file.
 *
 * This function reads the "max_entries_to_migrate" option from the
 * configuration file and sets the "max_entries_to_migrate" member of the
 * lmct_config struct. If the option is not found, then it initializes it
 * with the default value.
 * In case an invalid value is found, terminates the program.
 *
 * Args:
 *   @key_file pointer to the configuration file.
 *   @conf struct to be populated with the configuration.
 */
static void
populate_max_entries_to_migrate(GKeyFile *key_file, struct lmct_config *conf)
{
    g_autoptr(GError) error = NULL;
    int val;

    val = g_key_file_get_integer(key_file, "CONNTRACK",
                                 "max_entries_to_migrate", &error);

    if (error == NULL && val >= 0) {
        conf->max_entries_to_migrate = val;
        return;
    }

    if (val < 0) {
        LOG(ERROR, "%s: Error reading max_entries_to_migrate in config. "
            "Value is negative %d", __func__, val);
        exit(EXIT_FAILURE);
    }

    if (error != NULL && g_error_matches(error, G_KEY_FILE_ERROR,
                                         G_KEY_FILE_ERROR_INVALID_VALUE)) {
        LOG(ERROR, "%s: Error reading max_entries_to_migrate in config. %s",
            __func__, error->message);
        exit(EXIT_FAILURE);
    }

    LOG(INFO, "%s: max_entries_to_migrate not found in config.", __func__);

    conf->max_entries_to_migrate = MAX_ENTRIES_TO_MIGRATE;
}

/**
 * Reads the configuration file and initialises the config options for the
 * application.
 *
 * This function reads the configuration file present at
 * "/etc/lmct_config" and sets the corresponding options (currently
 * log_level, max_entries_to_migrate). If the config file is not found
 * then it initializes the default values for the above options.
 *
 * Args:
 *   @conf struct to be populated with the configuration.
 *   @config_file_path String path to the configuration file.
 */
static void
read_lmct_config(struct lmct_config *conf, const char *config_file_path)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GKeyFile) key_file;

    key_file = g_key_file_new();
    if (!g_key_file_load_from_file(key_file,
                                   config_file_path,
                                   G_KEY_FILE_NONE,
                                   &error)) {
        LOG(INFO, "%s: Config file not found. Using default config values.",
            __func__);
        return;
    }

    populate_log_level(key_file, conf);
    populate_max_entries_to_migrate(key_file, conf);
}

/**
 * Initialises the configuration module.
 *
 * Args:
 *   @config_file_path path to the configuration file.
 */
void
init_lmct_config(const char *config_file_path)
{
    read_lmct_config(&lmct_conf, config_file_path);

}

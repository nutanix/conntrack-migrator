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
 * implemented in lmct_config.c
 */

#ifndef LMCT_CONFIG_H
#define LMCT_CONFIG_H

#include <stdint.h>

#include "log.h"


enum filter_type {
    FILTER_BY_CT_ZONE,
    FILTER_BY_IP
};
/**
 * Represents the config options which are used globally in the application.
 */
struct lmct_config {
    uint32_t max_entries_to_migrate; // Max number of CT entries to migrate
    enum log_level log_lvl;          // Logging level to used
};

extern struct lmct_config lmct_conf;

extern enum filter_type fltr_type;
void
init_lmct_config();

void
populate_filter_type(enum filter_type);

#endif /* LMCT_CONFIG_H */

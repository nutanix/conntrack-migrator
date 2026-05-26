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
 * implemented in common.c
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include <glib.h>

/**
 * Sub-mode tag: tells the rest of the daemon which SAVE-mode CLI layout
 * was detected from argv.
 */
enum save_input_kind {
    SAVE_INPUT_IPS,
    SAVE_INPUT_PORT_ZONES
};

/**
 * Sub-mode tag: tells the rest of the daemon which LOAD-mode CLI layout
 * was detected from argv.
 */
enum load_input_kind {
    LOAD_INPUT_LEGACY,
    LOAD_INPUT_PORT_ZONES
};

/**
 * Bundle of SAVE-side migration targets. Tagged union over CLI sub-mode:
 *   kind == SAVE_INPUT_IPS         -> ips_to_migrate is set
 *   kind == SAVE_INPUT_PORT_ZONES  -> zones_to_migrate and ports_to_migrate
 *                                     are set
 * All hashtables are owned by save_targets and freed by save_targets_destroy.
 */
struct save_targets {
    enum save_input_kind kind;
    GHashTable *ips_to_migrate;
    GHashTable *zones_to_migrate;
    GHashTable *ports_to_migrate;
};

GHashTable *
create_hashtable_from_ip_list(const char *[], int);

bool
is_valid_uuid_string(const char *);

bool
parse_ct_zone(const char *, uint16_t *);

GHashTable *
create_hashtable_from_zone_and_port_list(const char *zones[],
                                         const char *port_uuids[],
                                         int n_entries,
                                         GHashTable **out_ports);

struct save_targets *
save_targets_new_from_ips(GHashTable *ips_to_migrate);

struct save_targets *
save_targets_new_from_zones_and_ports(GHashTable *zones, GHashTable *ports);

void
save_targets_destroy(struct save_targets *);

#endif /* COMMON_H */

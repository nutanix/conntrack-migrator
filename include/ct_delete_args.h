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
 * implemented in ct_delete_args.c
 */

#ifndef CT_DELETE_H
#define CT_DELETE_H

#include <pthread.h>

#include "common.h"

/**
 * Represents the arguments to be passed to the thread responsible
 * for cleaning up the conntrack entries in source hypervisor upon
 * successful migration.
 *
 * Real C tagged union over the active SAVE sub-mode:
 *   op_type == SAVE_IPS_OP        -> ips_migrated / ips_on_host valid.
 *   op_type == SAVE_PORT_ZONE_OP  -> zones_migrated / zones_on_host valid.
 * (the two pairs overlay the same memory; only the active arm is set.)
 *
 * Ownership:
 *   - ips_migrated / zones_migrated are aliases into save_mode_config and
 *     must not be freed by the delete thread.
 *   - ips_on_host / zones_on_host are built by on_clear and consumed by
 *     the delete thread; they are released alongside process exit since
 *     the daemon is short-lived.
 */
struct ct_delete_args {
    pthread_t tid;                   // Represents the thread ID
    enum save_mode_op_type op_type;  // Active SAVE sub-mode; selects which arm
                                     // of the union below is valid.

    /* Active sub-mode state. Anonymous outer union forces mutual
     * exclusion (a SAVE mode is either IP-list-driven or port-zone-
     * driven, never both), but the inner structs are anonymous so
     * field access stays flat:
     *   ct_del_args.ips_migrated, ct_del_args.zones_on_host, etc.
     */
    union {
        /* op_type == SAVE_IPS_OP */
        struct {
            GHashTable *ips_migrated;  // IP addresses migrated from this host
            GHashTable *ips_on_host;   // IP addresses currently on this host
        };
        /* op_type == SAVE_PORT_ZONE_OP */
        struct {
            GHashTable *zones_migrated; // CT zones migrated from this host
            GHashTable *zones_on_host;  // CT zones currently owned by ports on this host
        };
    };

    bool clear_called;         // Flag to indicate if clear DBUS IPC is invoked
    pthread_mutex_t mutex;            // mutex for the condition var
    pthread_cond_t clear_called_cond; // Condition to wait until the clear IPC is called
};

/**
 * ct_del_args is made global since it is accessed from multiple threads.
 **/
extern struct ct_delete_args ct_del_args;

#endif /* CT_DELETE_ARGS_H */

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
 * Tagged union over the active SAVE sub-mode:
 *   kind == SAVE_INPUT_IPS         -> ips_migrated / ips_on_host valid.
 *   kind == SAVE_INPUT_PORT_ZONES  -> zones_migrated / zones_on_host valid.
 *
 * Ownership:
 *   - ips_migrated / zones_migrated are aliases into save_targets and must
 *     not be freed by the delete thread.
 *   - ips_on_host / zones_on_host are built by on_clear and consumed by
 *     the delete thread; they are released alongside process exit since
 *     the daemon is short-lived.
 */
struct ct_delete_args {
    pthread_t tid;             // Represents the thread ID
    enum save_input_kind kind; // Active SAVE sub-mode; selects which set
                               // of pointers below is valid.

    /* IP-mode state */
    GHashTable *ips_migrated;  // IP addresses migrated from this host
    GHashTable *ips_on_host;   // IP addresses currently on this host

    /* Zone-mode state */
    GHashTable *zones_migrated; // CT zones migrated from this host
    GHashTable *zones_on_host;  // CT zones currently owned by ports on this host

    bool clear_called;         // Flag to indicate if clear DBUS IPC is invoked
    pthread_mutex_t mutex;            // mutex for the condition var
    pthread_cond_t clear_called_cond; // Condition to wait until the clear IPC is called
};

/**
 * ct_del_args is made global since it is accessed from multiple threads.
 **/
extern struct ct_delete_args ct_del_args;

#endif /* CT_DELETE_ARGS_H */

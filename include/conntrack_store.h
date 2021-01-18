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
 * implemented in conntrack_store.c
 */

#ifndef CONNTRACK_STORE_H
#define CONNTRACK_STORE_H

#include <glib.h>
#include <pthread.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

/**
 * Represents the hashtable to store the conntrack entries received from the
 * kernel.
 */
struct conntrack_store {
    GHashTable *store;    // Hashtable to store the entries
    pthread_mutex_t lock; // Mutex lock
};

extern struct conntrack_store *conn_store;

struct conntrack_store *
conntrack_store_new(void);

void
conntrack_store_destroy(struct conntrack_store *);

void
update_conntrack_store(struct conntrack_store *, struct nf_conntrack *,
                       enum nf_conntrack_msg_type);

#endif /* CONNTRACK_STORE_H */

/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the functions that interfaces
 *   with the conntrack store hashtable.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <pthread.h>

#include "conntrack_entry.h"
#include "conntrack_store.h"

struct conntrack_store *conn_store;

/**
 * Allocates memory for conntrack_store struct
 *
 * Returns:
 *   pointer to the allocated memory if success.
 *   In case of any error, terminates the process.
 */
struct conntrack_store *
conntrack_store_new(void)
{
    struct conntrack_store *conn_store;
    int ret;

    conn_store = g_malloc0(sizeof(struct conntrack_store));
    conn_store->store = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                              NULL,
                                              conntrack_entry_destroy_g_wrapper);

    ret = pthread_mutex_init(&conn_store->lock, NULL);
    assert(ret == 0);

    return conn_store;
}

/**
 * Releases the conntrack_store.
 *
 * Args:
 *   @conn_store pointer to hashtable to be released.
 */
void
conntrack_store_destroy(struct conntrack_store *conn_store)
{
    if (conn_store == NULL) {
        return;
    }

    if (conn_store->store != NULL) {
        g_hash_table_destroy(conn_store->store);
    }

    pthread_mutex_destroy(&conn_store->lock);
    g_free(conn_store);
}

/**
 * Inserts the entry into conntrack_store.
 *
 * This function uses the CTId of the conntrack_entry as the key for the
 * hashtable and converts nf_conntrack into a conntrack_entry struct by
 * filtering out the required attributes and use it as the value for the
 * key.
 *
 * Args:
 *   @conn_store pointer to the conntrack store.
 *   @ct pointer to nf_conntrack entry received from netlink dump/event
 *
 * Returns:
 *   0 in case of success, -1 otherwise.
 */
static int
conntrack_store_insert(struct conntrack_store *conn_store,
                       struct nf_conntrack *ct)
{
    uint32_t ct_id;
    struct conntrack_entry *ct_entry;

    ct_id = nfct_get_attr_u32(ct, ATTR_ID);
    if (ct_id == 0) {
        LOG(WARNING, "%s: CT with ID = 0 received!", __func__);
        return -1;
    }

    ct_entry = conntrack_entry_from_nf_conntrack(ct);
    if (ct_entry == NULL) {
        LOG(WARNING, "%s: received ct_entry as NULL", __func__);
        return -1;
    }

    pthread_mutex_lock(&conn_store->lock);
    g_hash_table_insert(conn_store->store, GUINT_TO_POINTER(ct_id), ct_entry);
    pthread_mutex_unlock(&conn_store->lock);

    return 0;
}

/**
 * Deletes the entry from the conntrack_store.
 *
 * This function extracts the ctid from the ct argument and then removes the
 * entry corresponding to the Ctid from the hashtable. Even if the entry is
 * not present in hashtable, the function treats it as a success.
 *
 * Args:
 *   @conn_store pointer to the conntrack store
 *   @ct pointer to the nf_conntrack received as part of destroy event
 *       during netlink events.
 * Returns:
 *   0 if success, -1 otherwise.
 */
static int
conntrack_store_remove(struct conntrack_store *conn_store,
                       struct nf_conntrack *ct)
{
    uint32_t ct_id;

    ct_id= nfct_get_attr_u32(ct, ATTR_ID);
    if (ct_id == 0) {
        return -1;
    }

    pthread_mutex_lock(&conn_store->lock);
    g_hash_table_remove(conn_store->store, GUINT_TO_POINTER(ct_id));
    pthread_mutex_unlock(&conn_store->lock);

    return 0;
}

/**
 * Process new event.
 *
 * Insert the conntrack_entry into the conntrack_store.
 *
 * Args:
 *   @conn_store pointer to the conntrack store.
 *   @ct pointer to the nf_conntrack entry received as part of the
 *       netlink event.
 */
static void
handle_new_event(struct conntrack_store *conn_store,
                 struct nf_conntrack *ct)
{
    conntrack_store_insert(conn_store, ct);
}

/**
 * Process update event.
 *
 * This function checks whether we already have a conntrack_entry in the
 * conntrack_store corresponding to ct. If yes, then we update the
 * conntrack_entry with the new info. Otherwise we create a new conntrack_entry
 * from the ct and insert it into the conntrack table.
 *
 * Args:
 *   @conn_store pointer to the conntrack_store hashtable
 *   @ct pointer to the nf_conntrack entry received as part of the
 *       netlink event.
 */
static void
handle_update_event(struct conntrack_store *conn_store,
                    struct nf_conntrack *ct)
{
    uint32_t ct_id;
    struct conntrack_entry *ct_entry;
    struct conntrack_entry *res_ct_entry;

    ct_id = nfct_get_attr_u32(ct, ATTR_ID);
    if (ct_id == 0) {
        LOG(WARNING, "%s: ct entry with 0 id received. Skipping.", __func__);
        return;
    }

    const gpointer key = GUINT_TO_POINTER(ct_id);
    pthread_mutex_lock(&conn_store->lock);
    ct_entry = g_hash_table_lookup(conn_store->store, key);
    if (ct_entry == NULL) {
        LOG(VERBOSE, "%s: Update received for a non-existent entry. "
            "Treating it as NEW.", __func__);
        res_ct_entry = conntrack_entry_from_nf_conntrack(ct);
    } else {
        res_ct_entry = get_conntrack_entry_from_update(ct_entry, ct);
    }

    if (res_ct_entry == NULL) {
        LOG(WARNING, "%s: received res_ct_entry as NULL", __func__);
    } else {
        g_hash_table_insert(conn_store->store, key, res_ct_entry);
    }

    pthread_mutex_unlock(&conn_store->lock);
}

/**
 * Process destroy event.
 *
 * Args:
 *   @conn_store pointer to the conntrack store.
 *   @ct pointer to the nf_conntrack entry received as part of the
 *     netlink event.
 */
static void
handle_destroy_event(struct conntrack_store *conn_store,
                     struct nf_conntrack *ct)
{
    int ret = conntrack_store_remove(conn_store, ct);
    if (ret == -1) {
        LOG(WARNING, "%s: CT entry with 0 id received. Skipping.", __func__);
    }
}

/**
 * Update the conntrack store based on the event received from the netlink.
 *
 * This function perform the following operations based on the event
 * type received.
 *  - NEW event: Inserts the conntrack_entry into the conntrack table
 *  - UPDATE event: Updates the conntrack_entry corresponding to the ct.
 *  - DELETE event: removes the conntrack_entry from the hashtable.
 *
 *  NOTE: @ct passed should have a positive conntrack id, otherwise no
 *  operation is performed on the hashtable.
 *
 *  Args:
 *    @conn_store pointer to the conntrack store.
 *    @ct pointer to the nf_conntrack entry received as part of the
 *        netlink event.
 *    @type event type. (NEW/UPDATE/DESTROY)
 */
void
update_conntrack_store(struct conntrack_store *conn_store,
                       struct nf_conntrack *ct,
                       enum nf_conntrack_msg_type type)
{
    switch(type) {
    case NFCT_T_NEW:
        handle_new_event(conn_store, ct);
        break;
    case NFCT_T_UPDATE:
        handle_update_event(conn_store, ct);
        break;
    case NFCT_T_DESTROY:
        handle_destroy_event(conn_store, ct);
        break;
    default:
        LOG(WARNING, "%s: unknown message type. Skipping...", __func__);
        break;
    }
}

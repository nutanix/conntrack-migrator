/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the functions that prepare the data to
 * be sent to dbus.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <gio/gio.h>
#include <glib.h>

#include "conntrack_entry.h"
#include "conntrack_store.h"
#include "data_template.h"
#include "lmct_config.h"
#include "marshal.h"

/**
 * Calculates the size of an array that needs to be sent to dbus.
 *
 * Args:
 *   @conn_store pointer to the connection_store containing the conntrack
 *               entries.
 *   @data_tmpl pointer to the data template.
 *
 * Returns:
 *   size in bytes of data to be sent to dbus.
 */
static uint32_t
calculate_payload_size(struct conntrack_store *conn_store,
                       struct data_template *data_tmpl)
{
    uint32_t payload_size = 0;
    GHashTableIter iter;
    gpointer key, value = NULL;
    struct conntrack_entry *ct_entry;

    // First is payload size itself -> uint32_t
    payload_size += UINT32_T_SIZE;

    // Second param is the data template.
    payload_size += (UINT8_T_SIZE + data_tmpl->payload_size);

    // Third param is conntrack entries
    pthread_mutex_lock(&conn_store->lock);
    g_hash_table_iter_init(&iter, conn_store->store);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        ct_entry = (struct conntrack_entry *)value;
        payload_size += BITMAP_NUM_WORDS * WORD_SIZE;
        payload_size += ct_entry->data_size;
    }
    pthread_mutex_unlock(&conn_store->lock);
    return payload_size;
}

/**
 * Writes the payload-size value to the buffer.
 *
 * Args:
 *   @start pointer to the buffer offset where the data needs to be
 *          written.
 *   @payload_size value to be written to the buffer.
 *
 * Returns:
 *   address in buffer where writing is finished.
 */
static void *
marshal_payload_size(void *start, uint32_t payload_size)
{
    LOG(VERBOSE, "%s: writing data size=%d", __func__, payload_size);

    memcpy(start, &payload_size, sizeof(payload_size));
    start += sizeof(payload_size);

    return start;
}

/**
 * Writes the template fields to the buffer.
 *
 * This function writes in the following format:
 * first num_bits representing the bits in the bitmap is written.
 * After that, for each bit in its size value is written. Each of
 * these values are uint8_t.
 *
 * Args:
 *   @start pointer to the buffer offset where the data needs to be
 *          written.
 *   @data_tmpl pointer to the data_template struct to be written to
 *              the buffer.
 *
 * Returns address in buffer where writing is finished.
 */
static void *
marshal_template(void *start, struct data_template *data_tmpl)
{
    LOG(VERBOSE, "%s: writing template.", __func__);

    memcpy(start, &data_tmpl->num_bits, UINT8_T_SIZE);
    start += UINT8_T_SIZE;
    memcpy(start, data_tmpl->payload, data_tmpl->payload_size);
    start += data_tmpl->payload_size;

    return start;
}

/**
 * Writes the CT entries to the buffer.
 *
 * This function writes in the following format:
 *  for each entry in the conntrack store:
 *  - first its bitmap is written
 *  - then the relevant conntrack fields are written.
 *
 * Args:
 *   @start pointer to the buffer offset where the data needs to be
 *          written.
 *   @conn_store pointer to the conntrack_store containing the conntrack
 *               entries.
 *
 * Returns:
 *   address in buffer where writing is finished.
 */
static void *
marshal_conntrack_store(void *start, struct conntrack_store *conn_store)
{
    LOG(VERBOSE, "%s: writing CT entries.", __func__);

    GHashTableIter iter;
    gpointer key, value = NULL;

    // Write the CT entries.
    pthread_mutex_lock(&conn_store->lock);
    g_hash_table_iter_init(&iter, conn_store->store);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        struct conntrack_entry *ct_entry = NULL;
        ct_entry = (struct conntrack_entry *)value;

        // Write the bitmap
        memcpy(start, ct_entry->bitmap, BITMAP_NUM_WORDS * WORD_SIZE);
        start += BITMAP_NUM_WORDS * WORD_SIZE;

        // Write the Conntrack Entry
        memcpy(start, ct_entry->data, ct_entry->data_size);
        start += ct_entry->data_size;
    }
    pthread_mutex_unlock(&conn_store->lock);
    return start;
}

/**
 * Sets the payload to 0 in case there is no data available to migrate.
 *
 * Args:
 *   @data_size the size of the data to be sent, is set in this field.
 *
 * Returns:
 *   buffer in which data is marshalled
 */
static void *
handle_no_data_to_migrate(uint32_t *data_size)
{
    void *buffer;

    *data_size = UINT32_T_SIZE;
    buffer = g_malloc0(*data_size);
    marshal_payload_size(buffer, 0);
    return buffer;
}

/**
 * Creates a buffer and writes the data to be sent to the dbus.
 *
 * This function creates a buffer and writes the following data:
 *  1. Size of payload
 *  2. Data template representing how to parse the conntrack entries.
 *  3. Conntrack entries along with their bitmaps.
 *
 * Args:
 *   @conn_store pointer to the conntrack_store containing the conntrack
 *               entries.
 *   @data_tmpl pointer to the data_template struct to be sent to dbus.
 *   @data_size the size of the data to be sent, is set in this field.
 *
 * Returns:
 *   buffer in which data is marshalled.
 */
void *
marshal(struct conntrack_store *conn_store, struct data_template *data_tmpl,
        uint32_t *data_size)
{
    uint32_t num_ct_entries = 0;
    void *buffer, *buffer_offset;

    // Marshal only in case all the data is intact
    if (conn_store != NULL && data_tmpl != NULL && data_size != NULL) {
        pthread_mutex_lock(&conn_store->lock);
        num_ct_entries = g_hash_table_size(conn_store->store);
        pthread_mutex_unlock(&conn_store->lock);
    }

    // CASE 1: No data to migrate.
    if (num_ct_entries == 0) {
        LOG(INFO, "%s: No entries to migrate. Skipping conntrack store "
            "marshalling", __func__);
        if (data_size == NULL) {
            return NULL;
        } else {
            return handle_no_data_to_migrate(data_size);
        }
    }

    // CASE 2: Data to migrate exceeds the limit set by the user. This is
    // identical to the case 1 except for log messages.
    if (num_ct_entries > lmct_conf.max_entries_to_migrate) {
        LOG(WARNING, "%s: Conntrack table contains more entries than the max "
            "limit.", __func__);
        LOG(WARNING, "%s: Not migrating them otherwise it could result in "
            "significant latency in VM migration.", __func__);
        LOG(WARNING, "%s: Max entries configured: %d, Conntrack table size: %d",
            __func__, lmct_conf.max_entries_to_migrate, num_ct_entries);
        return handle_no_data_to_migrate(data_size);
    }

    // Case-3 : Data is available to migrate and is within the limits set by
    // the user.
    *data_size = calculate_payload_size(conn_store, data_tmpl);
    LOG(VERBOSE, "%s: payload_size calulated: %d", __func__, *data_size);

    // Allocate the buffer
    buffer = g_malloc0(*data_size);
    buffer_offset = buffer;

    buffer_offset = marshal_payload_size(buffer_offset, *data_size);
    buffer_offset = marshal_template(buffer_offset, data_tmpl);
    buffer_offset = marshal_conntrack_store(buffer_offset, conn_store);

    return buffer;
}

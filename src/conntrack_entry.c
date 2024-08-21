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
 * with the conntrack_entry struct. This file provides the functionality
 * of converting the CT entry into an intermediate form
 * (called conntrack_entry).
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> //For memset

#include <glib.h>

#include "conntrack_entry.h"

int ct_entry_attr_to_size[CT_ATTR_MAX] = {
    [CT_ATTR_L3_SRC_V4] = UINT32_T_SIZE,
    [CT_ATTR_L3_DST_V4] = UINT32_T_SIZE,
    [CT_ATTR_L3_PROTONUM] = UINT8_T_SIZE,
    [CT_ATTR_PROTONUM] = UINT8_T_SIZE,
    [CT_ATTR_ZONE] = UINT16_T_SIZE,
    [CT_ATTR_L4_SRC_PORT] = UINT16_T_SIZE,
    [CT_ATTR_L4_DST_PORT] = UINT16_T_SIZE,
    [CT_ATTR_ICMP_SRC_ID] = UINT16_T_SIZE,
    [CT_ATTR_ICMP_DST_TYPE] = UINT8_T_SIZE,
    [CT_ATTR_ICMP_DST_CODE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_STATE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_ORIG_FLAGS_VALUE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_ORIG_FLAGS_MASK] = UINT8_T_SIZE,
    [CT_ATTR_TCP_ORIG_WSCALE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_REPL_FLAGS_VALUE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_REPL_FLAGS_MASK] = UINT8_T_SIZE,
    [CT_ATTR_TCP_REPL_WSCALE] = UINT8_T_SIZE,
    [CT_ATTR_TIMEOUT] = UINT32_T_SIZE,
    [CT_ATTR_MARK] = UINT32_T_SIZE,
    [CT_ATTR_STATUS] = UINT32_T_SIZE,
    [CT_ATTR_LABEL] = UINT32_T_SIZE * CT_LABEL_NUM_WORDS
};

enum nf_conntrack_attr ct_entry_attr_to_nf_attr[CT_ATTR_MAX] = {
    [CT_ATTR_L3_SRC_V4] = ATTR_IPV4_SRC,
    [CT_ATTR_L3_DST_V4] = ATTR_IPV4_DST,
    [CT_ATTR_L3_PROTONUM] = ATTR_L3PROTO,
    [CT_ATTR_PROTONUM] = ATTR_L4PROTO,
    [CT_ATTR_ZONE] = ATTR_ZONE,
    [CT_ATTR_L4_SRC_PORT] = ATTR_PORT_SRC,
    [CT_ATTR_L4_DST_PORT] = ATTR_PORT_DST,
    [CT_ATTR_ICMP_SRC_ID] = ATTR_ICMP_ID,
    [CT_ATTR_ICMP_DST_TYPE] = ATTR_ICMP_TYPE,
    [CT_ATTR_ICMP_DST_CODE] = ATTR_ICMP_CODE,
    [CT_ATTR_TCP_STATE] = ATTR_TCP_STATE,
    [CT_ATTR_TCP_ORIG_FLAGS_VALUE] = ATTR_TCP_FLAGS_ORIG,
    [CT_ATTR_TCP_ORIG_FLAGS_MASK] = ATTR_TCP_MASK_ORIG,
    [CT_ATTR_TCP_ORIG_WSCALE] = ATTR_TCP_WSCALE_ORIG,
    [CT_ATTR_TCP_REPL_FLAGS_VALUE] = ATTR_TCP_FLAGS_REPL,
    [CT_ATTR_TCP_REPL_FLAGS_MASK] = ATTR_TCP_MASK_REPL,
    [CT_ATTR_TCP_REPL_WSCALE] = ATTR_TCP_WSCALE_REPL,
    [CT_ATTR_TIMEOUT] = ATTR_TIMEOUT,
    [CT_ATTR_MARK] = ATTR_MARK,
    [CT_ATTR_STATUS] = ATTR_STATUS,
    [CT_ATTR_LABEL] = ATTR_CONNLABELS,
};

/**
 * Allocates a new conntrack_entry
 *
 * Returns:
 *   pointer to the allocated memory if success.
 *   In case of error, the process is terminated.
 */
struct conntrack_entry *
conntrack_entry_new(void)
{
    struct conntrack_entry *ct_entry;

    ct_entry = g_malloc0(sizeof(struct conntrack_entry));
    ct_entry->bitmap = g_malloc0(BITMAP_NUM_WORDS * WORD_SIZE);

    return ct_entry;
}

/**
 * Releases the conntrack_entry.
 *
 * Args:
 *   @ct_entry pointer to the conntrack_entry to be destroyed.
 */
void
conntrack_entry_destroy(struct conntrack_entry *ct_entry)
{
    if (ct_entry == NULL) {
        return;
    }

    g_free(ct_entry->bitmap);
    g_free(ct_entry->data);
    g_free(ct_entry);
}

/**
 * Releases the conntrack_entry.
 *
 * Wrapper around conntrack_entry_destroy to be passed as an
 * argument to g_hashtable free functions.
 *
 * Args:
 *   @ct_entry pointer to the conntrack_entry to be destroyed.
 */
void
conntrack_entry_destroy_g_wrapper(void *ct_entry)
{
    conntrack_entry_destroy(ct_entry);
}

/**
 * Sets the bit in the bitmap.
 *
 * Args:
 *   @bm pointer to the bitmap.
 *   @bit index to set.
 */
static void
set_bit_in_bitmap(uint32_t *bm, uint8_t bit)
{
    uint8_t num_bits_in_word = WORD_SIZE * BITS_PER_BYTE;
    uint8_t word = bit / num_bits_in_word;
    uint8_t bit_in_word = bit - (word * num_bits_in_word);

    bm[word] |= (1 << bit_in_word);
}

/**
 * Unset the bit in the bitmap.
 *
 * Args:
 *   @bm pointer to the bitmap
 *   @bit index to unset.
 */
static void
unset_bit_in_bitmap(uint32_t *bm, uint8_t bit)
{
    uint8_t num_bits_in_word = WORD_SIZE * BITS_PER_BYTE;
    uint8_t word = bit / num_bits_in_word;
    uint8_t bit_in_word = bit - (word * num_bits_in_word);
    uint32_t mask = 0xffffffff ^ (1 << bit_in_word);

    bm[word] &= mask;
}

/**
 * Checks if certain bit is set in the bitmap.
 *
 * Args:
 *   @bm pointer to the bitmap
 *   @bit index to test.
 *
 * Returns:
 *   true if the bit is set. else false
 */
bool
is_set_in_bitmap(uint32_t *bm, uint8_t bit)
{
    uint8_t num_bits_in_word = WORD_SIZE * BITS_PER_BYTE;
    uint8_t word = bit / num_bits_in_word;
    uint8_t bit_in_word = bit - (word * num_bits_in_word);

    return ((bm[word] & (1 << bit_in_word)) > 0);
}

/**
 * Calculate the data size of the conntrack_entry from the bits set in the
 * bitmap.
 *
 * Args:
 *   @bm pointer to the bitmap.
 *
 * Returns:
 *   the calculated payload size.
 */
static int
get_data_size_from_bitmap(uint32_t *bm)
{
    int i;
    uint32_t data_size = 0;

    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++)
    {
        if (is_set_in_bitmap(bm, i)) {
            data_size += ct_entry_attr_to_size[i];
        }
    }

    return data_size;
}

/**
 * Sets the bits in the bitmap for all the attributes that are set in the
 * nf_conntrack.
 *
 * Args:
 *   @ct pointer to the nf_conntrack entry
 *   @bm pointer to the bitmap.
 */
static void
create_bitmap_from_nf_conntrack(struct nf_conntrack *ct, uint32_t *bm)
{
    int i;

    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        enum nf_conntrack_attr nf_ct_attr;
        nf_ct_attr = ct_entry_attr_to_nf_attr[i];

        if (nfct_attr_is_set(ct, nf_ct_attr) <= 0) {
            continue;
        }
        set_bit_in_bitmap(bm, i);
    }
}

/**
 * Generates a array of 16 bytes from the struct nfct_bitmask.
 *
 * Args:
 *   @ct_label pointer to nfct_bitmask struct.
 *
 * Returns:
 *   Pointer to the allocated array for label if sucessful, NULL otherwise.
 */
static uint32_t *
label_from_nf_bitmask(const struct nfct_bitmask *ct_label)
{
    uint32_t *label;
    int i;
    int num_bits = CT_LABEL_NUM_WORDS * WORD_SIZE * BITS_PER_BYTE;

    label = g_malloc0(sizeof(uint32_t) * CT_LABEL_NUM_WORDS);

    for (i = 0; i < num_bits; i++) {
        if (nfct_bitmask_test_bit(ct_label, i) != 0) {
            set_bit_in_bitmap(label, i);
        }
    }

    return label;
}

/**
 * Creates a new conntrack_entry from the nf_conntrack struct.
 * This function creates a new conntrack_entry by filtering attributes from
 * the nf conntrack.
 *
 * Args:
 *   @ct pointer to the nf_conntrack object.
 *
 * Returns:
 *   pointer to the conntrack entry if success, NULL otherwise.
 */
struct conntrack_entry *
conntrack_entry_from_nf_conntrack(struct nf_conntrack *ct)
{
    struct conntrack_entry *ct_entry;
    int data_size;
    int i;
    void *offset;
    enum nf_conntrack_attr nf_ct_attr;

    // Allocate a new conntrack entry.
    ct_entry = conntrack_entry_new();

    // Generate bitmap from nfct conntrack struct.
    create_bitmap_from_nf_conntrack(ct, ct_entry->bitmap);

    // Use the bitmap to calculate data size.
    data_size = get_data_size_from_bitmap(ct_entry->bitmap);
    ct_entry->data_size = data_size;
    ct_entry->data = g_malloc0(data_size);

    LOG(VERBOSE, "%s: bitmap[0] = %u, bitmap[1] = %u", __func__,
        ct_entry->bitmap[0], ct_entry->bitmap[1]);
    LOG(VERBOSE, "%s: data_size = %d", __func__, data_size);

    // For each of the attributes set, write the attribute value to the payload.
    offset = ct_entry->data;
    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        if (is_set_in_bitmap(ct_entry->bitmap, i)) {
            bool free_attr_value = false;
            const void *attr_value;
            nf_ct_attr = ct_entry_attr_to_nf_attr[i];

            if (i == CT_ATTR_LABEL) {
                const void *nf_ct_attr_value;
                nf_ct_attr_value = nfct_get_attr(ct, nf_ct_attr);
                attr_value = label_from_nf_bitmask(nf_ct_attr_value);
                free_attr_value = true;
            } else {
                attr_value = nfct_get_attr(ct, nf_ct_attr);
            }

            if (attr_value == NULL) {
                LOG(ERROR, "%s: CT attr is NULL %d\n", __func__, i);
                goto err;
            }
            memcpy(offset, attr_value, ct_entry_attr_to_size[i]);
            offset = offset + ct_entry_attr_to_size[i];
            if (free_attr_value) {
                free((void *)attr_value);
            }
        }
    }
    log_conntrack_entry(VERBOSE, ct_entry);
    return ct_entry;

err:
    conntrack_entry_destroy(ct_entry);
    return NULL;
}

/**
 * Apply OR operation between the two bitmaps
 *
 * This function set the bits in res_bm for all the attributes that
 *   are set in either bm or netlink conntrack.
 *
 * Args:
 *   @res_bm pointer to the bitmap in which result of the operation is
 *     stored.
 *   @bm pointer to the first bitmap.
 *   @ct pointer to the netlink conntrack entry.
 */
static void
apply_or_operation(uint32_t *res_bm, uint32_t *bm, struct nf_conntrack *ct)
{
    enum nf_conntrack_attr nf_ct_attr;
    int i;

    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        // If some value is set in the original bitmap. Retain the value.
        if (is_set_in_bitmap(bm, i)) {
            set_bit_in_bitmap(res_bm, i);
        } else {
            nf_ct_attr = ct_entry_attr_to_nf_attr[i];
            if (nfct_attr_is_set(ct, nf_ct_attr) <= 0) {
                continue;
            }
            set_bit_in_bitmap(res_bm, i);
        }
    }
}

/**
 * Create a new conntrack entry by applying the update from nfct events.
 *
 * This function creates a new conntrack entry using the following steps:
 *   1. Set the bits in the bitmap for the attributes that are set either in
 *       original conntrack entry or set in the update event.
 *   2. For every attribute:
 *       2.1 If attribute is not set in any of the ct_entry/ct, ignore.
 *       2.2 If attribute is set in both ct_entry and ct, use the value from
 *           the update received.
 *       2.3 If the attribute is set in ct_entry but not in ct, retain the value
 *           from the ct_entry. [NOTE: this is done due to the fact that kernel
 *           includes only the updated attributes in the nf events].
 *       2.4 If the attribute is set in ct but not in ct_entry, add this value
 *           to the new CT.
 *
 * Args:
 *   @ct_entry pointer to the original conntrack entry.
 *   @ct pointer to the ct from the nfct events.
 *
 * Returns:
 *   pointer to the newly created conntrack entry if successful in applying
 *   the update. NULL otherwise
 */
struct conntrack_entry *
get_conntrack_entry_from_update(struct conntrack_entry *ct_entry,
                                struct nf_conntrack *ct)
{
    struct conntrack_entry *res_ct_entry;
    int data_size;
    int i;
    void *res_offset, *offset;

    res_ct_entry = conntrack_entry_new();

    // Generate bitmap from nfct conntrack struct.
    apply_or_operation(res_ct_entry->bitmap, ct_entry->bitmap, ct);

    // Use the bitmap to calculate data size.
    data_size = get_data_size_from_bitmap(res_ct_entry->bitmap);
    res_ct_entry->data_size = data_size;
    res_ct_entry->data = g_malloc0(data_size);

    LOG(VERBOSE, "%s: previous :: bitmap[0] = %u, bitmap[1] = %u; "
        "new :: bitmap[0] = %u, bitmap[1] = %u", __func__,
        ct_entry->bitmap[0], ct_entry->bitmap[1],
        res_ct_entry->bitmap[0], res_ct_entry->bitmap[1]);
    LOG(VERBOSE, "%s: previous :: data_size=%d; new :: data_size=%d", __func__,
        ct_entry->data_size, res_ct_entry->data_size);

    // For each of the attribute set, write the attribute value to the payload.
    res_offset = res_ct_entry->data;
    offset = ct_entry->data;

    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        const void *attr_value = NULL;
        bool free_attr_value;
        enum nf_conntrack_attr nf_ct_attr;

        nf_ct_attr = ct_entry_attr_to_nf_attr[i];
        free_attr_value = false;

        // Case 1: atribute not set in both entries.
        if (!is_set_in_bitmap(res_ct_entry->bitmap, i)) {
            // Ignore this field.
            continue;
        }

        // Case 2: attribute set in both ct_entry as well as update.
        // Case 3: attribute not set in ct_entry but set in update
        // Action: Take the value from the update.
        if (nfct_attr_is_set(ct, nf_ct_attr) > 0) {
            // Handle ct label separatley since it's a complex type.
            if (i == CT_ATTR_LABEL) {
                const void *nf_ct_attr_value;
                nf_ct_attr_value = nfct_get_attr(ct, nf_ct_attr);
                attr_value = label_from_nf_bitmask(nf_ct_attr_value);
                free_attr_value = true;
            } else {
                attr_value = nfct_get_attr(ct, nf_ct_attr);
            }

            // If attribute value is set in ct_entry, update the offset
            if (is_set_in_bitmap(ct_entry->bitmap, i)) {
                offset = offset + ct_entry_attr_to_size[i];
            }
        }
        // Case 4: attribute set in conntrack_entry but not in update
        else if ((is_set_in_bitmap(ct_entry->bitmap, i) &&
                 nfct_attr_is_set(ct, nf_ct_attr) <= 0)) {
            // Take value from original entry
            attr_value = offset;
            offset = offset + ct_entry_attr_to_size[i];
        }

        if (attr_value == NULL) {
            LOG(ERROR, "%s: CT attr is NULL %d", __func__, i);
            goto err;
        }
        memcpy(res_offset, attr_value, ct_entry_attr_to_size[i]);
        res_offset = res_offset + ct_entry_attr_to_size[i];

        if (free_attr_value) {
            free((void *)attr_value);
        }
    }
    log_conntrack_entry(VERBOSE, res_ct_entry);
    return res_ct_entry;

err:
    conntrack_entry_destroy(res_ct_entry);
    return NULL;
}

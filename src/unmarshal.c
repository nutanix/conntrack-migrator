/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the functions that parse the data read
 * from dbus.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "conntrack_entry.h"
#include "data_template.h"
#include "unmarshal.h"

/**
 * From the start pointer, reads a uint32_t value.
 *
 * Args:
 *   @start pointer to the buffer offset from where the data needs to be
 *          read.
 *   @payload_size the read value is saved in the address pointed by
 *                 payload_size.
 *
 * Returns:
 *   number of bytes read.
 */
uint32_t
unmarshal_payload_size(void *start, uint32_t *payload_size)
{
    uint32_t bytes_read = 0;
    uint32_t *_size;

    _size = start;
    *payload_size = *_size;
    bytes_read += UINT32_T_SIZE;

    LOG(VERBOSE, "%s: Received the following payload size: %d", __func__,
        *payload_size);
    return bytes_read;
}

/**
 * From the start pointer, reads the data_template
 *
 * The marshalled form of data template is as follows:
 *  - [ num_bits | size_attr_1 | size_attr_2 ...(num_bits times) ]. All the
 *  elements are type of uint8_t.
 *
 * This function reads the above values, from the start address given and
 * stores them to data_tmpl. payload_size field of data_template is calculated
 * using num_bits.
 *
 * Args:
 *   @start pointer to the buffer offset from where the data needs to be
 *          read.
 *   @data_tmpl the read value is saved in the address pointed by
 *               data_tmpl.
 *
 * Returns:
 *   number of bytes read.
 */
uint32_t
unmarshal_data_template(void *start, struct data_template *data_tmpl)
{
    uint32_t bytes_read = 0;
    uint8_t *tmp_u8;

    tmp_u8 = start;
    data_tmpl->num_bits = *tmp_u8;
    start += UINT8_T_SIZE;
    bytes_read += UINT8_T_SIZE;

    data_tmpl->payload_size = data_tmpl->num_bits * UINT8_T_SIZE;
    data_tmpl->payload = start;
    start += data_tmpl->payload_size;
    bytes_read += data_tmpl->payload_size;

    LOG(VERBOSE, "%s: Received the following num_bits: %d", __func__,
        data_tmpl->num_bits);
    return bytes_read;
}

/**
 * From the start pointer, converts the serialised form of conntrack_entry
 * to nf_conntrack struct.
 *
 * The marshalled format of the conntrack entry is as follows:
 *  - [bitmap | attr_value_1 | attr_value_2 | ...(n-times) ] where n is the
 * number of bits set in the bitmap.
 * This function first reads a 64 bit bitmap and then based on the attributes
 * set on the bitmap and using the size information from the data_template
 * it sets the relavant attribute in the ct. If label attribute is set, it is
 * read in the pointer to the label array.
 *
 * Args:
 *   @start pointer to the buffer offset from where the data needs to be
 *          read.
 *   @data_tmpl data_template to be used for unmarshalling.
 *   @ct the read value is saved in the address pointed by ct.
 *   @label If the label is set in the conntrack_entry, then it is returned
 *      via the label param.
 *      (for reason why this is not stored in ct see write_conntrack_entry.)
 *
 * Returns:
 *   number of bytes read.
 */
uint32_t
unmarshal_conntrack_entry(void *start, struct data_template *data_tmpl,
                          struct nf_conntrack *ct, uint32_t *label[])
{
    uint32_t bytes_read = 0;
    uint32_t *bm;
    int i;
    uint32_t word;
    int bit_num = 0;

    bm = start;
    start += WORD_SIZE * BITMAP_NUM_WORDS;
    bytes_read += WORD_SIZE * BITMAP_NUM_WORDS;

    for (i = 0; i < BITMAP_NUM_WORDS; i++) {
        word = bm[i];
        while (word > 0) {
            // If bit is set in the bitmap
            if (word & 1) {
                // If this is a known field. then read it.
                if (bit_num < CT_ATTR_MAX) {
                    if (bit_num == CT_ATTR_LABEL) {
                        *label = start;
                    } else {
                        nfct_set_attr(ct, ct_entry_attr_to_nf_attr[bit_num],
                                      start);
                    }
                } else {
                    LOG(WARNING, "%s: bit is un-supported %d", __func__,
                        bit_num);
                }
                start += data_tmpl->payload[bit_num];
                bytes_read += data_tmpl->payload[bit_num];
            }
            bit_num += 1;
            word = word >> 1;
        }
    }
    return bytes_read;
}

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
 * implemented in data_template.c
 */

#ifndef DATA_TEMPLATE_H
#define DATA_TEMPLATE_H

#include "common.h"  /* for enum save_mode_op_type */

/**
 * This struct instructs the receiving end how to parse the conntrack
 * entries received. num_bits field instructs how many attributes are
 * supported in this version of message. Then for each attribute, we
 * send its size.
 */
struct data_template {
    uint8_t num_bits;      // max number of atrributes in the conntrack_entry
    uint8_t *payload;      // array representing the size of each attribute
    uint32_t payload_size; // size of payload array
};

/**
 * Allocate a data_template for @op_type.
 * - SAVE_IPS_OP uses CT_ATTR_LEGACY_NUM_BITS (21), matching a v1.0 SAVE payload.
 * - SAVE_PORT_ZONE_OP uses CT_ATTR_MAX, including the NAT reply slots.
 * - Caller frees the result with data_template_destroy().
 *
 * @op_type SAVE sub-mode.
 */
struct data_template *
data_template_new(enum save_mode_op_type);

void
data_template_destroy(struct data_template *);

#endif /* DATA_TEMPLATE_H */

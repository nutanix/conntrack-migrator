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

struct data_template *
data_template_new(void);

void
data_template_destroy(struct data_template *);

#endif /* DATA_TEMPLATE_H */

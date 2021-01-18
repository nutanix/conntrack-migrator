/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the declarations of functions implemented in unmarshal.c
 */

#ifndef UNMARSHAL_H
#define UNMARSHAL_H

#include <stdint.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "conntrack_entry.h"
#include "data_template.h"

uint32_t
unmarshal_payload_size(void *, uint32_t *);

uint32_t
unmarshal_data_template(void *, struct data_template *);

uint32_t
unmarshal_conntrack_entry(void *, struct data_template *,
                          struct nf_conntrack *, uint32_t **);

#endif /* UNMARSHAL_H */

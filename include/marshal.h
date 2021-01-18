/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the declarations of functions implemented in marshal.c
 */

#ifndef MARSHAL_H
#define MARSHAL_H

#include "data_template.h"

void *
marshal(struct conntrack_store *, struct data_template *, uint32_t *);

#endif /* MARSHAL_H */

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
 *   with the data_template struct.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "conntrack_entry.h"
#include "data_template.h"

/**
 * Allocates a new data_template sized to @kind.
 *
 * See the header for the per-kind wire-format contract.
 *
 * Returns:
 *   pointer to the allocated memory if success.
 *   In case of error, terminates the process.
 */
struct data_template *
data_template_new(enum save_input_kind kind)
{
    struct data_template *data_tmpl;
    int i;
    uint8_t num_bits;

    /* Wire-compat: IP mode advertises only the v1.0 schema so the
     * payload is byte-identical to what a v1.0 SAVE binary produces.
     * Zone mode advertises every slot the current binary understands.
     * The trailing slots are gated off in IP mode by is_zone_only_slot()
     * (conntrack_entry.c) so they are never set in any bitmap either. */
    num_bits = (kind == SAVE_INPUT_IPS) ? CT_ATTR_LEGACY_NUM_BITS
                                        : CT_ATTR_MAX;

    data_tmpl = g_malloc0(sizeof(struct data_template));
    data_tmpl->num_bits = num_bits;
    data_tmpl->payload_size = num_bits * UINT8_T_SIZE;
    data_tmpl->payload = g_malloc0(sizeof(uint8_t) * num_bits);

    for (i = CT_ATTR_MIN; i < num_bits; i++) {
        data_tmpl->payload[i] = ct_entry_attr_to_size[i];
    }

    return data_tmpl;
}

/**
 * Releases the data_template struct.
 *
 * Args:
 *   @data_tmpl pointer to the data_template to be destroyed.
 */
void
data_template_destroy(struct data_template *data_tmpl)
{
    if (data_tmpl == NULL) {
        return;
    }
    if (data_tmpl->payload != NULL) {
        g_free(data_tmpl->payload);
    }
    g_free(data_tmpl);
}

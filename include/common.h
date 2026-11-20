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
 * implemented in common.c
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include <glib.h>

/**
 * Per-argument minimum values for ensure_cli_arg_is_int_at_least.
 *
 * Each constant names the CLI argument whose lower bound it enforces,
 * so the call site reads as a domain-level statement instead of a
 * magic number:
 *
 *   ensure_cli_arg_is_int_at_least(argv[MODE_ARG_INDEX], &mode, "mode",
 *                                  MIN_ACCEPTABLE_VALUE_FOR_MODE);
 *
 * Rationale for the values:
 *   - mode:        valid op-mode IDs start at 1 (the upper bound is
 *                  separately enforced by check_mode()).
 *   - num_entries: a zones/targets list of zero entries is not
 *                  meaningful, so callers require at least one.
 *   - num_ips:     zero is legitimate — it means "VM has no IPv4
 *                  NICs" (start_in_save_mode early-exits in that case).
 */
#define MIN_ACCEPTABLE_VALUE_FOR_MODE         1
#define MIN_ACCEPTABLE_VALUE_FOR_NUM_ENTRIES  1
#define MIN_ACCEPTABLE_VALUE_FOR_NUM_IPS      0

/**
 * Sub-mode tag: tells the rest of the daemon which SAVE-mode CLI layout
 * was detected from argv. Selects between IP-mode (filter CT entries by
 * IPv4 src/dst) and zone-mode (filter by CT zone).
 */
enum save_mode_op_type {
    SAVE_IPS_OP,
    SAVE_PORT_ZONE_OP
};

/**
 * Sub-mode tag: tells the rest of the daemon which LOAD-mode CLI layout
 * was detected from argv. Selects between IP-mode (legacy v1.0
 * pass-through, no zone awareness) and zone-mode (apply src->dst zone
 * rewrite before programming each CT entry).
 */
enum load_mode_op_type {
    LOAD_IPS_OP,
    LOAD_PORT_ZONE_OP
};

/**
 * Runtime configuration for capturing source flows.
 *
 * A migration tracks flows by IP addresses or by zones, never both,
 * so the two hashtables share a union.
 *
 * @op_type selects the active table:
 *   SAVE_IPS_OP:       ips_to_migrate
 *   SAVE_PORT_ZONE_OP: zones_to_migrate
 *
 * destroy_save_mode_config() uses @op_type to free the active table.
 */
struct save_mode_config {
    enum save_mode_op_type op_type;
    union {
        GHashTable *ips_to_migrate;     /* op_type == SAVE_IPS_OP       */
        GHashTable *zones_to_migrate;   /* op_type == SAVE_PORT_ZONE_OP */
    };
};

/**
 * LOAD-mode runtime config bundle. Tagged union over CLI sub-mode:
 *   op_type == LOAD_IPS_OP        -> src_dst_zone_map is NULL; pass-through.
 *   op_type == LOAD_PORT_ZONE_OP  -> src_dst_zone_map is uint16->uint16
 *                                    map, keyed by old_ct_zone (source
 *                                    side), value is the new_ct_zone
 *                                    (destination side) to write before
 *                                    programming each CT entry.
 * Owned by load_mode_config and freed by destroy_load_mode_config.
 */
struct load_mode_config {
    enum load_mode_op_type op_type;
    GHashTable *src_dst_zone_map;
};

/**
 * Log name for a SAVE sub-mode.
 *
 * @op_type SAVE sub-mode tag.
 */
const char *
convert_save_mode_op_type_to_string(enum save_mode_op_type);

/**
 * Builds a hashtable of IPv4 addresses from decimal strings.
 *
 * IPv6 strings are skipped. Returns NULL if any string is not an IP address.
 * The caller owns the table.
 *
 * @ip_list  address strings.
 * @num_ips  number of elements in @ip_list.
 */
GHashTable *
create_hashtable_from_ip_list(const char *const [], int);

/**
 * Checks a port-prefixed UUID of the form port_<8-4-4-4-12>.
 *
 * @s candidate string. NULL returns false.
 */
bool
is_valid_uuid_string(const char *);

/**
 * Parses a decimal CT zone in the range 0..65535.
 *
 * Rejects whitespace, a leading sign, and trailing junk.
 * @out is written only on success.
 *
 * @s    decimal string.
 * @out  parsed zone.
 */
bool
parse_ct_zone(const char *, uint16_t *);

/**
 * Parse a CLI argument as an int >= @min_value.
 * - An empty string or trailing junk calls errx().
 * - Call only from check_args(), before fork.
 *
 * @arg_value  raw argv string.
 * @out_value  parsed int. Untouched on failure.
 * @arg_name   name used in the error.
 * @min_value  lowest accepted value, inclusive.
 */
void
ensure_cli_arg_is_int_at_least(const char *, int *, const char *, int);

/**
 * Builds a hashtable of CT zones from decimal strings.
 *
 * Returns NULL if any string is not a uint16 zone. The caller owns the table.
 *
 * @zones      decimal zone strings.
 * @n_entries  number of elements in @zones.
 */
GHashTable *
create_hashtable_from_zone_list(const char *const [], int);

/**
 * Parses the flat D-Bus Clear payload into a zone hashtable.
 *
 * The payload is a flat list of pairs:
 *   [port_uuid_1, zone_1, port_uuid_2, zone_2, ...]
 *
 * OVN has a 1:1 port-to-zone mapping, so only the zone is kept.
 * The port UUID is checked and then discarded.
 *
 * @port_zone_strv  alternating port UUID and decimal zone.
 * @num_entries     length of @port_zone_strv. Must be even.
 *                  An odd length returns NULL.
 */
GHashTable *
create_hashtable_from_port_zone_pairs(const char *[], int);

/**
 * Wraps an IP hashtable in a SAVE-mode config. Takes ownership of the table.
 *
 * @ips_to_migrate non-NULL IP hashtable.
 */
struct save_mode_config *
create_save_mode_config_for_ip_mode(GHashTable *);

/**
 * Wraps a zone hashtable in a SAVE-mode config. Takes ownership of the table.
 *
 * @zones non-NULL zone hashtable.
 */
struct save_mode_config *
create_save_mode_config_for_port_zone_mode(GHashTable *);

/**
 * Frees a SAVE-mode config and the hashtable it owns.
 *
 * @save_config bundle to free. NULL is ignored.
 */
void
destroy_save_mode_config(struct save_mode_config *);

/**
 * Allocates a LOAD config for legacy IP mode. No zone rewrite.
 */
struct load_mode_config *
create_load_mode_config_for_legacy_mode(void);

/**
 * Wraps an old-zone to new-zone map in a LOAD config. Takes ownership.
 *
 * @src_dst_zone_map non-NULL map built by check_zone_load_args().
 */
struct load_mode_config *
create_load_mode_config_for_port_zone_mode(GHashTable *);

/**
 * Frees a LOAD config and its zone map.
 *
 * @load_config bundle to free. NULL is ignored.
 */
void
destroy_load_mode_config(struct load_mode_config *);

#endif /* COMMON_H */

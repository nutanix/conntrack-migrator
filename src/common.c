/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the common util functions.
 */

#include <arpa/inet.h> // For struct in_addr.
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <uuid/uuid.h>

#include "common.h"
#include "log.h"

/* Required literal prefix for the port-UUID wire form.
 * Full accepted shape is: "port_" + <canonical 8-4-4-4-12 UUID>, total 41
 * characters. The prefix is part of the value supplied by libvirt and is
 * preserved verbatim in any storage (hashtable keys, log lines, etc.). */
#define PORT_UUID_PREFIX     "port_"
#define PORT_UUID_PREFIX_LEN (sizeof(PORT_UUID_PREFIX) - 1)

/**
 * Returns a human-readable name for a SAVE sub-mode.
 *
 * See declaration in common.h for full doc.
 */
const char *
save_input_kind_to_string(enum save_input_kind kind)
{
    switch (kind) {
    case SAVE_INPUT_IPS:        return "IPS";
    case SAVE_INPUT_PORT_ZONES: return "PORT_ZONES";
    }
    return "UNKNOWN";
}

/**
 * Creates hashtable from IP addresses list.
 *
 * This function allocates a hashtable which converts the string
 * based ipv4 address into uint32_t format and store them into hashtable
 * for fast lookup operations. They key for the hashtable is the uint32_t
 * ip address. and value is ignored (kept as 1). Since GLib does not have
 * any HashSet, hashtable is used and the values corresponding to the key
 * are ignored.
 *
 * NOTE: As of now we do not have support for ipv6 addresses thus all ipv6
 * addresses will be ignored.
 *
 * Args:
 *   @ip_list list of string IP addresses
 *   @num_ips number of IP addresses in the list
 *
 * Returns:
 *   Resulting hashtable containing IP addresses as key
 *   In case memory allocation fails, the process is terminated.
 *   NULL, in case an invalid IP address is present in the ip_list.
 */
GHashTable *
create_hashtable_from_ip_list(const char *const ip_list[], int num_ips)
{
    int i;
    GHashTable *ht;

    if (num_ips < 0) {
        LOG(ERROR, "%s: negative num_ips (%d)", __func__, num_ips);
        return NULL;
    }
    if (num_ips > 0 && ip_list == NULL) {
        LOG(ERROR, "%s: num_ips=%d but ip_list is NULL",
            __func__, num_ips);
        return NULL;
    }

    ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    for (i = 0; i < num_ips; i++) {
        struct in_addr ip = {0};
        int success;

        success = inet_aton(ip_list[i], &ip);
        if (success == 0) {
            unsigned char buf[sizeof(struct in6_addr)];

            if (inet_pton(AF_INET6, ip_list[i], buf) == 1) {
                LOG(WARNING, "%s: No CT migration support for ipv6 address: "
                    "%s.", __func__, ip_list[i]);
            } else {
                LOG(ERROR, "%s: Invalid IP address %s", __func__, ip_list[i]);
                g_hash_table_destroy(ht);
                return NULL;
            }
        } else {
            g_hash_table_insert(ht, GUINT_TO_POINTER(ip.s_addr),
                                GINT_TO_POINTER(1));
        }
    }

    return ht;
}

/**
 * Validates that @s is a port-prefixed UUID string of the form
 * "port_<canonical 8-4-4-4-12 hex UUID>" (total length 41).
 *
 * The "port_" prefix is the wire form supplied by libvirt and is part
 * of the value; this validator rejects bare UUIDs without the prefix.
 * The UUID body itself is parsed by libuuid's uuid_parse(), which
 * enforces canonical 8-4-4-4-12 hex form (case-insensitive) - the
 * de-facto standard parser on the platform.
 *
 * Args:
 *   @s nul-terminated candidate string. May be NULL.
 *
 * Returns:
 *   true if the string is well-formed, false otherwise.
 */
bool
is_valid_uuid_string(const char *s)
{
    uuid_t parsed;

    if (s == NULL) {
        return false;
    }
    if (strncmp(s, PORT_UUID_PREFIX, PORT_UUID_PREFIX_LEN) != 0) {
        return false;
    }
    return uuid_parse(s + PORT_UUID_PREFIX_LEN, parsed) == 0;
}

/**
 * Strict parser for a CT zone: must be a complete decimal uint16 with no
 * trailing junk, no whitespace, no overflow.
 *
 * Uses the standard out-parameter pattern: @out is only written on success.
 * On failure the caller's storage is left untouched.
 *
 * Args:
 *   @s   nul-terminated decimal string.
 *   @out output uint16_t (only written on success). Must be non-NULL.
 *
 * Returns:
 *   true on success, false otherwise.
 */
bool
parse_ct_zone(const char *s, uint16_t *out)
{
    char *end = NULL;
    unsigned long v;

    if (s == NULL || *s == '\0' || out == NULL) {
        return false;
    }

    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > UINT16_MAX) {
        return false;
    }

    *out = (uint16_t) v;
    return true;
}

/**
 * Ensures a CLI argument is an integer >= @min_value.
 *
 * See declaration in common.h for the full contract.
 */
void
ensure_cli_arg_is_int_at_least(const char *arg_value, int *out_value,
                               const char *arg_name, int min_value)
{
    char *end;
    long v;

    if (arg_value == NULL || *arg_value == '\0') {
        errx(EXIT_FAILURE, "Missing value for '%s'", arg_name);
    }

    /* Base 10: lock the grammar to decimal so "010" is ten, not octal
     * eight (which strtol would do with base 0). Value range is
     * checked separately below; the base only affects how digits are
     * read, not how big the result can be. */
    errno = 0;
    v = strtol(arg_value, &end, 10);

    if (errno != 0 || end == arg_value || *end != '\0') {
        errx(EXIT_FAILURE,
             "Invalid value for '%s': '%s' (must be a valid integer)",
             arg_name, arg_value);
    }
    if (v < (long) min_value || v > INT_MAX) {
        errx(EXIT_FAILURE,
             "Invalid value for '%s': '%s' (must be in range [%d, %d])",
             arg_name, arg_value, min_value, INT_MAX);
    }

    *out_value = (int) v;
}

/**
 * Builds the zones_to_migrate hashtable from a parsed-CLI zone array.
 *
 * Inputs are already arity- and content-validated by check_zone_save_args
 * (in main.c) before this is called, so a parse failure here is treated
 * as a defensive bug-in-caller and the partial table is torn down.
 *
 * Ownership: the returned table is caller-owned. Keys are inlined zone
 * values (no destroyers attached); value slots are unused (kept as 1)
 * to mirror create_hashtable_from_ip_list.
 *
 * Args:
 *   @zones     array of nul-terminated decimal zone strings (length n)
 *   @n_entries number of zone strings to consume
 *
 * Returns:
 *   zones_to_migrate hashtable on success, NULL on failure.
 */
GHashTable *
create_hashtable_from_zone_list(const char *const zones[], int n_entries)
{
    int i;
    GHashTable *zones_ht;

    if (n_entries < 0) {
        LOG(ERROR, "%s: negative n_entries (%d)", __func__, n_entries);
        return NULL;
    }
    if (n_entries > 0 && zones == NULL) {
        LOG(ERROR, "%s: n_entries=%d but zones is NULL",
            __func__, n_entries);
        return NULL;
    }

    zones_ht = g_hash_table_new(g_direct_hash, g_direct_equal);

    for (i = 0; i < n_entries; i++) {
        uint16_t zone;

        if (!parse_ct_zone(zones[i], &zone)) {
            LOG(ERROR, "%s: Invalid zone at index %d: '%s'", __func__,
                i, zones[i]);
            g_hash_table_destroy(zones_ht);
            return NULL;
        }

        g_hash_table_insert(zones_ht,
                            GUINT_TO_POINTER((guint) zone),
                            GINT_TO_POINTER(1));
    }

    return zones_ht;
}

/**
 * Builds a uint16-keyed hashtable from a strv of paired
 * [port_uuid_0, zone_0, port_uuid_1, zone_1, ...] elements.
 *
 * See declaration in common.h for the full contract. Caller owns the
 * returned table. Keys are inlined pointer values (no destroyers
 * attached); value slots are unused (kept as 1) to mirror
 * create_hashtable_from_ip_list.
 *
 * The port_uuid half of each pair is parsed for well-formedness so a
 * garbled payload is rejected up front, but is otherwise discarded:
 * the zone-mode delete path only filters on CT zone.
 *
 * Args:
 *   @port_zone_strv flat strv of alternating port_uuid / decimal-zone
 *                   strings: [port_uuid_0, zone_0, port_uuid_1, zone_1,
 *                   ...]. Length must be 2 * num_pairs and elements at
 *                   indexes < num_entries must be non-NULL.
 *   @num_entries    total number of strv elements (must be even). The
 *                   pair count is num_entries / 2.
 *
 * Returns:
 *   newly-allocated GHashTable on success; NULL on parse error (any
 *   partially-built table is torn down before return).
 */
GHashTable *
create_hashtable_from_port_zone_pairs(const char *port_zone_strv[],
                                      int num_entries)
{
    GHashTable *zones_on_host;
    int num_pairs;
    int pair_idx;

    if (num_entries < 0) {
        LOG(ERROR, "%s: negative num_entries (%d)", __func__, num_entries);
        return NULL;
    }
    if (num_entries > 0 && port_zone_strv == NULL) {
        LOG(ERROR, "%s: num_entries=%d but port_zone_strv is NULL",
            __func__, num_entries);
        return NULL;
    }

    if (num_entries % 2 != 0) {
        LOG(ERROR, "%s: expected even-length strv (port_uuid, zone) pairs, "
            "got %d entries", __func__, num_entries);
        return NULL;
    }
    num_pairs = num_entries / 2;

    zones_on_host = g_hash_table_new(g_direct_hash, g_direct_equal);

    for (pair_idx = 0; pair_idx < num_pairs; pair_idx++) {
        const int port_uuid_slot = pair_idx * 2;
        const int zone_slot      = port_uuid_slot + 1;
        const char *port_uuid    = port_zone_strv[port_uuid_slot];
        const char *zone_str     = port_zone_strv[zone_slot];
        uint16_t zone;

        if (port_uuid == NULL || zone_str == NULL) {
            LOG(ERROR, "%s: NULL element at pair index %d",
                __func__, pair_idx);
            g_hash_table_destroy(zones_on_host);
            return NULL;
        }
        if (!is_valid_uuid_string(port_uuid)) {
            LOG(ERROR, "%s: malformed port UUID at pair index %d: '%s'",
                __func__, pair_idx, port_uuid);
            g_hash_table_destroy(zones_on_host);
            return NULL;
        }
        if (!parse_ct_zone(zone_str, &zone)) {
            LOG(ERROR, "%s: invalid zone for port %s at pair index %d: '%s'",
                __func__, port_uuid, pair_idx, zone_str);
            g_hash_table_destroy(zones_on_host);
            return NULL;
        }

        g_hash_table_insert(zones_on_host,
                            GUINT_TO_POINTER((guint) zone),
                            GINT_TO_POINTER(1));
    }

    LOG(INFO, "%s: Built zones_on_host hashtable: %d unique zones (from "
        "%d port/zone pairs)",
        __func__, g_hash_table_size(zones_on_host), num_pairs);
    return zones_on_host;
}

/**
 * Allocates a save_targets bundle wrapping an ips_to_migrate hashtable.
 *
 * Takes ownership of @ips_to_migrate; subsequent save_targets_destroy()
 * will destroy it.
 *
 * Args:
 *   @ips_to_migrate hashtable of IP addresses to migrate. Must be non-NULL.
 *
 * Returns:
 *   pointer to the bundle. Process aborts on allocation failure.
 */
struct save_targets *
save_targets_new_from_ips(GHashTable *ips_to_migrate)
{
    struct save_targets *targets;

    if (ips_to_migrate == NULL) {
        errx(EXIT_FAILURE,
             "%s: refusing to allocate IP-mode save_targets with NULL "
             "ips_to_migrate (programmer error in caller)", __func__);
    }

    targets = g_malloc0(sizeof(*targets));
    targets->kind = SAVE_INPUT_IPS;
    targets->ips_to_migrate = ips_to_migrate;
    return targets;
}

/**
 * Allocates a save_targets bundle wrapping a zones_to_migrate hashtable.
 *
 * Takes ownership of @zones; subsequent save_targets_destroy() will
 * destroy it.
 *
 * Args:
 *   @zones zones_to_migrate hashtable. Must be non-NULL.
 *
 * Returns:
 *   pointer to the bundle. Process aborts on allocation failure.
 */
struct save_targets *
save_targets_new_from_zones(GHashTable *zones)
{
    struct save_targets *targets;

    if (zones == NULL) {
        errx(EXIT_FAILURE,
             "%s: refusing to allocate zone-mode save_targets with NULL "
             "zones (programmer error in caller)", __func__);
    }

    targets = g_malloc0(sizeof(*targets));
    targets->kind = SAVE_INPUT_PORT_ZONES;
    targets->zones_to_migrate = zones;
    return targets;
}

/**
 * Releases a save_targets bundle and the hashtables it owns.
 *
 * NULL-tolerant.
 *
 * Args:
 *   @targets pointer to the bundle. May be NULL.
 */
void
save_targets_destroy(struct save_targets *targets)
{
    if (targets == NULL) {
        return;
    }

    /* The two pointers overlay the same memory now, so checking both
     * blindly would double-free the active arm. Dispatch on @kind. */
    switch (targets->kind) {
    case SAVE_INPUT_IPS:
        if (targets->ips_to_migrate != NULL) {
            g_hash_table_destroy(targets->ips_to_migrate);
            targets->ips_to_migrate = NULL;
        }
        break;
    case SAVE_INPUT_PORT_ZONES:
        if (targets->zones_to_migrate != NULL) {
            g_hash_table_destroy(targets->zones_to_migrate);
            targets->zones_to_migrate = NULL;
        }
        break;
    }

    g_free(targets);
}

/**
 * Allocates a LOAD targets bundle for the legacy (IP-based) mode.
 *
 * Legacy LOAD carries no zone information on the wire and needs no
 * rewrite, so zone_remap is left NULL. apply_zone_rewrite() in
 * dbus_server.c short-circuits when kind is LOAD_INPUT_LEGACY.
 *
 * Returns:
 *   pointer to the bundle. Process aborts on allocation failure.
 */
struct load_targets *
load_targets_new_ips(void)
{
    struct load_targets *targets;

    targets = g_malloc0(sizeof(*targets));
    targets->kind       = LOAD_INPUT_LEGACY;
    return targets;
}

/**
 * Allocates a LOAD targets bundle that wraps a pre-built
 * (old_zone -> new_zone) remap hashtable.
 *
 * Mirrors save_targets_new_from_zones() on the SAVE side: argv walking
 * lives in main.c (build_zone_remap_from_args), and this function is a
 * pure wrapper that takes ownership of the remap.
 *
 * Args:
 *   @remap  hashtable built by build_zone_remap_from_args(). Must be
 *           non-NULL. Ownership transfers to the returned bundle and
 *           is released by load_targets_destroy().
 *
 * Returns:
 *   pointer to the bundle. Process aborts on a NULL @remap (caller
 *   contract violation) or on allocation failure.
 */
struct load_targets *
load_targets_new_from_remap(GHashTable *remap)
{
    struct load_targets *targets;

    if (remap == NULL) {
        errx(EXIT_FAILURE,
             "%s: refusing to allocate port-zone load_targets with NULL "
             "remap (programmer error in caller)", __func__);
    }

    targets = g_malloc0(sizeof(*targets));
    targets->kind       = LOAD_INPUT_PORT_ZONES;
    targets->zone_remap = remap;
    return targets;
}

/**
 * Releases a load_targets bundle and the hashtable it owns.
 *
 * NULL-tolerant.
 *
 * Args:
 *   @targets pointer to the bundle. May be NULL.
 */
void
load_targets_destroy(struct load_targets *targets)
{
    if (targets == NULL) {
        return;
    }
    if (targets->zone_remap != NULL) {
        g_hash_table_destroy(targets->zone_remap);
        targets->zone_remap = NULL;
    }
    g_free(targets);
}

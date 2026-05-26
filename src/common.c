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
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "log.h"

/* Canonical UUID body length: 8-4-4-4-12 = 36 chars. */
#define UUID_STRING_LEN 36

/* Required literal prefix for the port-UUID wire form.
 * Full accepted shape is: "port_" + <canonical 8-4-4-4-12 UUID>, total 41
 * characters. The prefix is part of the value supplied by libvirt and is
 * preserved verbatim in any storage (hashtable keys, log lines, etc.). */
#define PORT_UUID_PREFIX     "port_"
#define PORT_UUID_PREFIX_LEN (sizeof(PORT_UUID_PREFIX) - 1)

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
create_hashtable_from_ip_list(const char *ip_list[], int num_ips)
{
    int i;
    GHashTable *ht;

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
 * The "port_" prefix is the wire form supplied by libvirt and is part of
 * the value; this validator rejects bare UUIDs without the prefix. The
 * UUID body is checked structurally only - dashes at offsets 8/13/18/23
 * and hex (case-insensitive) everywhere else. No version/variant bit
 * checks: callers pass canonical UUIDs and we only need to reject
 * obvious junk.
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
    int i;

    if (s == NULL) {
        return false;
    }
    if (strncmp(s, PORT_UUID_PREFIX, PORT_UUID_PREFIX_LEN) != 0) {
        return false;
    }
    s += PORT_UUID_PREFIX_LEN;

    if (strlen(s) != UUID_STRING_LEN) {
        return false;
    }

    for (i = 0; i < UUID_STRING_LEN; i++) {
        char c = s[i];

        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') {
                return false;
            }
        } else {
            bool is_hex = (c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F');
            if (!is_hex) {
                return false;
            }
        }
    }
    return true;
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
 * Builds the (zones_to_migrate, ports_to_migrate) hashtable pair from
 * parallel parsed-CLI arrays.
 *
 * Inputs are already arity- and content-validated by check_zone_save_args
 * (in main.c) before this is called, so a parse failure here is treated as
 * a defensive bug-in-caller and both tables are torn down.
 *
 * Ownership: both returned tables are caller-owned. The "zones" table is
 * the function return value; the "ports" table is returned via @out_ports.
 * Keys/values are copied (g_strdup / g_memdup) so the argv slices the
 * caller passed do not need to outlive the tables.
 *
 * Args:
 *   @zones      array of nul-terminated decimal zone strings (length n)
 *   @port_uuids array of nul-terminated UUID strings (length n)
 *   @n_entries  number of (zone, port_uuid) pairs
 *   @out_ports  output: ports_to_migrate hashtable (port_uuid -> uint16 zone)
 *
 * Returns:
 *   zones_to_migrate hashtable on success, NULL on failure (in which case
 *   *out_ports is left set to NULL).
 */
GHashTable *
create_hashtable_from_zone_and_port_list(const char *zones[],
                                         const char *port_uuids[],
                                         int n_entries,
                                         GHashTable **out_ports)
{
    int i;
    GHashTable *zones_ht;
    GHashTable *ports_ht;

    if (out_ports == NULL) {
        return NULL;
    }
    *out_ports = NULL;

    zones_ht = g_hash_table_new(g_direct_hash, g_direct_equal);
    ports_ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    for (i = 0; i < n_entries; i++) {
        uint16_t zone;
        uint16_t *zone_val;

        if (!parse_ct_zone(zones[i], &zone)) {
            LOG(ERROR, "%s: Invalid zone at index %d: '%s'", __func__,
                i, zones[i]);
            g_hash_table_destroy(zones_ht);
            g_hash_table_destroy(ports_ht);
            return NULL;
        }
        if (!is_valid_uuid_string(port_uuids[i])) {
            LOG(ERROR, "%s: Invalid port UUID at index %d: '%s'", __func__,
                i, port_uuids[i]);
            g_hash_table_destroy(zones_ht);
            g_hash_table_destroy(ports_ht);
            return NULL;
        }

        g_hash_table_insert(zones_ht,
                            GUINT_TO_POINTER((guint) zone),
                            GINT_TO_POINTER(1));

        zone_val = g_malloc(sizeof(*zone_val));
        *zone_val = zone;
        g_hash_table_insert(ports_ht, g_strdup(port_uuids[i]), zone_val);
    }

    *out_ports = ports_ht;
    return zones_ht;
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

    targets = g_malloc0(sizeof(*targets));
    targets->kind = SAVE_INPUT_IPS;
    targets->ips_to_migrate = ips_to_migrate;
    return targets;
}

/**
 * Allocates a save_targets bundle wrapping a (zones, ports) pair.
 *
 * Takes ownership of both hashtables; subsequent save_targets_destroy()
 * will destroy them.
 *
 * Args:
 *   @zones zones_to_migrate hashtable. Must be non-NULL.
 *   @ports ports_to_migrate hashtable. Must be non-NULL.
 *
 * Returns:
 *   pointer to the bundle. Process aborts on allocation failure.
 */
struct save_targets *
save_targets_new_from_zones_and_ports(GHashTable *zones, GHashTable *ports)
{
    struct save_targets *targets;

    targets = g_malloc0(sizeof(*targets));
    targets->kind = SAVE_INPUT_PORT_ZONES;
    targets->zones_to_migrate = zones;
    targets->ports_to_migrate = ports;
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

    if (targets->ips_to_migrate != NULL) {
        g_hash_table_destroy(targets->ips_to_migrate);
    }
    if (targets->zones_to_migrate != NULL) {
        g_hash_table_destroy(targets->zones_to_migrate);
    }
    if (targets->ports_to_migrate != NULL) {
        g_hash_table_destroy(targets->ports_to_migrate);
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
    targets->zone_remap = NULL;
    return targets;
}

/**
 * Builds the LOAD targets bundle for the new port-zone CLI shape.
 *
 * Walks argv at the @stride-strided offsets starting from @start_idx.
 * The port_uuid column at offset 0 is intentionally ignored: at LOAD
 * time the only thing each CT entry carries is ATTR_ZONE, so the only
 * usable pivot is old_zone -> new_zone. UUID well-formedness has
 * already been validated by check_zone_load_args() in main.c.
 *
 * If two entries declare the same old_zone with different new_zones,
 * the last write wins and a WARNING is logged. The CLI validator can
 * be tightened later to reject this shape outright.
 *
 * Args:
 *   @n_entries  declared N from argv[NUM_ENTRIES_ARG_INDEX].
 *   @argv       full argv array.
 *   @start_idx  index of the first per-entry slot (typically
 *               ENTRIES_LIST_START_ARG_INDEX).
 *   @stride     LOAD_PORT_ZONE_STRIDE.
 *
 * Returns:
 *   pointer to the bundle on success, NULL on parse failure (in which
 *   case any partially-built remap is torn down).
 */
struct load_targets *
load_targets_new_from_zone_args(int n_entries, char *argv[], int start_idx, int stride)
{
    struct load_targets *targets;
    GHashTable *remap;
    int i;

    remap = g_hash_table_new(g_direct_hash, g_direct_equal);

    for (i = 0; i < n_entries; i++) {
        int base = start_idx + (i * stride);
        const char *old_str = argv[base + 1];
        const char *new_str = argv[base + 2];
        uint16_t old_zone, new_zone;

        if (!parse_ct_zone(old_str, &old_zone) ||
            !parse_ct_zone(new_str, &new_zone)) {
            LOG(ERROR, "%s: failed to parse zone at entry %d "
                "(old='%s' new='%s')",
                __func__, i, old_str, new_str);
            g_hash_table_destroy(remap);
            return NULL;
        }

        if (g_hash_table_contains(remap,
                                  GUINT_TO_POINTER((guint) old_zone))) {
            uint16_t existing = (uint16_t) GPOINTER_TO_UINT(
                g_hash_table_lookup(remap,
                    GUINT_TO_POINTER((guint) old_zone)));
            if (existing != new_zone) {
                LOG(WARNING, "%s: old_zone %u remapped twice "
                    "(was -> %u, now -> %u). Last write wins.",
                    __func__, (unsigned) old_zone,
                    (unsigned) existing, (unsigned) new_zone);
            }
        }

        g_hash_table_insert(remap,
                            GUINT_TO_POINTER((guint) old_zone),
                            GUINT_TO_POINTER((guint) new_zone));
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
    }
    g_free(targets);
}

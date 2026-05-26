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
 * Sub-mode tag: tells the rest of the daemon which SAVE-mode CLI layout
 * was detected from argv.
 */
enum save_input_kind {
    SAVE_INPUT_IPS,
    SAVE_INPUT_PORT_ZONES
};

/**
 * Sub-mode tag: tells the rest of the daemon which LOAD-mode CLI layout
 * was detected from argv.
 */
enum load_input_kind {
    LOAD_INPUT_LEGACY,
    LOAD_INPUT_PORT_ZONES
};

/**
 * Bundle of SAVE-side migration targets. Real C tagged union over @kind:
 *   kind == SAVE_INPUT_IPS         -> ips_to_migrate is the active arm.
 *   kind == SAVE_INPUT_PORT_ZONES  -> zones_to_migrate is the active arm.
 * The active hashtable is owned by save_targets and freed by
 * save_targets_destroy (which dispatches on @kind because the two
 * pointer fields now overlay the same memory). Anonymous union so call
 * sites can keep using targets->ips_to_migrate / targets->zones_to_migrate
 * directly.
 */
struct save_targets {
    enum save_input_kind kind;
    union {
        GHashTable *ips_to_migrate;     /* kind == SAVE_INPUT_IPS */
        GHashTable *zones_to_migrate;   /* kind == SAVE_INPUT_PORT_ZONES */
    };
};

/**
 * Bundle of LOAD-side migration policy. Tagged union over CLI sub-mode:
 *   kind == LOAD_INPUT_LEGACY      -> zone_remap is NULL; pass-through.
 *   kind == LOAD_INPUT_PORT_ZONES  -> zone_remap is uint16->uint16 map,
 *                                     keyed by old_ct_zone, value is the
 *                                     new_ct_zone to write before
 *                                     programming each CT entry.
 * Owned by load_targets and freed by load_targets_destroy.
 */
struct load_targets {
    enum load_input_kind kind;
    GHashTable *zone_remap;
};

/**
 * Returns a human-readable, log-friendly name for a SAVE sub-mode.
 *
 * Used so log lines that fan out through both IP-mode and zone-mode
 * paths can self-identify their mode without the operator having to
 * grep backwards for the bootstrap banner.
 */
const char *
save_input_kind_to_string(enum save_input_kind kind);
 
GHashTable *
create_hashtable_from_ip_list(const char *[], int);

bool
is_valid_uuid_string(const char *);

bool
parse_ct_zone(const char *, uint16_t *);

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
 * Ensures that a CLI argument string is an integer >= @min_value and
 * writes the parsed value to *out_value on success.
 *
 * Stricter than atoi(): the full string must be a valid decimal
 * number with no leading/trailing junk. Any of the following triggers
 * errx(EXIT_FAILURE) with a message that names the offending argument:
 *   - @arg_value is NULL or empty
 *   - @arg_value contains non-numeric characters (e.g. "1xyz")
 *   - @arg_value is less than @min_value or greater than INT_MAX
 *
 * The @min_value parameter lets the same helper enforce both
 * "positive" (min_value = 1, for <N>-of-entries and <mode>) and
 * "non-negative" (min_value = 0, for the legacy IP form's num_ips
 * slot where 0 means "VM has no IPv4 NICs"; see the graceful
 * early-exit in start_in_save_mode). min_value = 1 also subsumes the
 * "n <= 0 silent fallback" branches that used to live in
 * detect_save_input_kind.
 *
 * Designed for CLI argv slots where every existing caller treated
 * bad input as a fatal error anyway. Folding the errx() into the
 * helper avoids many copies of the same exit message and prevents
 * the atoi() footgun of treating "1xyz" or "" as a successful parse.
 *
 * Note: this helper only enforces a lower bound. Value-set checks
 * (e.g. mode must be 1 or 2) belong in a dedicated validator
 * (check_mode) called immediately after this one.
 *
 * Args:
 *   @arg_value the raw string from argv.
 *   @out_value on success, set to the parsed int. Untouched on
 *              failure (function does not return on failure).
 *   @arg_name  display name for the argument, used in the error
 *              message. Must be non-NULL.
 *   @min_value lowest accepted value (inclusive). Typical values: 1
 *              for "positive int", 0 for "non-negative int".
 */
void
ensure_cli_arg_is_int_at_least(const char *arg_value, int *out_value,
                               const char *arg_name, int min_value);

GHashTable *
create_hashtable_from_zone_list(const char *zones[], int n_entries);

/**
 * Builds a uint16-keyed hashtable from a strv of paired
 * [port_uuid_0, zone_0, port_uuid_1, zone_1, ...] elements.
 *
 * Used by the zone-mode Clear D-Bus endpoint to translate the
 * "(port, zone) pairs still on this host" payload into a hashtable
 * for the delete dump callback to look up against. The port_uuid half
 * of each pair is treated as opaque metadata and intentionally
 * ignored: the zone-mode delete path only filters on CT zone, so
 * persisting the UUID buys us nothing past the parse step.
 *
 * @num_entries must be even; an odd count is a wire-protocol violation
 * and the function will return NULL after logging.
 */
GHashTable *
create_hashtable_from_port_zone_pairs(const char *port_zone_strv[],
                                      int num_entries);

struct save_targets *
save_targets_new_from_ips(GHashTable *ips_to_migrate);

struct save_targets *
save_targets_new_from_zones(GHashTable *zones);

void
save_targets_destroy(struct save_targets *);

struct load_targets *
load_targets_new_ips(void);

struct load_targets *
load_targets_new_from_zone_args(int n_entries, char *argv[], int start_idx,
                                int stride);

void
load_targets_destroy(struct load_targets *);

#endif /* COMMON_H */

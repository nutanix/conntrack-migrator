/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Entry point for the conntrack_migrator process.
 *
 * Responsibilites:
 *   1. On the source hypervisor, this process maintains a local copy of the
 *      CT entries for the VM's IP addresses (provided as arguments) and upon
 *      the invocation of Save() IPC, returns these entries to the caller.
 *      This is the save mode of operation.
 *   2. On the destination hyperviosr, this process upon the invocation of
 *      Load() IPC, receives the array of CT entries and programs it in the
 *      kernel conntrack table. This is the load mode of operation.
 *
 * To interface with the netlink, the process requires the CAP_NET_ADMIN
 * capability.
 *
 * Usage:
 *  Legacy IP-based:
 *    - SAVE: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 2 <helper_id> <num_ips> <ip1> <ip2> ...
 *    - LOAD: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 1 <helper_id>
 *  Port/CT-zone-based:
 *    - SAVE: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 2 <helper_id> <N> <port_uuid_1> <old_ct_zone_1> ... <port_uuid_N> <old_ct_zone_N>
 *    - LOAD: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 1 <helper_id> <N> <port_uuid_1> <old_ct_zone_1> <new_ct_zone_1> ... <port_uuid_N> <old_ct_zone_N> <new_ct_zone_N>
 */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <glib.h>
#include <libmnl/libmnl.h>
#include <pthread.h>

#include "common.h"
#include "conntrack.h"
#include "conntrack_store.h"
#include "ct_delete_args.h"
#include "dbus_server.h"
#include "lmct_config.h"
#include "log.h"

#define MODE_ARG_INDEX                  1
#define HELPER_ID_ARG_INDEX             2

/* Legacy (IP-mode) names kept for backward compat with existing code. */
#define NUM_IP_ADDR_ARG_INDEX           3
#define IP_ADDR_LIST_ARG_INDEX          4

/* Generic names that read cleanly for both IP and port-zone layouts. */
#define NUM_ENTRIES_ARG_INDEX           3
#define ENTRIES_LIST_START_ARG_INDEX    4

/* Per-entry argv stride for the legacy IP layout and the new
 * (port_uuid, ct_zone[, new_ct_zone]) layout. IP_STRIDE is named (not
 * inlined as 1) so detect_save_mode_op_type() reads symmetrically against
 * its port-zone peer and the shape-mismatch error message is self-explanatory. */
#define IP_STRIDE                       1   /* <ip> */
#define SAVE_PORT_ZONE_STRIDE           2   /* <port_uuid> <old_ct_zone> */
#define LOAD_PORT_ZONE_STRIDE           3   /* <port_uuid> <old_ct_zone> <new_ct_zone> */

#define MAX_IP_ADDRESSES_SUPPORTED      127

/**
 * Parsed command-line arguments.
 *
 * Filled by check_args() before the double fork and read by dmain()
 * in the grandchild.
 *
 * @mode selects the active union arm:
 *   SAVE_MODE: save_op_type
 *   LOAD_MODE: load_op_type
 *
 * @num_entries is the parsed IP or target count. 0 means no IPv4 NICs.
 */
struct cli_mode_config {
    enum op_mode mode;
    union {
        enum save_mode_op_type save_op_type;
        enum load_mode_op_type load_op_type;
    };
    int num_entries;
    /* LOAD port-zone only: old_zone -> new_zone.
     * Built in check_zone_load_args(), consumed by dmain().
     * Ownership moves to create_load_mode_config_for_port_zone_mode()
     * and is released by destroy_load_mode_config().
     * NULL in SAVE mode and legacy LOAD mode. */
    GHashTable *src_dst_zone_map;
};

const char *lmct_config_path = "/etc/lmct_config";

// Mode number to string
const char *mode_to_string[] = {
    [LOAD_MODE] = "LOAD",
    [SAVE_MODE] = "SAVE"
};

struct ct_delete_args ct_del_args = {
    .op_type = SAVE_IPS_OP,       /* overwritten in start_in_save_mode */
    /* Only the active union arm is named; the other arm overlays the
     * same memory and is zero-initialised by the {0} default. Naming
     * both arms here would trip -Woverride-init. */
    .ips_migrated = NULL,
    .ips_on_host = NULL,
    .clear_called = false,
    .clear_failed = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .clear_called_cond = PTHREAD_COND_INITIALIZER
};

/**
 * Set the pthread name.
 * - A failure is logged and ignored.
 *
 * Args:
 *   @tid  thread.
 *   @name name to set.
 */
static void
set_thread_name(pthread_t tid, const char *name)
{
    int ret = pthread_setname_np(tid, name);
    if (ret != 0) {
        LOG(WARNING, "%s: failed to set thread name '%s': %s",
            __func__, name, strerror(ret));
    }
}

/**
 * Publish the socket-bind result.
 * - Wakes start_in_save_mode.
 * - Called on open failure and after bind returns.
 *
 * Args:
 *   @targs    events-thread args.
 *   @bound_ok true when the socket is bound.
 */
static void
signal_events_socket_ready(struct ct_events_targs *targs, bool bound_ok)
{
    pthread_mutex_lock(&targs->ready_mu);
    targs->bound_ok = bound_ok;
    targs->ready = true;
    pthread_cond_signal(&targs->ready_cv);
    pthread_mutex_unlock(&targs->ready_mu);
}

/**
 * Wait until the events thread has finished bind.
 *
 * Args:
 *   @targs events-thread args.
 *
 * Returns:
 *   true if bind succeeded.
 */
static bool
wait_until_events_socket_ready(struct ct_events_targs *targs)
{
    bool ok;

    pthread_mutex_lock(&targs->ready_mu);
    while (!targs->ready) {
        pthread_cond_wait(&targs->ready_cv, &targs->ready_mu);
    }
    ok = targs->bound_ok;
    pthread_mutex_unlock(&targs->ready_mu);
    return ok;
}

/**
 * Destroy the bind barrier and free the events args.
 * - NULL is ignored.
 *
 * Args:
 *   @targs events-thread args.
 */
static void
free_events_targs(struct ct_events_targs *targs)
{
    if (targs == NULL) {
        return;
    }
    pthread_cond_destroy(&targs->ready_cv);
    pthread_mutex_destroy(&targs->ready_mu);
    g_free(targs);
}

/**
 * Wrapper for listening for CT events based on the filter on src/dst field in
 * the CT entries.
 *
 * Args:
 *   @data user data provided to the function. Here it's of type ct_events_targs
 * Returns:
 *   NULL
 */
static void *
pthread_wrapper_ct_events(void *data)
{
    struct ct_events_targs *targs;
    struct mnl_socket *nl;
    int bind_ret;

    targs = (struct ct_events_targs *) data;
    LOG(INFO, "%s: Starting conntrack events thread. op_type=%s is_src=%d",
        __func__, convert_save_mode_op_type_to_string(targs->save_config->op_type),
        targs->is_src);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        LOG(ERROR, "%s: mnl_socket_open failed. %s", __func__,
            strerror(errno));
        signal_events_socket_ready(targs, false);
        return NULL;
    }

    bind_ret = mnl_socket_bind(nl, NF_NETLINK_CONNTRACK_NEW |
                               NF_NETLINK_CONNTRACK_UPDATE |
                               NF_NETLINK_CONNTRACK_DESTROY,
                               MNL_SOCKET_AUTOPID);
    signal_events_socket_ready(targs, bind_ret == 0);
    if (bind_ret < 0) {
        LOG(ERROR, "%s: mnl_socket_bind failed. %s", __func__,
            strerror(errno));
        mnl_socket_close(nl);
        return NULL;
    }

    listen_for_conntrack_events(nl, targs->save_config,
                                targs->is_src, targs->stop_flag);
    mnl_socket_close(nl);

    LOG(INFO, "%s: Finished conntrack events thread. op_type=%s is_src=%d",
        __func__, convert_save_mode_op_type_to_string(targs->save_config->op_type),
        targs->is_src);

    return NULL;
}

/**
 * Gets all the entries present in the kernel CT table for the given
 * SAVE-mode config.
 *
 * Args:
 *   @save_config SAVE-mode config (mode-aware) used to filter the required
 *                CT entries.
 */
static void
dump_conntrack(struct save_mode_config *save_config)
{
    struct nfct_handle *handle;

    // Set the subscriptions for this handle to 0 since we are going to
    // explicitly request dump on this socket.
    handle = nfct_open(CONNTRACK, 0);
    if (handle == NULL) {
        LOG(ERROR, "%s: nfct_open failed. %s", __func__, strerror(errno));
        return;
    }
    get_conntrack_dump(handle, save_config);
    nfct_close(handle);
}

/**
 * Start one conntrack-events thread.
 * - On success the caller owns @out_targs. Join it, then free_events_targs().
 * - On failure @out_targs is left unchanged and the allocation is freed here.
 *
 * Args:
 *   @save_config read-only SAVE config for the callback.
 *   @stop_flag   shared stop flag.
 *   @is_src      true for the IP src thread. False for the IP dst or zone thread.
 *   @thread_name pthread name.
 *   @out_targs   receives the thread args.
 *
 * Returns:
 *   0 on success, -1 if the barrier or the thread cannot be created.
 */
static int
create_events_thread(struct save_mode_config *save_config, bool *stop_flag,
                     bool is_src, const char *thread_name,
                     struct ct_events_targs **out_targs)
{
    struct ct_events_targs *targs;
    int ret;

    targs = g_malloc0(sizeof(*targs));
    targs->save_config = save_config;
    targs->stop_flag   = stop_flag;
    targs->is_src      = is_src;
    if (pthread_mutex_init(&targs->ready_mu, NULL) != 0) {
        LOG(ERROR, "%s: failed to init ready mutex for '%s'",
            __func__, thread_name);
        g_free(targs);
        return -1;
    }
    if (pthread_cond_init(&targs->ready_cv, NULL) != 0) {
        LOG(ERROR, "%s: failed to init ready cond for '%s'",
            __func__, thread_name);
        pthread_mutex_destroy(&targs->ready_mu);
        g_free(targs);
        return -1;
    }

    ret = pthread_create(&targs->tid, NULL, &pthread_wrapper_ct_events, targs);
    if (ret != 0) {
        LOG(ERROR, "%s: events thread '%s' creation failed: %s",
            __func__, thread_name, strerror(ret));
        free_events_targs(targs);
        return -1;
    }
    set_thread_name(targs->tid, thread_name);

    *out_targs = targs;
    return 0;
}

/**
 * Start the delete thread on the already filled ct_del_args.
 * - The thread blocks until clear_called.
 *
 * Returns:
 *   0 on success, -1 if pthread_create fails. tid is left unset.
 */
static int
create_delete_thread(void)
{
    int ret;

    ret = pthread_create(&ct_del_args.tid, NULL,
                         &delete_ct_entries, (void *)&ct_del_args);
    if (ret != 0) {
        LOG(ERROR, "%s: CT delete thread creation failed: %s",
            __func__, strerror(ret));
        return -1;
    }
    set_thread_name(ct_del_args.tid, "ct_delete");
    return 0;
}

/**
 * Start the SAVE workers, then dump the live flows.
 * - No entries, or more than 127 IPs: return 0 and start nothing.
 * - Record the migrated set on ct_del_args and start the delete thread.
 * - IP mode: src and dst event threads. Zone mode: one event thread.
 * - Dump only after those sockets are bound.
 * - On failure, join whatever started and wake the delete thread.
 *
 * Args:
 *   @save_config entries to migrate.
 *   @stop_flag   shared stop flag for the event threads.
 *
 * Returns:
 *   0 on success, -1 otherwise.
 */
static int
start_in_save_mode(struct save_mode_config *save_config, bool *stop_flag)
{
    struct ct_events_targs *src_targs  = NULL;
    struct ct_events_targs *dst_targs  = NULL;
    struct ct_events_targs *zone_targs = NULL;
    uint32_t num_entries;

    /* Common: arity + early exits. The "no entries" path is not an
     * error in either mode (e.g. a VM with no IPv4 NICs in IP mode);
     * QEMU expects the helper to live for the migration window, so we
     * just skip starting the worker threads and let the DBus loop run. */
    if (save_config->op_type == SAVE_IPS_OP) {
        num_entries = g_hash_table_size(save_config->ips_to_migrate);
    } else {
        num_entries = g_hash_table_size(save_config->zones_to_migrate);
    }
    if (num_entries == 0) {
        LOG(INFO, "%s: No entries to migrate (op_type=%s); skipping save "
            "mode threads", __func__,
            convert_save_mode_op_type_to_string(save_config->op_type));
        return 0;
    }
    /* IP-only: BPF filter cap. Zone mode does in-callback matching so
     * the per-IP limit does not apply. */
    if (save_config->op_type == SAVE_IPS_OP &&
        num_entries > MAX_IP_ADDRESSES_SUPPORTED) {
        LOG(WARNING, "Number of IP addresses exceeds the max limit: %d. "
            "No Conntrack Migration will be performed.",
            MAX_IP_ADDRESSES_SUPPORTED);
        return 0;
    }

    /* Common: wire up the delete-thread state, then create the thread.
     * The delete thread is started in BOTH modes; the body of
     * _delete_ct_entries dispatches on op_type when on_clear wakes it up.
     * NOTE: ct_del_args is an extern global. */
    ct_del_args.op_type = save_config->op_type;
    if (save_config->op_type == SAVE_IPS_OP) {
        ct_del_args.ips_migrated = save_config->ips_to_migrate;
    } else {
        ct_del_args.zones_migrated = save_config->zones_to_migrate;
    }
    if (create_delete_thread() != 0) {
        return -1;
    }

    /* Mode-specific: create the events thread(s). IP mode runs two
     * BPF-filtered threads (src + dst). Zone mode runs one unfiltered
     * thread; the callback handles zone matching in-process because
     * BPF cannot filter on CT zone. */
    if (save_config->op_type == SAVE_IPS_OP) {
        if (create_events_thread(save_config, stop_flag, true,
                                 "ct_events_src", &src_targs) != 0) {
            goto cleanup_delete_thread;
        }
        if (create_events_thread(save_config, stop_flag, false,
                                 "ct_events_dst", &dst_targs) != 0) {
            goto cleanup_delete_thread;
        }
    } else {
        if (create_events_thread(save_config, stop_flag, false,
                                 "ct_events_zone", &zone_targs) != 0) {
            goto cleanup_delete_thread;
        }
    }

    /* Wait until each events socket is bound, then dump. A NEW or
     * DESTROY in the gap before bind would be in neither place. */
    if (save_config->op_type == SAVE_IPS_OP) {
        if (!wait_until_events_socket_ready(src_targs) ||
            !wait_until_events_socket_ready(dst_targs)) {
            goto cleanup_delete_thread;
        }
    } else if (!wait_until_events_socket_ready(zone_targs)) {
        goto cleanup_delete_thread;
    }

    dump_conntrack(save_config);

    if (save_config->op_type == SAVE_IPS_OP) {
        pthread_join(src_targs->tid, NULL);
        pthread_join(dst_targs->tid, NULL);
        free_events_targs(src_targs);
        free_events_targs(dst_targs);
    } else {
        pthread_join(zone_targs->tid, NULL);
        free_events_targs(zone_targs);
    }
    pthread_join(ct_del_args.tid, NULL);
    return 0;

cleanup_delete_thread:
    /* Stop any events thread that did start, then wake the delete
     * thread so it does not block on clear_called_cond. */
    *stop_flag = true;
    if (src_targs != NULL) {
        pthread_join(src_targs->tid, NULL);
    }
    if (dst_targs != NULL) {
        pthread_join(dst_targs->tid, NULL);
    }
    if (zone_targs != NULL) {
        pthread_join(zone_targs->tid, NULL);
    }
    pthread_mutex_lock(&ct_del_args.mutex);
    ct_del_args.clear_called = true;
    pthread_cond_signal(&ct_del_args.clear_called_cond);
    pthread_mutex_unlock(&ct_del_args.mutex);
    pthread_join(ct_del_args.tid, NULL);
    free_events_targs(src_targs);
    free_events_targs(dst_targs);
    free_events_targs(zone_targs);
    return -1;
}

/**
 * Creates the ips_to_migrate hashtable from the legacy SAVE-mode CLI.
 *
 * Args:
 *   @argv    array of CLI args.
 *   @num_ips declared IP count from cli_mode_config.num_entries
 *            (already validated by check_ip_save_args pre-fork). May
 *            legitimately be 0 ("VM has no IPv4 NICs"; see the early
 *            exit in start_in_save_mode).
 *
 * Returns:
 *   Resulting hashtable containing IP address(uint32_t) as key.
 */
static GHashTable *
create_ips_ht_from_args(const char *const argv[], int num_ips)
{
    GHashTable *ht;
    const char *const *ips = argv + IP_ADDR_LIST_ARG_INDEX;

    ht = create_hashtable_from_ip_list(ips, num_ips);
    if (ht == NULL) {
        LOG(ERROR, "%s: Hashtable creation failed.", __func__);
        return NULL;
    }

    return ht;
}

/**
 * Build the zones_to_migrate table from the SAVE port-zone CLI.
 * - Reads the old_ct_zone column. port_uuid is not stored.
 *
 * Args:
 *   @argv      CLI arguments.
 *   @n_entries declared entry count. Must be > 0.
 *
 * Returns:
 *   Zone hashtable, or NULL.
 */
static GHashTable *
create_zones_ht_from_args(const char *const argv[], int n_entries)
{
    int i;
    const char **zones;
    GHashTable *ht;
    const int old_zone_offset = 1;

    if (n_entries <= 0) {
        LOG(ERROR, "%s: non-positive n_entries (%d)", __func__, n_entries);
        return NULL;
    }

    if (argv == NULL) {
        LOG(ERROR, "%s: argv is NULL", __func__);
        return NULL;
    }


    zones = g_malloc0(sizeof(*zones) * n_entries);
    for (i = 0; i < n_entries; i++) {
        int port_uuid_index =
            ENTRIES_LIST_START_ARG_INDEX + (i * SAVE_PORT_ZONE_STRIDE);
        int zone_index = port_uuid_index + old_zone_offset;
        zones[i] = argv[zone_index];
    }

    ht = create_hashtable_from_zone_list(zones, n_entries);
    g_free(zones);

    if (ht == NULL) {
        LOG(ERROR, "%s: Hashtable creation failed.", __func__);
        return NULL;
    }
    return ht;
}

/**
 * Pick the SAVE layout from the trailing argument count.
 * - No list: SAVE_IPS_OP and @out_n_entries = 0.
 * - N IPs: SAVE_IPS_OP.
 * - N port/zone pairs: SAVE_PORT_ZONE_OP.
 * - Any other shape calls errx().
 *
 * Args:
 *   @argc          argument count.
 *   @argv          CLI arguments.
 *   @out_n_entries declared N. 0 when there is no list.
 *
 * Returns:
 *   Detected sub-mode.
 */
static enum save_mode_op_type
detect_save_mode_op_type(int argc, const char *const argv[], int *out_n_entries)
{
    int n;
    int remaining;

    if (argc <= ENTRIES_LIST_START_ARG_INDEX) {
        *out_n_entries = 0;
        return SAVE_IPS_OP;
    }

    ensure_cli_arg_is_int_at_least(argv[NUM_ENTRIES_ARG_INDEX], &n,
                                   "num_entries",
                                   MIN_ACCEPTABLE_VALUE_FOR_NUM_ENTRIES);
    *out_n_entries = n;

    remaining = argc - ENTRIES_LIST_START_ARG_INDEX;

    if (remaining == n * IP_STRIDE) {
        return SAVE_IPS_OP;
    }
    if (remaining == n * SAVE_PORT_ZONE_STRIDE) {
        return SAVE_PORT_ZONE_OP;
    }

    errx(EXIT_FAILURE,
        "SAVE mode: argv shape mismatch. N=%d, expected %d args (IP form) "
        "or %d args (port-zone form), got %d.",
        n, n * IP_STRIDE, n * SAVE_PORT_ZONE_STRIDE, remaining);
}

/**
 * Pick the LOAD layout.
 * - argc == 3: LOAD_IPS_OP and @out_n_entries = 0.
 * - argc == 4 + 3*N: LOAD_PORT_ZONE_OP.
 * - Anything else calls errx(). No fallback to legacy LOAD.
 *
 * Args:
 *   @argc          argument count.
 *   @argv          CLI arguments.
 *   @out_n_entries declared N. 0 for legacy LOAD.
 *
 * Returns:
 *   Detected sub-mode.
 */
static enum load_mode_op_type
detect_load_mode_op_type(int argc, const char *const argv[], int *out_n_entries)
{
    int n;
    int remaining;

    if (argc == HELPER_ID_ARG_INDEX + 1) {   /* argc == 3: legacy LOAD */
        *out_n_entries = 0;
        return LOAD_IPS_OP;
    }

    if (argc <= ENTRIES_LIST_START_ARG_INDEX) {
        errx(EXIT_FAILURE,
             "LOAD mode: trailing args present but no port-zone list. "
             "Expected `conntrack_migrator 1 <helper_id>` or "
             "`conntrack_migrator 1 <helper_id> <N> "
             "<port_uuid> <old_zone> <new_zone> ...`.");
    }

    ensure_cli_arg_is_int_at_least(argv[NUM_ENTRIES_ARG_INDEX], &n,
                                   "LOAD num_entries",
                                   MIN_ACCEPTABLE_VALUE_FOR_NUM_ENTRIES);
    *out_n_entries = n;

    remaining = argc - ENTRIES_LIST_START_ARG_INDEX;

    if (remaining == n * LOAD_PORT_ZONE_STRIDE) {
        return LOAD_PORT_ZONE_OP;
    }

    errx(EXIT_FAILURE,
         "LOAD mode: argv shape mismatch. N=%d, expected %d args "
         "(port-zone form), got %d.",
         n, n * LOAD_PORT_ZONE_STRIDE, remaining);
}

/**
 * Checks if the mode passed is either LOAD or SAVE.
 *
 * Called once pre-fork from check_args(); an out-of-set mode aborts
 * the process via errx() before fork happens, so dmain() is guaranteed
 * to receive a valid cli_mode_config.mode value.
 *
 * Args:
 *   @mode operating mode
 */
static void
check_mode(int mode)
{
    if ((mode != LOAD_MODE) && (mode != SAVE_MODE)) {
        errx(EXIT_FAILURE, "Incorrect mode passed. Should be 1 (LOAD) or "
                "2 (SAVE)\n");
    }
}

/**
 * Build the SAVE config from the parsed CLI.
 * - IP mode stores the IP hashtable.
 * - Zone mode stores the zone hashtable.
 *
 * Args:
 *   @argv CLI arguments.
 *   @cli  parsed CLI. Caller is in SAVE mode.
 *
 * Returns:
 *   New config, or NULL if the hashtable cannot be built.
 */
static struct save_mode_config *
build_save_mode_config(const char *const argv[],
                       const struct cli_mode_config *cli)
{
    if (cli->save_op_type == SAVE_IPS_OP) {
        GHashTable *ips_to_migrate =
            create_ips_ht_from_args(argv, cli->num_entries);
        if (ips_to_migrate == NULL) {
            return NULL;
        }
        return create_save_mode_config_for_ip_mode(ips_to_migrate);
    }

    GHashTable *zones_ht = create_zones_ht_from_args(argv, cli->num_entries);
    if (zones_ht == NULL) {
        return NULL;
    }
    return create_save_mode_config_for_port_zone_mode(zones_ht);
}

/**
 * Build the LOAD config from the parsed CLI.
 * - Legacy mode has no zone map.
 * - Port-zone mode takes ownership of cli->src_dst_zone_map.
 *
 * Args:
 *   @cli parsed CLI. Caller is in LOAD mode.
 *
 * Returns:
 *   New config.
 */
static struct load_mode_config *
build_load_mode_config(const struct cli_mode_config *cli)
{
    struct load_mode_config *load_config;

    if (cli->load_op_type == LOAD_IPS_OP) {
        LOG(INFO, "%s: LOAD legacy mode (no zone rewrite)", __func__);
        return create_load_mode_config_for_legacy_mode();
    }

    load_config = create_load_mode_config_for_port_zone_mode(cli->src_dst_zone_map);
    if (load_config == NULL) {
        LOG(ERROR, "%s: failed to create load_config", __func__);
        return NULL;
    }
    LOG(INFO, "%s: LOAD port-zones mode, %d src-to-dst zone map entries",
        __func__, cli->num_entries);
    return load_config;
}

/**
 * Fill the dbus args and start the dbus thread.
 * - LOAD mode builds load_config. SAVE leaves it NULL.
 *
 * Args:
 *   @args           thread args to fill.
 *   @cli            parsed CLI.
 *   @helper_id      helper id for the dbus object.
 *   @stop_flag      shared stop flag.
 *   @loop_mu_inited set true once loop_mu is initialised.
 *
 * Returns:
 *   0 on success, EINVAL if the LOAD config cannot be built,
 *   EAGAIN if the mutex or thread cannot be created.
 */
static int
start_dbus_server(struct dbus_targs *args, const struct cli_mode_config *cli,
                  const char *helper_id, bool *stop_flag, bool *loop_mu_inited)
{
    int ret;

    args->helper_id = helper_id;
    args->stop_flag = stop_flag;
    args->mode = cli->mode;
    args->save_op_type = (cli->mode == SAVE_MODE) ? cli->save_op_type
                                                  : SAVE_IPS_OP;
    args->load_config = NULL;
    args->loop = NULL;
    args->should_quit = false;

    ret = pthread_mutex_init(&args->loop_mu, NULL);
    if (ret != 0) {
        LOG(ERROR, "%s: failed to init loop_mu: %s", __func__, strerror(ret));
        return EAGAIN;
    }
    *loop_mu_inited = true;

    /* LOAD mode only. SAVE leaves load_config NULL. */
    if (cli->mode == LOAD_MODE) {
        args->load_config = build_load_mode_config(cli);
        if (args->load_config == NULL) {
            return EINVAL;
        }
    }

    ret = pthread_create(&args->tid, NULL, dbus_server_init, args);
    if (ret != 0) {
        LOG(ERROR, "%s: dbus_server thread creation failed. %s", __func__,
            strerror(ret));
        return EAGAIN;
    }
    set_thread_name(args->tid, "dbus_server");
    return 0;
}

/**
 * Entry point for the daemon.
 *
 * Args:
 *   @argc num of arguments to the application.
 *   @argv string argument list.
 *   @cli  parsed CLI bundle populated by check_args() before the
 *         daemon was forked. Mode, sub-op_type, and num_entries are read
 *         directly from here instead of re-walking argv. fork() copies
 *         the entire address space (including the parent's stack frame),
 *         so the pointer is valid in the grandchild.
 *
 * Returns:
 *   0 if the daemon exits without any error. otherwise the specific error
 *   code is returned.
 */
static int
dmain(int argc, const char *const argv[], const struct cli_mode_config *cli)
{
    const char *helper_id;
    const char *dbus_address;
    int ret;
    int rc = 0;
    bool stop_flag = false;
    bool log_open = false;
    bool dbus_started = false;
    bool loop_mu_inited = false;
    struct dbus_targs dbus_server_args = {0};
    struct save_mode_config *save_config = NULL;

    (void) argc;

    if (argv == NULL || cli == NULL) {
        return EINVAL;
    }

    helper_id = argv[HELPER_ID_ARG_INDEX];

    ret = init_log(INFO, helper_id);
    if (ret != 0) {
        return EAGAIN;
    }
    log_open = true;

    init_lmct_config(lmct_config_path);
    set_log_level(lmct_conf.log_lvl);

    dbus_address = getenv("DBUS_SYSTEM_BUS_ADDRESS");
    LOG(INFO, "%s: Starting in mode %s", __func__, mode_to_string[cli->mode]);
    LOG(INFO, "%s: dbus address %s", __func__,
        dbus_address != NULL ? dbus_address : "(unset)");
    LOG(INFO, "%s: helper id: %s", __func__, helper_id);
    LOG(INFO, "%s: Maximum CT entries migratable: %d", __func__,
        lmct_conf.max_entries_to_migrate);

    conn_store = conntrack_store_new();
    if (conn_store == NULL) {
        LOG(ERROR, "%s: connection_store is NULL", __func__);
        rc = EAGAIN;
        goto cleanup;
    }

    ret = start_dbus_server(&dbus_server_args, cli, helper_id, &stop_flag,
                            &loop_mu_inited);
    if (ret != 0) {
        rc = ret;
        goto cleanup;
    }
    dbus_started = true;

    if (cli->mode == SAVE_MODE) {
        save_config = build_save_mode_config(argv, cli);
        if (save_config == NULL) {
            rc = EINVAL;
            goto cleanup;
        }
        if (start_in_save_mode(save_config, &stop_flag) != 0) {
            rc = EAGAIN;
        }
    }

cleanup:
    stop_flag = true;

    if (dbus_started) {
        if (rc != 0) {
            dbus_server_request_quit(&dbus_server_args);
        }
        pthread_join(dbus_server_args.tid, NULL);
    }
    if (save_config != NULL) {
        destroy_save_mode_config(save_config);
    }
    if (dbus_server_args.load_config != NULL) {
        destroy_load_mode_config(dbus_server_args.load_config);
    }
    if (loop_mu_inited) {
        pthread_mutex_destroy(&dbus_server_args.loop_mu);
    }
    if (conn_store != NULL) {
        conntrack_store_destroy(conn_store);
        conn_store = NULL;
    }
    if (log_open) {
        close_log();
    }

    return rc;
}

static void
err_usage(void)
{
    errx(EXIT_FAILURE,
        "Usage:\n"
        "  Legacy IP-based:\n"
        "    SAVE mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 2 "
            "<helper_id> <num_ips> <ip1> <ip2> ...\n"
        "    LOAD mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 1 "
            "<helper_id>\n"
        "  Port/CT-zone-based:\n"
        "    SAVE mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 2 "
            "<helper_id> <N> <port_uuid_1> <old_ct_zone_1> ... "
            "<port_uuid_N> <old_ct_zone_N>\n"
        "    LOAD mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 1 "
            "<helper_id> <N> <port_uuid_1> <old_ct_zone_1> <new_ct_zone_1> "
            "... <port_uuid_N> <old_ct_zone_N> <new_ct_zone_N>\n"
        "NOTE: DBUS_SYSTEM_BUS_ADDRESS env variable must be set.\n");
}

/**
 * Checks if the DBUS_SYSTEM_BUS_ADDRESS env variable is set.
 */
static void
check_dbus_address_env(void)
{
    const char *dbus_address = getenv("DBUS_SYSTEM_BUS_ADDRESS");
    if (dbus_address == NULL || strcmp(dbus_address, "") == 0) {
        errx(EXIT_FAILURE, "DBUS_SYSTEM_BUS_ADDRESS environment variable not "
                "set\n");
    }
}

/**
 * Performs checks on args when started in save mode (legacy IP form).
 *
 * Checks performed:
 * 1. Num of ip address param is present and is non-negative.
 * 2. The ip address list size matches the num of ip addresses provided.
 *
 * NOTE: this is the legacy SAVE validator, kept verbatim from the original
 * implementation. The 127-IP cap referenced in the original docstring is
 * enforced later in start_in_save_mode().
 *
 * Args:
 *   @argc num of arguments.
 *   @argv array of CLI arguments.
 */
static void
check_ip_save_args(int argc, const char *const argv[])
{
    int num_ip_addr;

    if (argc < 4) {
        errx(EXIT_FAILURE, "Number of IP addresses not present in args");
    }

    /* min_value = 0 (not 1) because num_ip_addr == 0 is the legitimate
     * "VM has no IPv4 NICs" case. The helper rejects negatives and
     * non-numeric input; we still need the count-vs-argc check below
     * to catch "I declared 5 IPs but only passed 2". */
    ensure_cli_arg_is_int_at_least(argv[NUM_IP_ADDR_ARG_INDEX], &num_ip_addr,
                                   "num_ips", MIN_ACCEPTABLE_VALUE_FOR_NUM_IPS);
    if (num_ip_addr > (argc - IP_ADDR_LIST_ARG_INDEX)) {
        errx(EXIT_FAILURE,
             "Declared num_ips (%d) exceeds the number of IP addresses "
             "supplied in argv (%d)",
             num_ip_addr, argc - IP_ADDR_LIST_ARG_INDEX);
    }
}

/**
 * Check each SAVE port-zone entry. The count is already known.
 * - port_uuid must be a valid port UUID and must not repeat.
 * - old_ct_zone must be a uint16.
 * - The first bad entry calls errx().
 *
 * Args:
 *   @n    declared entry count.
 *   @argv CLI arguments.
 */
static void
check_zone_save_args(int n, const char *const argv[])
{
    int i;
    const int old_zone_offset = 1;
    GHashTable *seen_uuids = g_hash_table_new(g_str_hash, g_str_equal);

    for (i = 0; i < n; i++) {
        int base = ENTRIES_LIST_START_ARG_INDEX + (i * SAVE_PORT_ZONE_STRIDE);
        const char *port_uuid = argv[base];
        const char *zone_str  = argv[base + old_zone_offset];
        uint16_t zone_val;

        if (!is_valid_uuid_string(port_uuid)) {
            g_hash_table_destroy(seen_uuids);
            errx(EXIT_FAILURE,
                 "Invalid UUID at port-zone entry %d: '%s'",
                 i, port_uuid);
        }
        if (g_hash_table_contains(seen_uuids, port_uuid)) {
            g_hash_table_destroy(seen_uuids);
            errx(EXIT_FAILURE,
                 "Duplicate port_uuid at port-zone entry %d: '%s'",
                 i, port_uuid);
        }
        g_hash_table_insert(seen_uuids, (gpointer) port_uuid,
                            GINT_TO_POINTER(1));
        if (!parse_ct_zone(zone_str, &zone_val)) {
            g_hash_table_destroy(seen_uuids);
            errx(EXIT_FAILURE,
                 "Invalid old_ct_zone at port-zone entry %d: '%s' "
                 "(must be uint16)", i, zone_str);
        }
    }
    g_hash_table_destroy(seen_uuids);
}

/**
 * Check each LOAD port-zone triple and build old_zone -> new_zone.
 * - port_uuid is checked and not stored.
 * - A repeated old_zone keeps the last new_zone and logs a warning.
 * - A bad UUID or zone calls errx().
 *
 * Args:
 *   @n    declared entry count.
 *   @argv CLI arguments.
 *
 * Returns:
 *   New map. The caller owns it.
 */
static GHashTable *
check_zone_load_args(int n, const char *const argv[])
{
    GHashTable *src_dst_zone_map;
    int i;
    const int old_zone_offset = 1;
    const int new_zone_offset = 2;

    src_dst_zone_map = g_hash_table_new(g_direct_hash, g_direct_equal);

    for (i = 0; i < n; i++) {
        int base = ENTRIES_LIST_START_ARG_INDEX + (i * LOAD_PORT_ZONE_STRIDE);
        const char *port_uuid    = argv[base];
        const char *old_zone_str = argv[base + old_zone_offset];
        const char *new_zone_str = argv[base + new_zone_offset];
        uint16_t old_zone, new_zone;
        gpointer existing_val;

        if (!is_valid_uuid_string(port_uuid)) {
            g_hash_table_destroy(src_dst_zone_map);
            errx(EXIT_FAILURE,
                 "Invalid UUID at port-zone entry %d: '%s'",
                 i, port_uuid);
        }
        if (!parse_ct_zone(old_zone_str, &old_zone)) {
            g_hash_table_destroy(src_dst_zone_map);
            errx(EXIT_FAILURE,
                 "Invalid old_ct_zone at port-zone entry %d: '%s'",
                 i, old_zone_str);
        }
        if (!parse_ct_zone(new_zone_str, &new_zone)) {
            g_hash_table_destroy(src_dst_zone_map);
            errx(EXIT_FAILURE,
                 "Invalid new_ct_zone at port-zone entry %d: '%s'",
                 i, new_zone_str);
        }

        if (g_hash_table_lookup_extended(src_dst_zone_map,
                                         GUINT_TO_POINTER((guint) old_zone),
                                         NULL, &existing_val)) {
            uint16_t existing = (uint16_t) GPOINTER_TO_UINT(existing_val);
            if (existing != new_zone) {
                LOG(WARNING, "%s: old_zone %u remapped twice "
                    "(was -> %u, now -> %u). Last write wins.",
                    __func__, (unsigned) old_zone,
                    (unsigned) existing, (unsigned) new_zone);
            }
        }

        g_hash_table_insert(src_dst_zone_map,
                            GUINT_TO_POINTER((guint) old_zone),
                            GUINT_TO_POINTER((guint) new_zone));
    }

    return src_dst_zone_map;
}

/**
 * Check SAVE arguments.
 * - Detect IP vs port-zone, then run that checker.
 * - Write the detected op type and N when the output pointers are non-NULL.
 *
 * Args:
 *   @argc          argument count.
 *   @argv          CLI arguments.
 *   @out_op_type   detected sub-mode. May be NULL.
 *   @out_n_entries declared N. 0 when there is no IP list. May be NULL.
 */
static void
check_save_mode_args(int argc, const char *const argv[],
                     enum save_mode_op_type *out_op_type,
                     int *out_n_entries)
{
    int n_entries = 0;
    enum save_mode_op_type op_type =
        detect_save_mode_op_type(argc, argv, &n_entries);

    if (op_type == SAVE_IPS_OP) {
        check_ip_save_args(argc, argv);
    } else {
        if (op_type == SAVE_PORT_ZONE_OP) {
            check_zone_save_args(n_entries, argv);
        } else {
            errx(EXIT_FAILURE, "Invalid save mode op_type: %d", op_type);
        }
    }

    if (out_op_type != NULL) {
        *out_op_type = op_type;
    }
    if (out_n_entries != NULL) {
        *out_n_entries = n_entries;
    }
}

/**
 * Check LOAD arguments.
 * - Legacy LOAD has no extra arguments and no zone map.
 * - Port-zone LOAD is checked by check_zone_load_args(), which builds the map.
 * - Write the op type, N, and map when the output pointers are non-NULL.
 * - A NULL map pointer drops the new map instead of leaking it.
 *
 * Args:
 *   @argc                 argument count.
 *   @argv                 CLI arguments.
 *   @out_op_type          detected sub-mode. May be NULL.
 *   @out_n_entries        declared N. 0 for legacy LOAD. May be NULL.
 *   @out_src_dst_zone_map zone map. NULL for legacy LOAD. Caller owns it.
 */
static void
check_load_mode_args(int argc, const char *const argv[],
                     enum load_mode_op_type *out_op_type,
                     int *out_n_entries,
                     GHashTable **out_src_dst_zone_map)
{
    int n_entries = 0;
    GHashTable *src_dst_zone_map = NULL;
    enum load_mode_op_type op_type =
        detect_load_mode_op_type(argc, argv, &n_entries);

    if (op_type == LOAD_PORT_ZONE_OP) {
        src_dst_zone_map = check_zone_load_args(n_entries, argv);
    } else {
        if (op_type != LOAD_IPS_OP) {
            errx(EXIT_FAILURE, "Invalid load mode op_type: %d", op_type);
        }
    }

    if (out_op_type != NULL) {
        *out_op_type = op_type;
    }
    if (out_n_entries != NULL) {
        *out_n_entries = n_entries;
    }
    if (out_src_dst_zone_map != NULL) {
        *out_src_dst_zone_map = src_dst_zone_map;
    } else if (src_dst_zone_map != NULL) {
        /* Caller dropped ownership; don't leak. */
        g_hash_table_destroy(src_dst_zone_map);
    }
}

/**
 * Top-level CLI validation entry point.
 *
 * Checks performed:
 * 1. Minimum argc.
 * 2. DBUS_SYSTEM_BUS_ADDRESS env is set.
 * 3. Mode is valid (LOAD/SAVE).
 * 4. Per-mode argument shape and per-entry content (legacy IP form or
 *    new port-zone form, auto-detected from argv).
 *
 * On success populates @out with the validated (mode, sub-op_type) pair.
 * On any failure errx() exits the process.
 *
 * Args:
 *   @argc num of arguments.
 *   @argv array of CLI arguments.
 *   @out  output struct populated with the parse result. Must be non-NULL.
 */
static void
check_args(int argc, const char *const argv[], struct cli_mode_config *out)
{
    int mode;

    if (argv == NULL || out == NULL) {
        errx(EXIT_FAILURE,
             "%s: argv=%p out=%p (both must be non-NULL)",
             __func__, (void *)argv, (void *)out);
    }

    if (argc < 3) {
        err_usage();
    }

    check_dbus_address_env();

    ensure_cli_arg_is_int_at_least(argv[MODE_ARG_INDEX], &mode, "mode",
                                   MIN_ACCEPTABLE_VALUE_FOR_MODE);
    check_mode(mode);
    out->mode = (enum op_mode) mode;

    /* num_entries is populated by the mode-specific dispatcher, which
     * in turn picks it up from detect_*_mode_op_type's existing parse -
     * no second call to ensure_cli_arg_is_int_at_least on argv[3]. */
    if (mode == SAVE_MODE) {
        check_save_mode_args(argc, argv, &out->save_op_type,
                             &out->num_entries);
    } else {
        check_load_mode_args(argc, argv, &out->load_op_type,
                             &out->num_entries, &out->src_dst_zone_map);
    }
}

/**
 * Entry point for the conntrack_migrator application.
 *
 * This function is the entry point for the conntrack_migrator
 * application. As a first step it validates some of the arguments
 * provided and then proceeds to daemonise itself. main uses double forking
 * to turn itself into a daemon.
 * The process forks a child and waits for the child to terminate.
 * The first fork enables the child process to take control of the tty
 * session and become the process leader. At this point, the child forks
 * another process and does not wait for it to exit. Thus, the new grand-child
 * process is now orphaned and handled by the init process.
 * Thus the second fork guarantees that the child is no longer a session
 * leader, preventing the daemon from ever acquiring a controlling terminal.
 *
 * Args:
 *   @argc num of argmuments to the application
 *   @argv string argument list
 *
 * Returns:
 *   0 if the application exits without any error. otherwise the specific
 *   error code is returned.
 */
int
main(int argc, char *argv[])
{
    int child_pid;
    struct cli_mode_config cli = {0};

    /* Validate CLI args + decide IP-vs-zone sub-op_type before any forks.
     * fork() preserves the parent's address space (copy-on-write of
     * the entire AS, including this stack frame), so `cli` is still
     * readable in the grandchild and is passed directly to dmain()
     * rather than being re-parsed there. */
    check_args(argc, (const char *const *)argv, &cli);

    // Fork child
    child_pid = fork();
    if (child_pid < 0) {
        err(EXIT_FAILURE, "Child fork failed.\n");
    }
    if (child_pid == 0) {
        // Become a process group and session group leader
        setsid();

        // Fork granchild so that session leader can exit
        int grandchild_pid = fork();
        if (grandchild_pid < 0) {
            err(EXIT_FAILURE, "grand-child fork failed.\n");
        }
        if (grandchild_pid == 0) {
            int ret = 0;
            // Grand-child process
            chdir("/");

            // Close all open file descriptors inherited from parent.
            int x;
            for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
                close(x);
            }

            // start the daemon
            ret = dmain(argc, (const char *const *)argv, &cli);
            exit((ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE));
        } else {
            // Child process
            printf("pid=%d\n", grandchild_pid);
            exit(EXIT_SUCCESS);
        }
        exit(EXIT_SUCCESS);
    } else {
        // Parent process
        wait(NULL);
    }
    return EXIT_SUCCESS;
}

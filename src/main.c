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
 *  Two CLI shapes are supported. The legacy IP-based form is preserved as-is
 *  so existing callers keep working; the new port/CT-zone form is selected
 *  automatically based on the ratio of trailing args to the declared count.
 *
 *  Legacy IP-based:
 *    - SAVE mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 2 \
 *            <helper_id> <num_ips> <ip1> <ip2> ...
 *    - LOAD mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 1 <helper_id>
 *
 *  New port/CT-zone-based:
 *    - SAVE mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 2 \
 *            <helper_id> <N> <port_uuid_1> <old_ct_zone_1> ... \
 *                              <port_uuid_N> <old_ct_zone_N>
 *    - LOAD mode: DBUS_SYSTEM_BUS_ADDRESS=<addr> conntrack_migrator 1 \
 *            <helper_id> <N> <port_uuid_1> <old_ct_zone_1> <new_ct_zone_1> \
 *                          ... <port_uuid_N> <old_ct_zone_N> <new_ct_zone_N>
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

/* Per-entry argv stride for the new (port_uuid, ct_zone[, new_ct_zone]) layout. */
#define SAVE_PORT_ZONE_STRIDE           2   /* <port_uuid> <old_ct_zone> */
#define LOAD_PORT_ZONE_STRIDE           3   /* <port_uuid> <old_ct_zone> <new_ct_zone> */

#define MAX_IP_ADDRESSES_SUPPORTED      127

/**
 * Result of CLI parsing - filled by check_args() pre-fork and consumed
 * by dmain() post-fork. Threading the parsed result through avoids
 * re-walking argv inside the daemon: fork() copies the entire address
 * space (including main's stack frame), so the struct is valid in the
 * grandchild and is read verbatim.
 *
 * The sub-kind field is a tagged union: the active arm is determined by
 * @mode (SAVE_MODE -> save_kind, LOAD_MODE -> load_kind).
 *
 * @num_entries holds the declared entry count from
 * argv[NUM_ENTRIES_ARG_INDEX] when applicable:
 *   - SAVE IP-mode "no IPv4 NICs" path  (argc <= 4):  0
 *   - SAVE IP-mode standard:                          num_ips
 *   - SAVE port-zone mode:                            N
 *   - LOAD legacy:                                    0
 *   - LOAD port-zone mode:                            N
 * Consumers that legitimately accept 0 (the no-IPv4-NICs path) must
 * treat 0 as "list absent" rather than "list empty bad".
 *
 * num_entries is captured by detect_*_input_kind during its existing
 * shape-detection parse and propagated up through check_*_mode_args -
 * check_args does not parse argv[3] a second time.
 */
struct cli_mode_config {
    enum op_mode mode;
    union {
        enum save_input_kind save_kind;
        enum load_input_kind load_kind;
    };
    int num_entries;
};

const char *lmct_config_path = "/etc/lmct_config";

// Mode number to string
const char *mode_to_string[] = {
    [LOAD_MODE] = "LOAD",
    [SAVE_MODE] = "SAVE"
};

struct ct_delete_args ct_del_args = {
    .kind = SAVE_INPUT_IPS,       /* overwritten in start_in_save_mode */
    /* Only the active union arm is named; the other arm overlays the
     * same memory and is zero-initialised by the {0} default. Naming
     * both arms here would trip -Woverride-init. */
    .ips_migrated = NULL,
    .ips_on_host = NULL,
    .clear_called = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .clear_called_cond = PTHREAD_COND_INITIALIZER
};

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

    targs = (struct ct_events_targs *) data;
    LOG(INFO, "%s: Starting conntrack events thread. is_src = %d", __func__,
        targs->is_src);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        LOG(ERROR, "%s: mnl_socket_open failed. %s", __func__,
            strerror(errno));
        return NULL;
    }

    if (mnl_socket_bind(nl, NF_NETLINK_CONNTRACK_NEW |
                        NF_NETLINK_CONNTRACK_UPDATE |
                        NF_NETLINK_CONNTRACK_DESTROY,
                        MNL_SOCKET_AUTOPID) < 0) {
        LOG(ERROR, "%s: mnl_socket_bind failed. %s", __func__,
            strerror(errno));
        mnl_socket_close(nl);
        return NULL;
    }

    listen_for_conntrack_events(nl, targs->targets,
                                targs->is_src, targs->stop_flag);
    mnl_socket_close(nl);

    LOG(INFO, "%s: Finished conntrack events. is_src = %d", __func__,
        targs->is_src);

    return NULL;
}

/**
 * Gets all the entries present in the kernel CT table for the given
 * SAVE migration targets.
 *
 * Args:
 *   @targets SAVE targets bundle (mode-aware) used to filter the required
 *            CT entries.
 */
static void
dump_conntrack(struct save_targets *targets)
{
    struct nfct_handle *handle;

    // Set the subscriptions for this handle to 0 since we are going to
    // explicitly request dump on this socket.
    handle = nfct_open(CONNTRACK, 0);
    if (handle == NULL) {
        LOG(ERROR, "%s: nfct_open failed. %s", __func__, strerror(errno));
        return;
    }
    get_conntrack_dump(handle, targets);
    nfct_close(handle);
}

/**
 * Start threads required for save mode of operation.
 *
 * Following things are performed in the save mode:
 * 1. Conntrack delete thread is started which waits till Clear IPC is
 *    called. The thread is started in both IP and zone sub-modes; it
 *    dispatches on ct_del_args.kind when it wakes up.
 * 2. Conntrack events threads are started to filter events for the
 *    migration targets. In IP mode this is two BPF-filtered threads
 *    (one src, one dst). In zone mode BPF can't filter on CT zone, so a
 *    single unfiltered thread is started and the callback does the zone
 *    match in-process.
 *    If any update is received for a non-existent entry, it is treated
 *    as NEW since it contains the base five tuple information required to
 *    identify flow. Similarly, if a destroy event is received for a
 *    non-existent entry, it is ignored.
 * 3. Finally, Conntrack dump is taken from the kernel to get all the live
 *    flows in the system.
 *
 * The above workflow is used to maintain a local copy of the CT entries for
 * the VM.
 *
 * Args:
 *   @targets SAVE targets bundle (mode-aware) for which CT entries have
 *            to be migrated.
 *   @stop_flag flag used by thread to exit after dbus operations.
 *
 * Returns:
 *   0 in case of success, -1 otherwise
 */
static int
start_in_save_mode(struct save_targets *targets, bool *stop_flag)
{
    int ret;
    struct ct_events_targs *src_targs, *dst_targs, *zone_targs;

    if (targets->kind == SAVE_INPUT_IPS) {
        uint32_t num_ips;

        // Start the delete thread.
        // NOTE: ct_del_args is an extern global variable
        ct_del_args.kind         = SAVE_INPUT_IPS;
        ct_del_args.ips_migrated = targets->ips_to_migrate;

        num_ips = g_hash_table_size(targets->ips_to_migrate);

        // This happens in case a VM has no IPv4 NICs attached to it. Thus,
        // the VM will not have any CT entries present in kernel to migrate.
        // Also, since QEMU expects helper process to be present during
        // migration, we do not exit the process completely rather just runs
        // the dbus server to facilitate the IPC calls.
        if (num_ips == 0) {
            LOG(INFO, "%s: Not starting any save mode threads since number "
                "of IP addresses is 0", __func__);
            return 0;
        }

        if (num_ips > MAX_IP_ADDRESSES_SUPPORTED) {
            LOG(WARNING, "Number of IP addresses exceeds the max limit: %d. "
                "No Conntrack Migration will be performed.",
                MAX_IP_ADDRESSES_SUPPORTED);
            return 0;
        }

        // Conntrack delete thread.
        ret = pthread_create(&ct_del_args.tid, NULL,
                             &delete_ct_entries,
                             (void *)&ct_del_args);
        if (ret != 0) {
            LOG(ERROR, "%s: CT delete thread creation failed. %s", __func__,
                strerror(ret));
            return -1;
        }
        ret = pthread_setname_np(ct_del_args.tid, "ct_delete");
        if (ret != 0) {
            LOG(WARNING, "%s: Failed to set thread name \"ct_delete\": %s",
                __func__, strerror(ret));
        }

        // Listen for conntrack events which contains their src IP address
        // in ips_to_migrate.
        src_targs = g_malloc0(sizeof(struct ct_events_targs));
        src_targs->targets = targets;
        src_targs->stop_flag = stop_flag;
        src_targs->is_src = true;
        ret = pthread_create(&src_targs->tid, NULL, &pthread_wrapper_ct_events,
                             (void *)src_targs);
        if (ret != 0) {
            LOG(ERROR, "%s: src events thread creation failed. %s", __func__,
                strerror(ret));
            return -1;
        }
        ret = pthread_setname_np(src_targs->tid, "ct_events_src");
        if (ret != 0) {
            LOG(WARNING, "%s: Failed to set thread name \"ct_events_src\". %s",
                __func__, strerror(ret));
        }

        // Listen for conntrack events which contains their dst IP address
        // in ips_to_migrate.
        dst_targs = g_malloc0(sizeof(struct ct_events_targs));
        dst_targs->targets = targets;
        dst_targs->stop_flag = stop_flag;
        dst_targs->is_src = false;
        ret = pthread_create(&dst_targs->tid, NULL,
                             &pthread_wrapper_ct_events,
                             (void *)dst_targs);
        if (ret != 0) {
            LOG(ERROR, "%s: dst events thread creation failed. %s", __func__,
                strerror(ret));
            return -1;
        }
        ret = pthread_setname_np(dst_targs->tid, "ct_events_dst");
        if (ret != 0) {
            LOG(WARNING, "%s: Failed to set thread name \"ct_events_dst\". %s",
                __func__, strerror(ret));
        }

        // Get all the conntrack entries for the given ip address.
        dump_conntrack(targets);

        // Wait for all the threads to be stopped.
        pthread_join(src_targs->tid, NULL);
        pthread_join(dst_targs->tid, NULL);
        pthread_join(ct_del_args.tid, NULL);

        g_free(src_targs);
        g_free(dst_targs);

    } else {

         /* SAVE_INPUT_PORT_ZONES */
        uint32_t num_zones = g_hash_table_size(targets->zones_to_migrate);

        if (num_zones == 0) {
            LOG(INFO, "%s: Not starting any save mode threads since number "
                "of zones is 0", __func__);
            return 0;
        }

        // Wire up the delete-thread state for zone mode.
        // NOTE: ct_del_args is an extern global variable
        ct_del_args.kind           = SAVE_INPUT_PORT_ZONES;
        ct_del_args.zones_migrated = targets->zones_to_migrate;

        // Conntrack delete thread (mode-aware: dispatches on
        // ct_del_args.kind when on_clear wakes it up).
        ret = pthread_create(&ct_del_args.tid, NULL,
                             &delete_ct_entries,
                             (void *)&ct_del_args);
        if (ret != 0) {
            LOG(ERROR, "%s: CT delete thread creation failed. %s", __func__,
                strerror(ret));
            return -1;
        }
        ret = pthread_setname_np(ct_del_args.tid, "ct_delete");
        if (ret != 0) {
            LOG(WARNING, "%s: Failed to set thread name \"ct_delete\": %s",
                __func__, strerror(ret));
        }

        // BPF can't filter on CT zone, so we don't split src/dst threads.
        // One unfiltered events thread is enough; the callback does the
        // zone match in-process.
        zone_targs = g_malloc0(sizeof(struct ct_events_targs));
        zone_targs->targets = targets;
        zone_targs->stop_flag = stop_flag;
        zone_targs->is_src = false;   /* unused in zone mode */
        ret = pthread_create(&zone_targs->tid, NULL,
                             &pthread_wrapper_ct_events,
                             (void *)zone_targs);
        if (ret != 0) {
            LOG(ERROR, "%s: zone events thread creation failed. %s", __func__,
                strerror(ret));
            return -1;
        }
        ret = pthread_setname_np(zone_targs->tid, "ct_events_zone");
        if (ret != 0) {
            LOG(WARNING, "%s: Failed to set thread name \"ct_events_zone\". "
                "%s", __func__, strerror(ret));
        }

        // Get all the conntrack entries for the given zones.
        dump_conntrack(targets);

        // Wait for the events thread, then the delete thread. Same order
        // as the IP branch above.
        pthread_join(zone_targs->tid, NULL);
        pthread_join(ct_del_args.tid, NULL);

        g_free(zone_targs);

    }

    return 0;
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
create_ips_ht_from_args(char *argv[], int num_ips)
{
    GHashTable *ht;
    const char **ips = (const char **)(argv + IP_ADDR_LIST_ARG_INDEX);

    ht = create_hashtable_from_ip_list(ips, num_ips);
    if (ht == NULL) {
        LOG(ERROR, "%s: Hashtable creation failed.", __func__);
        return NULL;
    }

    return ht;
}

/**
 * Creates the zones_to_migrate hashtable from the SAVE port-zone CLI
 * arguments.
 *
 * Walks argv at the SAVE_PORT_ZONE_STRIDE-strided offsets, extracts the
 * old_ct_zone column (the port_uuid column has already been validated
 * pre-fork by check_zone_save_args and is otherwise discarded - the
 * delete path filters strictly on CT zone), and hands the array to
 * create_hashtable_from_zone_list().
 *
 * Args:
 *   @argv      array of CLI args.
 *   @n_entries declared entry count from cli_mode_config.num_entries
 *              (already validated by check_zone_save_args pre-fork).
 *
 * Returns:
 *   zones_to_migrate hashtable on success, NULL on failure.
 */
static GHashTable *
create_zones_ht_from_args(char *argv[], int n_entries)
{
    int i;
    const char **zones;
    GHashTable *ht;

    zones = g_malloc0(sizeof(*zones) * n_entries);
    for (i = 0; i < n_entries; i++) {
        int port_uuid_index =
            ENTRIES_LIST_START_ARG_INDEX + (i * SAVE_PORT_ZONE_STRIDE);
        int zone_index = port_uuid_index + 1;
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
 * Decides which SAVE-mode CLI layout we are looking at by comparing the
 * number of trailing argv slots against the declared entry count N:
 *
 *   ratio = (argc - ENTRIES_LIST_START_ARG_INDEX) / N
 *     ratio == 1 -> SAVE_INPUT_IPS         (one IP per entry)
 *     ratio == 2 -> SAVE_INPUT_PORT_ZONES  (port_uuid + old_zone per entry)
 *
 * The "no list / N == 0" cases default to SAVE_INPUT_IPS so the existing
 * "VM with no IPv4 NICs" passthrough in start_in_save_mode() stays intact.
 *
 * Called once pre-fork from check_save_mode_args(); the detected kind
 * and declared N are recorded on cli_mode_config and read by dmain()
 * after the double fork rather than re-detected.
 *
 * Args:
 *   @argc           num of CLI arguments.
 *   @argv           array of CLI arguments.
 *   @out_n_entries  output for the declared entry count. Set to 0 on the
 *                   "no list" shortcut so the caller can record it on
 *                   cli_mode_config without an extra parse of argv[3].
 *
 * Returns:
 *   The detected sub-mode. Aborts the process via errx() on a shape
 *   mismatch (declared N is non-zero but trailing args fit neither layout).
 */
static enum save_input_kind
detect_save_input_kind(int argc, char *argv[], int *out_n_entries)
{
    int n;
    int remaining;

    if (argc <= ENTRIES_LIST_START_ARG_INDEX) {
        *out_n_entries = 0;
        return SAVE_INPUT_IPS;
    }

    ensure_cli_arg_is_int_at_least(argv[NUM_ENTRIES_ARG_INDEX], &n,
                                   "num_entries",
                                   MIN_ACCEPTABLE_VALUE_FOR_NUM_ENTRIES);
    *out_n_entries = n;

    remaining = argc - ENTRIES_LIST_START_ARG_INDEX;

    if (remaining == n) {
        return SAVE_INPUT_IPS;
    }
    if (remaining == n * SAVE_PORT_ZONE_STRIDE) {
        return SAVE_INPUT_PORT_ZONES;
    }

    errx(EXIT_FAILURE,
         "SAVE mode: argv shape mismatch. N=%d, expected %d args (IP form) "
         "or %d args (port-zone form), got %d.",
         n, n * 1, n * SAVE_PORT_ZONE_STRIDE, remaining);
}

/**
 * Decides which LOAD-mode CLI layout we are looking at.
 *
 * Legacy LOAD is strictly: `conntrack_migrator 1 <helper_id>` (argc == 3).
 * New LOAD is:             `conntrack_migrator 1 <helper_id> <N>
 *                              <port_uuid> <old_ct_zone> <new_ct_zone> ...`
 *                          (argc == 4 + 3*N).
 *
 * Anything else is a hard error - we deliberately do NOT silently fall back
 * to legacy if the trailing args do not match the new shape.
 *
 * Called once pre-fork from check_load_mode_args(); the detected kind
 * and declared N are recorded on cli_mode_config and read by dmain()
 * after the double fork rather than re-detected (mirroring
 * detect_save_input_kind above).
 *
 * Args:
 *   @argc           num of CLI arguments.
 *   @argv           array of CLI arguments.
 *   @out_n_entries  output for the declared entry count. Set to 0 on the
 *                   legacy shortcut so the caller can record it on
 *                   cli_mode_config without an extra parse of argv[3].
 *
 * Returns:
 *   The detected sub-mode. Aborts the process via errx() on any mismatch.
 */
static enum load_input_kind
detect_load_input_kind(int argc, char *argv[], int *out_n_entries)
{
    int n;
    int remaining;

    if (argc == HELPER_ID_ARG_INDEX + 1) {   /* argc == 3: legacy LOAD */
        *out_n_entries = 0;
        return LOAD_INPUT_LEGACY;
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
        return LOAD_INPUT_PORT_ZONES;
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
 * Entry point for the daemon.
 *
 * Args:
 *   @argc num of arguments to the application.
 *   @argv string argument list.
 *   @cli  parsed CLI bundle populated by check_args() before the
 *         daemon was forked. Mode, sub-kind, and num_entries are read
 *         directly from here instead of re-walking argv. fork() copies
 *         the entire address space (including the parent's stack frame),
 *         so the pointer is valid in the grandchild.
 *
 * Returns:
 *   0 if the daemon exits without any error. otherwise the specific error
 *   code is returned.
 */
static int
dmain(int argc, char *argv[], const struct cli_mode_config *cli)
{
    const char *helper_id;
    int ret;
    int rc = 0;
    bool stop_flag = false;
    bool log_open = false;
    bool dbus_started = false;
    bool loop_mu_inited = false;
    struct dbus_targs dbus_server_args = {0};
    struct save_targets *save_targets = NULL;

    (void) argc;

    helper_id = argv[HELPER_ID_ARG_INDEX];

    // Initialise logging at default INFO level.
    ret = init_log(INFO, helper_id);
    if (ret != 0) {
        return EAGAIN;   // nothing else allocated yet
    }
    log_open = true;

    // Init configs.
    init_lmct_config(lmct_config_path);

    // set the logging level read from config.
    set_log_level(lmct_conf.log_lvl);

    LOG(INFO, "%s: Starting in mode %s", __func__,
        mode_to_string[cli->mode]);
    LOG(INFO, "%s: dbus address %s", __func__,
        getenv("DBUS_SYSTEM_BUS_ADDRESS"));
    LOG(INFO, "%s: helper id: %s", __func__, helper_id);
    LOG(INFO, "%s: Maximum CT entries migratable: %d", __func__,
        lmct_conf.max_entries_to_migrate);

    // Initialise globals.
    conn_store = conntrack_store_new();
    if (conn_store == NULL) {
        LOG(ERROR, "%s: connection_store is NULL", __func__);
        rc = EAGAIN;
        goto cleanup;
    }

    // Start the dbus server
    dbus_server_args.helper_id    = helper_id;
    dbus_server_args.stop_flag    = &stop_flag;
    dbus_server_args.mode         = cli->mode;
    dbus_server_args.load_targets = NULL;
    dbus_server_args.loop         = NULL;
    dbus_server_args.should_quit  = false;
    ret = pthread_mutex_init(&dbus_server_args.loop_mu, NULL);
    if (ret != 0) {
        LOG(ERROR, "%s: failed to init loop_mu: %s", __func__, strerror(ret));
        rc = EAGAIN;
        goto cleanup;
    }
    loop_mu_inited = true;

    /* In LOAD mode build the (old_zone -> new_zone) remap up-front so the
     * dbus thread has it ready by the time the destination's Load IPC
     * arrives. SAVE mode leaves load_targets NULL. */
    if (cli->mode == LOAD_MODE) {
        if (cli->load_kind == LOAD_INPUT_LEGACY) {
            dbus_server_args.load_targets = load_targets_new_ips();
            LOG(INFO, "%s: LOAD legacy mode (no zone rewrite)", __func__);
        } else {
            dbus_server_args.load_targets =
                load_targets_new_from_zone_args(cli->num_entries, argv,
                                                ENTRIES_LIST_START_ARG_INDEX,
                                                LOAD_PORT_ZONE_STRIDE);
            if (dbus_server_args.load_targets == NULL) {
                LOG(ERROR, "%s: failed to build load_targets", __func__);
                rc = EINVAL;
                goto cleanup;
            }
            LOG(INFO, "%s: LOAD port-zones mode, %d remap entries",
                __func__, cli->num_entries);
        }
    }

    ret = pthread_create(&dbus_server_args.tid,
                         NULL, dbus_server_init,
                         &dbus_server_args);
    if (ret != 0) {
        LOG(ERROR, "%s: dbus_server thread creation failed. %s", __func__,
            strerror(ret));
        rc = EAGAIN;
        goto cleanup;
    }
    dbus_started = true;
    ret = pthread_setname_np(dbus_server_args.tid, "dbus_server");
    if (ret != 0) {
        LOG(WARNING, "%s: Failed to set thread name \"dbus_server\". %s",
            __func__, strerror(ret));
    }

    // Start save mode threads.
    if (cli->mode == SAVE_MODE) {
        if (cli->save_kind == SAVE_INPUT_IPS) {
            GHashTable *ips_to_migrate;
            ips_to_migrate = create_ips_ht_from_args(argv, cli->num_entries);
            if (ips_to_migrate == NULL) {
                rc = EINVAL;
                goto cleanup;
            }
            save_targets = save_targets_new_from_ips(ips_to_migrate);
        } else {
            GHashTable *zones_ht =
                create_zones_ht_from_args(argv, cli->num_entries);
            if (zones_ht == NULL) {
                rc = EINVAL;
                goto cleanup;
            }
            save_targets = save_targets_new_from_zones(zones_ht);
        }

        ret = start_in_save_mode(save_targets, &stop_flag);
        if (ret != 0) {
            rc = EAGAIN;
            /* start_in_save_mode may have left events threads running
             * that still reference save_targets (a pre-existing issue
             * tracked separately). Don't destroy save_targets in that
             * case -- a small intentional leak on the abnormal-exit
             * path is preferable to a use-after-free. */
            save_targets = NULL;
        }
    }

cleanup:
    /* Tell any still-running events threads to exit. start_in_save_mode
     * normally joins them itself, but we set this defensively to cover
     * partial-failure paths that leave the events threads alive. */
    stop_flag = true;

    /* Wake the dbus thread on every error path so pthread_join below
     * doesn't hang waiting for an RPC that will never arrive. On the
     * normal success path the loop has already quit itself (via
     * on_save -> ... -> on_clear -> g_main_loop_quit for SAVE, and
     * on_load -> g_main_loop_quit for LOAD), so request_quit is a no-op
     * there. */
    if (dbus_started) {
        if (rc != 0) {
            dbus_server_request_quit(&dbus_server_args);
        }
        pthread_join(dbus_server_args.tid, NULL);
    }
    if (save_targets != NULL) {
        save_targets_destroy(save_targets);
    }
    if (dbus_server_args.load_targets != NULL) {
        load_targets_destroy(dbus_server_args.load_targets);
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
check_ip_save_args(int argc, char *argv[])
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
 * Per-entry content checks for the new SAVE port-zone layout.
 *
 * Arity (argc vs declared N) is guaranteed by detect_save_input_kind()
 * before we get here, so we only validate the *content* of each entry:
 *  - port_uuid is a port-prefixed canonical UUID of the form
 *    "port_<8-4-4-4-12>" (total length 41),
 *  - old_ct_zone parses cleanly as uint16.
 *
 * Aborts the process via errx() on the first malformed entry.
 *
 * Args:
 *   @argc num of arguments (used only for an arity sanity check).
 *   @argv array of CLI arguments.
 */
static void
check_zone_save_args(int argc, char *argv[])
{
    int n;
    int i;

    (void) argc;

    ensure_cli_arg_is_int_at_least(argv[NUM_ENTRIES_ARG_INDEX], &n,
                                   "num_entries",
                                   MIN_ACCEPTABLE_VALUE_FOR_NUM_ENTRIES);

    for (i = 0; i < n; i++) {
        int base = ENTRIES_LIST_START_ARG_INDEX + (i * SAVE_PORT_ZONE_STRIDE);
        const char *port_uuid = argv[base];
        const char *zone_str  = argv[base + 1];
        uint16_t zone_val;

        if (!is_valid_uuid_string(port_uuid)) {
            errx(EXIT_FAILURE,
                 "Invalid UUID at port-zone entry %d: '%s'",
                 i, port_uuid);
        }
        if (!parse_ct_zone(zone_str, &zone_val)) {
            errx(EXIT_FAILURE,
                 "Invalid old_ct_zone at port-zone entry %d: '%s' "
                 "(must be uint16)", i, zone_str);
        }
    }
}

/**
 * Per-entry content checks for the new LOAD port-zone layout.
 *
 * Arity is guaranteed by detect_load_input_kind(); we only validate the
 * content of each (port_uuid, old_ct_zone, new_ct_zone) triple.
 *
 * Args:
 *   @argc num of arguments (used only for an arity sanity check).
 *   @argv array of CLI arguments.
 */
static void
check_zone_load_args(int argc, char *argv[])
{
    int n;
    int i;

    (void) argc;

    ensure_cli_arg_is_int_at_least(argv[NUM_ENTRIES_ARG_INDEX], &n,
                                   "num_entries",
                                   MIN_ACCEPTABLE_VALUE_FOR_NUM_ENTRIES);

    for (i = 0; i < n; i++) {
        int base = ENTRIES_LIST_START_ARG_INDEX + (i * LOAD_PORT_ZONE_STRIDE);
        const char *port_uuid    = argv[base];
        const char *old_zone_str = argv[base + 1];
        const char *new_zone_str = argv[base + 2];
        uint16_t z;

        if (!is_valid_uuid_string(port_uuid)) {
            errx(EXIT_FAILURE,
                 "Invalid UUID at port-zone entry %d: '%s'",
                 i, port_uuid);
        }
        if (!parse_ct_zone(old_zone_str, &z)) {
            errx(EXIT_FAILURE,
                 "Invalid old_ct_zone at port-zone entry %d: '%s'",
                 i, old_zone_str);
        }
        if (!parse_ct_zone(new_zone_str, &z)) {
            errx(EXIT_FAILURE,
                 "Invalid new_ct_zone at port-zone entry %d: '%s'",
                 i, new_zone_str);
        }
    }
}

/**
 * Top-level SAVE-mode arg dispatcher.
 *
 * Picks IP vs port-zone via detect_save_input_kind() and delegates
 * per-entry validation to the appropriate validator. Reports the
 * detected sub-kind and the declared entry count to the caller so they
 * can be recorded on cli_mode_config without an extra argv parse.
 *
 * Args:
 *   @argc          num of arguments.
 *   @argv          array of CLI arguments.
 *   @out_kind      output pointer for the detected sub-kind. May be NULL.
 *   @out_n_entries output pointer for the declared entry count, captured
 *                  from detect_save_input_kind's existing parse. May be
 *                  NULL. 0 on the SAVE-IP "no list" shortcut.
 */
static void
check_save_mode_args(int argc, char *argv[],
                     enum save_input_kind *out_kind,
                     int *out_n_entries)
{
    int n_entries = 0;
    enum save_input_kind kind =
        detect_save_input_kind(argc, argv, &n_entries);

    if (kind == SAVE_INPUT_IPS) {
        check_ip_save_args(argc, argv);
    } else {
        if (kind == SAVE_INPUT_PORT_ZONES) {
            check_zone_save_args(argc, argv);
        } else {
            errx(EXIT_FAILURE, "Invalid save input kind: %d", kind);
        }
    }

    if (out_kind != NULL) {
        *out_kind = kind;
    }
    if (out_n_entries != NULL) {
        *out_n_entries = n_entries;
    }
}

/**
 * Top-level LOAD-mode arg dispatcher.
 *
 * Legacy LOAD takes no extra args beyond <mode> <helper_id>; the new LOAD
 * port-zone layout is content-validated. Reports the detected sub-kind
 * and the declared entry count to the caller so they can be recorded on
 * cli_mode_config without an extra argv parse.
 *
 * Args:
 *   @argc          num of arguments.
 *   @argv          array of CLI arguments.
 *   @out_kind      output pointer for the detected sub-kind. May be NULL.
 *   @out_n_entries output pointer for the declared entry count, captured
 *                  from detect_load_input_kind's existing parse. May be
 *                  NULL. 0 on the LOAD legacy shortcut.
 */
static void
check_load_mode_args(int argc, char *argv[],
                     enum load_input_kind *out_kind,
                     int *out_n_entries)
{
    int n_entries = 0;
    enum load_input_kind kind =
        detect_load_input_kind(argc, argv, &n_entries);

    if (kind == LOAD_INPUT_PORT_ZONES) {
        check_zone_load_args(argc, argv);
    } else {
        if (kind != LOAD_INPUT_LEGACY) {
            errx(EXIT_FAILURE, "Invalid load input kind: %d", kind);
        }
    }

    if (out_kind != NULL) {
        *out_kind = kind;
    }
    if (out_n_entries != NULL) {
        *out_n_entries = n_entries;
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
 * On success populates @out with the validated (mode, sub-kind) pair.
 * On any failure errx() exits the process.
 *
 * Args:
 *   @argc num of arguments.
 *   @argv array of CLI arguments.
 *   @out  output struct populated with the parse result. Must be non-NULL.
 */
static void
check_args(int argc, char *argv[], struct cli_mode_config *out)
{
    int mode;

    if (argc < 3) {
        err_usage();
    }

    check_dbus_address_env();

    ensure_cli_arg_is_int_at_least(argv[MODE_ARG_INDEX], &mode, "mode",
                                   MIN_ACCEPTABLE_VALUE_FOR_MODE);
    check_mode(mode);
    out->mode = (enum op_mode) mode;

    /* num_entries is populated by the mode-specific dispatcher, which
     * in turn picks it up from detect_*_input_kind's existing parse -
     * no second call to ensure_cli_arg_is_int_at_least on argv[3]. */
    if (mode == SAVE_MODE) {
        check_save_mode_args(argc, argv, &out->save_kind,
                             &out->num_entries);
    } else {
        check_load_mode_args(argc, argv, &out->load_kind,
                             &out->num_entries);
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

    /* Validate CLI args + decide IP-vs-zone sub-kind before any forks.
     * fork() preserves the parent's address space (copy-on-write of
     * the entire AS, including this stack frame), so `cli` is still
     * readable in the grandchild and is passed directly to dmain()
     * rather than being re-parsed there. */
    check_args(argc, argv, &cli);

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
            ret = dmain(argc, argv, &cli);
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

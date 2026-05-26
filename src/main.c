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
 * Result of CLI parsing - filled by check_args() and consumed by main().
 *
 * The sub-kind field is a tagged union: the active arm is determined by
 * @mode (SAVE_MODE -> save_kind, LOAD_MODE -> load_kind).
 */
struct parsed_cli {
    enum op_mode mode;
    union {
        enum save_input_kind save_kind;
        enum load_input_kind load_kind;
    };
};

const char *lmct_config_path = "/etc/lmct_config";

// Mode number to string
const char *mode_to_string[] = {
    [LOAD_MODE] = "LOAD",
    [SAVE_MODE] = "SAVE"
};

struct ct_delete_args ct_del_args = {
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
 * 1. (IP mode only) Conntrack delete thread is started which waits till
 *    Clear IPC is called.
 * 2. Conntrack events threads are started to filter events for the
 *    migration targets. In IP mode this is two BPF-filtered threads
 *    (one src, one dst). In zone mode BPF can't filter on CT zone, so a
 *    single unfiltered thread is started and the callback does the zone
 *    match in-process.
 *    If any update is received for a non-exisitent entry, it is treated
 *    as NEW since it contains the base five tuple information required to
 *    identify flow. Similarly, if a destroy event is received for a
 *    non-existent entry, it is ignored.
 * 3. Finally, Conntrack dump is taken from the kernel to get all the live
 *    flows in the system.
 *
 * The above workflow is used to maintain a local copy of the CT entries for
 * the VM.
 *
 * NOTE: zone-mode cleanup (Clear/delete) is deferred to Step 3; the zone
 * branch deliberately does not start the delete thread.
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

        return 0;
    }

    /* SAVE_INPUT_PORT_ZONES */
    {
        uint32_t num_zones = g_hash_table_size(targets->zones_to_migrate);

        if (num_zones == 0) {
            LOG(INFO, "%s: Not starting any save mode threads since number "
                "of zones is 0", __func__);
            return 0;
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

        // Wait for the events thread to be stopped. Zone-mode cleanup
        // (Clear/delete) is deferred to Step 3; no delete thread to join.
        pthread_join(zone_targs->tid, NULL);

        g_free(zone_targs);

        return 0;
    }
}

/**
 * Creates hashtable of IP addresses from CLI arguments.
 *
 * Args:
 *   @argv array of CLI args.
 *
 * Returns:
 *   Resulting hashtable containing IP address(uint32_t) as key.
 */
static GHashTable *
create_ips_ht_from_args(char *argv[])
{
    int num_ips;
    GHashTable *ht;

    num_ips = atoi(argv[NUM_IP_ADDR_ARG_INDEX]);
    const char **ips = (const char **)(argv + IP_ADDR_LIST_ARG_INDEX);

    ht = create_hashtable_from_ip_list(ips, num_ips);
    if (ht == NULL) {
        LOG(ERROR, "%s: Hashtable creation failed.", __func__);
        return NULL;
    }

    return ht;
}

/**
 * Creates the (zones_to_migrate, ports_to_migrate) hashtable pair from the
 * SAVE port-zone CLI arguments.
 *
 * Walks argv at the SAVE_PORT_ZONE_STRIDE-strided offsets, splits out the
 * port_uuid and old_ct_zone columns, and hands the parallel arrays to
 * create_hashtable_from_zone_and_port_list().
 *
 * Args:
 *   @argv      array of CLI args.
 *   @out_ports output: ports_to_migrate hashtable.
 *
 * Returns:
 *   zones_to_migrate hashtable on success, NULL on failure (in which case
 *   *out_ports is left set to NULL).
 */
static GHashTable *
create_zones_and_port_ht_from_args(char *argv[], GHashTable **out_ports)
{
    int n_entries;
    int i;
    const char **zones;
    const char **port_uuids;
    GHashTable *ht;

    n_entries = atoi(argv[NUM_ENTRIES_ARG_INDEX]);
    zones = g_malloc0(sizeof(*zones) * n_entries);
    port_uuids = g_malloc0(sizeof(*port_uuids) * n_entries);
    for (i = 0; i < n_entries; i++) {
        int base = ENTRIES_LIST_START_ARG_INDEX + (i * SAVE_PORT_ZONE_STRIDE);
        port_uuids[i] = argv[base];
        zones[i] = argv[base + 1];
    }

    ht = create_hashtable_from_zone_and_port_list(zones, port_uuids,
                                                  n_entries, out_ports);
    g_free(zones);
    g_free(port_uuids);

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
 * NOTE: this lives in the runtime (post-fork) section of the file, above
 * dmain(), because dmain re-runs the detection after the double fork to
 * recover the SAVE sub-kind without threading it through a new parameter.
 * The pre-fork validator block below uses the same function for shape
 * checking; we deliberately keep one definition shared by both call sites.
 *
 * Args:
 *   @argc num of CLI arguments.
 *   @argv array of CLI arguments.
 *
 * Returns:
 *   The detected sub-mode. Aborts the process via errx() on a shape
 *   mismatch (declared N is non-zero but trailing args fit neither layout).
 */
static enum save_input_kind
detect_save_input_kind(int argc, char *argv[])
{
    int n;
    int remaining;

    if (argc <= ENTRIES_LIST_START_ARG_INDEX) {
        return SAVE_INPUT_IPS;
    }

    n = atoi(argv[NUM_ENTRIES_ARG_INDEX]);
    if (n <= 0) {
        return SAVE_INPUT_IPS;
    }

    remaining = argc - ENTRIES_LIST_START_ARG_INDEX;

    if (remaining == n * 1) {
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
 * NOTE: this lives in the runtime (post-fork) section of the file, above
 * dmain(), because dmain re-runs the detection after the double fork to
 * recover the LOAD sub-kind without threading it through a new parameter.
 * The pre-fork validator block below uses the same function for shape
 * checking; we deliberately keep one definition shared by both call sites
 * (mirroring detect_save_input_kind above).
 *
 * Args:
 *   @argc num of CLI arguments.
 *   @argv array of CLI arguments.
 *
 * Returns:
 *   The detected sub-mode. Aborts the process via errx() on any mismatch.
 */
static enum load_input_kind
detect_load_input_kind(int argc, char *argv[])
{
    int n;
    int remaining;

    if (argc == HELPER_ID_ARG_INDEX + 1) {   /* argc == 3: legacy LOAD */
        return LOAD_INPUT_LEGACY;
    }

    if (argc <= ENTRIES_LIST_START_ARG_INDEX) {
        errx(EXIT_FAILURE,
             "LOAD mode: trailing args present but no port-zone list. "
             "Expected `conntrack_migrator 1 <helper_id>` or "
             "`conntrack_migrator 1 <helper_id> <N> "
             "<port_uuid> <old_zone> <new_zone> ...`.");
    }

    n = atoi(argv[NUM_ENTRIES_ARG_INDEX]);
    if (n <= 0) {
        errx(EXIT_FAILURE,
             "LOAD mode: invalid number of port-zone entries: '%s' "
             "(must be a positive integer).",
             argv[NUM_ENTRIES_ARG_INDEX]);
    }

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
 * Entry point for the daemon.
 *
 * Args:
 *   @argc num of arguments to the application
 *   @argv string argument list
 *
 * Returns:
 *   0 if the daemon exits without any error. otherwise the specific error
 *   code is returned.
 */
static int
dmain(int argc, char *argv[])
{
    int mode;
    const char *helper_id;
    int ret;
    bool stop_flag = false;
    struct dbus_targs dbus_server_args;
    enum save_input_kind save_kind = SAVE_INPUT_IPS;

    // Parse the command line arguments.
    mode = atoi(argv[MODE_ARG_INDEX]);
    helper_id = argv[HELPER_ID_ARG_INDEX];

    // Re-detect the SAVE sub-kind here because the parent's parsed_cli
    // lived on a stack frame that is gone after the double fork. argv
    // is preserved across forks, so detection is cheap and side-effect-free.
    if (mode == SAVE_MODE) {
        save_kind = detect_save_input_kind(argc, argv);
    }

    // Initialise logging at default INFO level.
    ret = init_log(INFO, helper_id);
    if (ret != 0) {
        return EAGAIN;
    }

    // Init configs.
    init_lmct_config(lmct_config_path);

    // set the logging level read from config.
    set_log_level(lmct_conf.log_lvl);

    LOG(INFO, "%s: Starting in mode %s", __func__, mode_to_string[mode]);
    LOG(INFO, "%s: dbus address %s", __func__,
        getenv("DBUS_SYSTEM_BUS_ADDRESS"));
    LOG(INFO, "%s: helper id: %s", __func__, helper_id);
    LOG(INFO, "%s: Maximum CT entries migratable: %d", __func__,
        lmct_conf.max_entries_to_migrate);

    // Initialise globals.
    conn_store = conntrack_store_new();
    if (conn_store == NULL) {
        LOG(ERROR, "%s: connection_store is NULL", __func__);
        return EAGAIN;
    }

    // Start the dbus server
    dbus_server_args.helper_id    = helper_id;
    dbus_server_args.stop_flag    = &stop_flag;
    dbus_server_args.mode         = (enum op_mode) mode;
    dbus_server_args.load_targets = NULL;

    /* In LOAD mode build the (old_zone -> new_zone) remap up-front so the
     * dbus thread has it ready by the time the destination's Load IPC
     * arrives. SAVE mode leaves load_targets NULL. */
    if (mode == LOAD_MODE) {
        enum load_input_kind load_kind = detect_load_input_kind(argc, argv);

        if (load_kind == LOAD_INPUT_LEGACY) {
            dbus_server_args.load_targets = load_targets_new_ips();
            LOG(INFO, "%s: LOAD legacy mode (no zone rewrite)", __func__);
        } else {
            int n = atoi(argv[NUM_ENTRIES_ARG_INDEX]);
            dbus_server_args.load_targets =
                load_targets_new_from_zone_args(n, argv,
                                                ENTRIES_LIST_START_ARG_INDEX,
                                                LOAD_PORT_ZONE_STRIDE);
            if (dbus_server_args.load_targets == NULL) {
                LOG(ERROR, "%s: failed to build load_targets", __func__);
                return EINVAL;
            }
            LOG(INFO, "%s: LOAD port-zones mode, %d remap entries",
                __func__, n);
        }
    }

    ret = pthread_create(&dbus_server_args.tid,
                         NULL, dbus_server_init,
                         &dbus_server_args);
    if (ret != 0) {
        LOG(ERROR, "%s: dbus_server thread creation failed. %s", __func__,
            strerror(ret));
        return EAGAIN;
    }
    ret = pthread_setname_np(dbus_server_args.tid, "dbus_server");
    if (ret != 0) {
        LOG(WARNING, "%s: Failed to set thread name \"dbus_server\". %s",
            __func__, strerror(ret));
    }

    // Start save mode threads.
    if (mode == SAVE_MODE) {
        struct save_targets *targets;

        if (save_kind == SAVE_INPUT_IPS) {
            GHashTable *ips_to_migrate;
            ips_to_migrate = create_ips_ht_from_args(argv);
            if (ips_to_migrate == NULL) {
                return EINVAL;
            }
            targets = save_targets_new_from_ips(ips_to_migrate);
        } else {
            GHashTable *zones_ht = NULL;
            GHashTable *ports_ht = NULL;
            zones_ht = create_zones_and_port_ht_from_args(argv, &ports_ht);
            if (zones_ht == NULL) {
                return EINVAL;
            }
            targets = save_targets_new_from_zones_and_ports(zones_ht,
                                                            ports_ht);
        }

        ret = start_in_save_mode(targets, &stop_flag);
        save_targets_destroy(targets);
        if (ret != 0) {
            return EAGAIN;
        }
    }

    pthread_join(dbus_server_args.tid, NULL);
    conntrack_store_destroy(conn_store);
    load_targets_destroy(dbus_server_args.load_targets);
    close_log();

    return 0;
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
 * Checks if the mode passed is either LOAD or SAVE.
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

    num_ip_addr = atoi(argv[NUM_IP_ADDR_ARG_INDEX]);
    if (num_ip_addr < 0 || num_ip_addr > (argc - IP_ADDR_LIST_ARG_INDEX)) {
        errx(EXIT_FAILURE, "Invalid argument for number of IP addresses");
    }
}

/**
 * Per-entry content checks for the new SAVE port-zone layout.
 *
 * Arity (argc vs declared N) is guaranteed by detect_save_input_kind()
 * before we get here, so we only validate the *content* of each entry:
 *  - port_uuid is a canonical 8-4-4-4-12 hex UUID,
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

    (void) argc;   /* arity already checked by the detector */

    n = atoi(argv[NUM_ENTRIES_ARG_INDEX]);

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

    n = atoi(argv[NUM_ENTRIES_ARG_INDEX]);

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
 * detected sub-kind to the caller via @out_kind.
 *
 * Args:
 *   @argc     num of arguments.
 *   @argv     array of CLI arguments.
 *   @out_kind output pointer for the detected sub-kind. May be NULL.
 */
static void
check_save_mode_args(int argc, char *argv[],
                     enum save_input_kind *out_kind)
{
    enum save_input_kind kind = detect_save_input_kind(argc, argv);

    if (kind == SAVE_INPUT_IPS) {
        check_ip_save_args(argc, argv);
    } else {
        if(kind == SAVE_INPUT_PORT_ZONES) {
            check_zone_save_args(argc, argv);
        } else {
            errx(EXIT_FAILURE, "Invalid save input kind: %d", kind);
        }
    }

    if (out_kind != NULL) {
        *out_kind = kind;
    }
}

/**
 * Top-level LOAD-mode arg dispatcher.
 *
 * Legacy LOAD takes no extra args beyond <mode> <helper_id>; the new LOAD
 * port-zone layout is content-validated. Reports the detected sub-kind
 * to the caller via @out_kind.
 *
 * Args:
 *   @argc     num of arguments.
 *   @argv     array of CLI arguments.
 *   @out_kind output pointer for the detected sub-kind. May be NULL.
 */
static void
check_load_mode_args(int argc, char *argv[],
                     enum load_input_kind *out_kind)
{
    enum load_input_kind kind = detect_load_input_kind(argc, argv);

    if (kind == LOAD_INPUT_PORT_ZONES) {
        check_zone_load_args(argc, argv);
    }else{
        if(kind != LOAD_INPUT_LEGACY) {
            errx(EXIT_FAILURE, "Invalid load input kind: %d", kind);
        }
    }

    if (out_kind != NULL) {
        *out_kind = kind;
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
check_args(int argc, char *argv[], struct parsed_cli *out)
{
    int mode;

    if (argc < 3) {
        err_usage();
    }

    check_dbus_address_env();

    mode = atoi(argv[MODE_ARG_INDEX]);
    check_mode(mode);
    out->mode = (enum op_mode) mode;

    if (mode == SAVE_MODE) {
        check_save_mode_args(argc, argv, &out->save_kind);
    } else {
        check_load_mode_args(argc, argv, &out->load_kind);
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
    struct parsed_cli cli = {0};

    // Validate CLI args + decide IP-vs-zone sub-kind before any forks.
    // The result is recomputed inside dmain() because the parent's stack
    // (and thus this `cli`) is gone by the time the grandchild runs.
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
            ret = dmain(argc, argv);
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

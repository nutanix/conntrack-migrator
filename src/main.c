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
 *  - SAVE mode: DBUS_SESSION_BUS_ADDRESS=<dbus address> conntrack_migrator 2 <dbus_helper_id> <num_ip_addresses> <space separated ip address list>
 *  - LOAD mode: DBUS_SESSION_BUS_ADDRESS=<dbus address> conntrack_migrator 1 <dbus_helper_id>
 *
 *  eg:
 *  - SAVE mode: DBUS_SESSION_BUS_ADDRESS=unix:abstract=/abc,guid=def conntrack_migrator 2 helper1 2 1.1.1.1 2.2.2.2
 *  - LOAD mode: DBUS_SESSION_BUS_ADDRESS=unix:abstract=/abc,guid=def conntrack_migrator 1 helper1
 */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <stdbool.h>
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

#define MODE_ARG_INDEX 1
#define HELPER_ID_ARG_INDEX 2
#define NUM_IP_ADDR_ARG_INDEX 3
#define IP_ADDR_LIST_ARG_INDEX 4
#define NUM_CT_ZONES_ARG_INDEX 4
#define CT_ZONES_LIST_ARG_INDEX 5

#define MAX_IP_ADDRESSES_SUPPORTED 127

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

    listen_for_conntrack_events(nl, targs);
    mnl_socket_close(nl);

    LOG(INFO, "%s: Finished conntrack events. is_src = %d", __func__,
        targs->is_src);

    return NULL;
}

/**
 * Gets all the entries present in the kernel CT table for the given IP
 * addresses.
 *
 * Args:
 *   @ips_to_migrate IP addresses used to filter the required CT entries.
 *   @ct_zones_to_migrate CT Zones used to filter the required CT entries.
 */
static void
dump_conntrack(struct ct_events_targs *ct_events_targs)
{
    struct nfct_handle *handle;

    // Set the subscriptions for this handle to 0 since we are going to
    // explicitly request dump on this socket.
    handle = nfct_open(CONNTRACK, 0);
    if (handle == NULL) {
        LOG(ERROR, "%s: nfct_open failed. %s", __func__, strerror(errno));
        return;
    }
    get_conntrack_dump(handle, ct_events_targs);
    nfct_close(handle);
}

/**
* Start threads required for save mode of operation when filter type is
* FILTER_BY_CT_ZONE.
*
* Following things are performed in the save mode:
* 1. Conntrack events threads are started to filter events for the CT
*    zones present in the ct_zones_to_migrate. If any update is received for a
*    non-exisitent entry, it is treated as NEW since it contains the base five
*    tuple information required to identify flow. Similarly, if a destroy
*    event is received for a non-existent entry, it is ignored.
* 2. Finally, Conntrack dump is taken from the kernel to get all the live
*    flows in the system.
*
* The above workflow is used to maintain a local copy of the CT entries for
* the VM.
*
* Args:
*   @ct_zones_to_migrate Hashtable of CT zones for which CT entries
*                   have to be migrated.
*   @stop_flag flag used by thread to exit after dbus operations.
*
* Returns:
*   0 in case of success, -1 otherwise
*/
static int
start_in_save_mode_for_ct_zones(GHashTable *ct_zones_to_migrate,
                                bool *stop_flag)
{
    int ret;
    uint32_t num_ct_zones;
    struct ct_events_targs *targs;

    num_ct_zones = g_hash_table_size(ct_zones_to_migrate);

    if (num_ct_zones == 0) {
        LOG(INFO, "%s: Not starting any save mode threads since number of"
            "ct-zones is 0", __func__);
        return 0;
    }

    targs = g_malloc0(sizeof(struct ct_events_targs));
    targs->ct_zones_to_migrate = ct_zones_to_migrate;
    targs->stop_flag = stop_flag;
    targs->is_src = true;
    ret = pthread_create(&targs->tid, NULL, &pthread_wrapper_ct_events,
                         (void *)targs);
    if (ret != 0) {
        LOG(ERROR, "%s: src events thread creation failed. %s", __func__,
            strerror(ret));
        return -1;
    }
    ret = pthread_setname_np(targs->tid, "ct_events_src");
    if (ret != 0) {
        LOG(WARNING, "%s: Failed to set thread name \"ct_events_src\". %s",
            __func__, strerror(ret));
    }

    dump_conntrack(targs);

    // Wait for all the threads to be stopped.
    pthread_join(targs->tid, NULL);

    g_free(targs);

    return 0;
}


/**
* Start threads required for save mode of operation when filter type is
* FILTER_BY_IP.
*
* Following things are performed in the save mode:
* 1. Conntrack delete thread is started which waits till Clear IPC is called.
* 2. Conntrack events threads are started to filter events for the IP
*    addresses present in the ips_to_migrate. If any update is received for a
*    non-exisitent entry, it is treated as NEW since it contains the base five
*    tuple information required to identify flow. Similarly, if a destroy
*    event is received for a non-existent entry, it is ignored.
* 3. Finally, Conntrack dump is taken from the kernel to get all the live
*    flows in the system.
*
* The above workflow is used to maintain a local copy of the CT entries for
* the VM.
*
* Args:
*   @ips_to_migrate Hashtable of IP addresses for which CT entries
*                   have to be migrated.
*   @stop_flag flag used by thread to exit after dbus operations.
*
* Returns:
*   0 in case of success, -1 otherwise
*/
static int
start_in_save_mode_for_ip(GHashTable *ips_to_migrate, bool *stop_flag)
{
    int ret;
    uint32_t num_ips;
    struct ct_events_targs *src_targs, *dst_targs;

    // Start the delete thread.
    // NOTE: ct_del_args is an extern global variable
    ct_del_args.ips_migrated = ips_to_migrate;

    num_ips = g_hash_table_size(ips_to_migrate);

    // This happens in case a VM has no IPv4 NICs attached to it. Thus, the VM
    // will not have any CT entries present in kernel to migrate. Also, since
    // QEMU expects helper process to be present during migration, we do not
    // exit the process completely rather just runs the dbus server to
    // facilitate the IPC calls.
    if (num_ips == 0) {
        LOG(INFO, "%s: Not starting any save mode threads since number of IP "
            "addresses is 0", __func__);
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
    src_targs->ips_to_migrate = ips_to_migrate;
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
    dst_targs->ips_to_migrate = ips_to_migrate;
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
    // Because ips_to_migrate is same in case of src/dst targs we can use any
    // one of them.
    dump_conntrack(src_targs);

    // Wait for all the threads to be stopped.
    pthread_join(src_targs->tid, NULL);
    pthread_join(dst_targs->tid, NULL);
    pthread_join(ct_del_args.tid, NULL);

    g_free(src_targs);
    g_free(dst_targs);

    return 0;
}

/**
 * Start threads required for save mode of operation.
 * The workflow is used to maintain a local copy of the CT entries for
 * the VM.
 *
 * Args:
 *   @ips_to_migrate Hashtable of IP addresses for which CT entries
 *                   have to be migrated.
 *   @ct_zones_to_migrate Hashtable of Ct zones for which CT entries have to be
 *                        migrated.
 *   @stop_flag flag used by thread to exit after dbus operations.
 *
 * Returns:
 *   0 in case of success, -1 otherwise
 */
static int
start_in_save_mode(GHashTable *ips_to_migrate, GHashTable *ct_zones_to_migrate,
                   bool *stop_flag)
{
    if ( fltr_type == FILTER_BY_IP ) {
        return start_in_save_mode_for_ip(ips_to_migrate, stop_flag);
    }

    return start_in_save_mode_for_ct_zones(ct_zones_to_migrate, stop_flag);
}


/**
 * Creates hashtable of IP addresses/ CT Zones from CLI arguments.
 *
 * Args:
 *   @argv array of CLI args.
 *
 * Returns:
 *   Resulting hashtable containing IP address/CT zones(uint32_t)  as key.
 */
GHashTable *
get_entity_ht_from_args(char *argv[])
{
    if (fltr_type == FILTER_BY_IP) {
        int num_ips;
        GHashTable *ips_to_migrate;
        num_ips = atoi(argv[NUM_IP_ADDR_ARG_INDEX]);
        const char **ip_list = (const char **)(argv + IP_ADDR_LIST_ARG_INDEX);
        ips_to_migrate = create_hashtable_from_ip_list(ip_list, num_ips);
        if (ips_to_migrate == NULL) {
            LOG(ERROR, "%s: Hashtable creation failed.", __func__);
        }
        return ips_to_migrate;
    }

    int num_zones;
    GHashTable *ct_zones_to_migrate;
    num_zones = atoi(argv[NUM_CT_ZONES_ARG_INDEX]);
    const char **zone_list = (const char **)(argv + CT_ZONES_LIST_ARG_INDEX);
    ct_zones_to_migrate = create_hashtable_from_ct_zones_list(zone_list, 
                                                              num_zones);
    if (ct_zones_to_migrate == NULL) {
        LOG(ERROR, "%s: Hashtable creation failed.", __func__);
    }
    return ct_zones_to_migrate;
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

    // Parse the command line argmuments.
    mode = atoi(argv[MODE_ARG_INDEX]);
    helper_id = argv[HELPER_ID_ARG_INDEX];

    // Initialise logging at default INFO level.
    ret = init_log(INFO, helper_id);
    if (ret != 0) {
        return EAGAIN;
    }

    // Init configs.
    init_lmct_config(lmct_config_path);

    // set the logging level read from config.
    set_log_level(lmct_conf.log_lvl);

    int i;
    for (i = 0; i < argc; i++) {
        LOG(INFO, "Mansi: Argument %d: %s\n", i, argv[i]);
    }

    LOG(INFO, "%s: Starting in mode %s", __func__, mode_to_string[mode]);
    LOG(INFO, "%s: Starting in filter on basis of %s", __func__, 
        fltr_type == FILTER_BY_IP ? "IP Addresses" : "CT Zones");
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
    dbus_server_args.helper_id = helper_id;
    dbus_server_args.stop_flag = &stop_flag;
    dbus_server_args.mode = (enum op_mode) mode;
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
        GHashTable *ips_to_migrate = NULL;
        GHashTable *ct_zones_to_migrate = NULL;

        if (fltr_type == FILTER_BY_IP) {
            ips_to_migrate = get_entity_ht_from_args(argv);
        } else {
            ct_zones_to_migrate = get_entity_ht_from_args(argv);
        }

        if (ips_to_migrate == NULL && ct_zones_to_migrate == NULL) {
                return EINVAL;
        }
        ret = start_in_save_mode(ips_to_migrate, ct_zones_to_migrate,
                                 &stop_flag);
        g_hash_table_destroy(ips_to_migrate);
        g_hash_table_destroy(ct_zones_to_migrate);
        if (ret != 0) {
            return EAGAIN;
        }
    }
    pthread_join(dbus_server_args.tid, NULL);
    conntrack_store_destroy(conn_store);
    close_log();

    return 0;
}

static void
err_usage(void)
{
    errx(EXIT_FAILURE,
        "Usage:\n"
        "SAVE mode: DBUS_SYSTEM_BUS_ADDRESS=<dbus address> "
        "conntrack_migrator 2 <dbus_helper_id> <num_ip_addresses> "
        "<space separated ip address list>\n"
        "LOAD mode: DBUS_SYSTEM_BUS_ADDRESS=<dbus address> "
        "conntrack_migrator 1 <dbus_helper_id>\n"
        "NOTE: DBUS_SYSTEM_BUS_ADDRESS env variable should be set.\n");
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
 * Performs checks on args when started in save mode.
 *
 * Checks performed:
 * 1. Num of ip address param is present and is non-negative
 * 2. The ip address list size is num of ip address provided
 * 3. Number of ip addresses does not exceed 127 which is the limit set by
 *    netlink bsd filters.
 *
 * Args:
 *   @argc num of arguemnts
 *   @argv array of CLI arguments.
 *
 * Returns:
 *   true if success, false otherwise.
 */
static void
check_save_mode_args(int argc, char *argv[])
{
    if (fltr_type == FILTER_BY_IP) {
        int num_ip_addr;
        num_ip_addr = atoi(argv[NUM_IP_ADDR_ARG_INDEX]);
        if (num_ip_addr < 0 || num_ip_addr > (argc - IP_ADDR_LIST_ARG_INDEX)) {
            errx(EXIT_FAILURE, "Invalid argument for number of IP addresses");
        }
    } else if (fltr_type == FILTER_BY_CT_ZONE) {
        int num_ct_zones;
        num_ct_zones = atoi(argv[NUM_CT_ZONES_ARG_INDEX]);
        if (num_ct_zones < 0 || num_ct_zones > (argc - CT_ZONES_LIST_ARG_INDEX)) {
            errx(EXIT_FAILURE, "Invalid argument for number of CT Zones");
        }
    } else {
        errx(EXIT_FAILURE, "Filter type not set properly");
    }
    return;
}

static void
set_filter_type(int argc, char * argv[]){

    if (argc < 4) {
        errx(EXIT_FAILURE, "Number of IP addresses/ ct-zones not present in args");
    }

    // Deciding filterting type - ct_zone/ip_addr, on value
    // of NUM_IP_ADDR_ARG_INDEX if this -1 then ct zone else
    // it will be no of ip addr provided. This hack is to support
    // older versions.
    int num_ip_addr;
    num_ip_addr = atoi(argv[NUM_IP_ADDR_ARG_INDEX]);
    if (num_ip_addr >= 0) {
        populate_filter_type(FILTER_BY_IP);
    } else if (num_ip_addr == -1){
        populate_filter_type(FILTER_BY_CT_ZONE);
    } else {
        errx(EXIT_FAILURE, "Number of IP addresses/ ct-zones not present" 
             "in args");
    }
    return;
}

/**
 * Performs checks on CLI args.
 *
 * Checks performed:
 * 1. Mode is vaild
 * 2. DBUS_SYSTEM_BUS_ADDRESS env is set
 * 3. SAVE mode has proper arguments
 *
 * Args:
 *   @argc num of arguemnts
 *   @argv array of CLI arguments.
 */
static void
check_args(int argc, char *argv[])
{
    int mode;

    if (argc < 3) {
        err_usage();
    }

    //check_dbus_address_env();

    mode = atoi(argv[MODE_ARG_INDEX]);
    check_mode(mode);

    set_filter_type(argc, argv);

    if (mode == SAVE_MODE) {
        check_save_mode_args(argc, argv);
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

    // Perform prechecks on the arguments
    check_args(argc, argv);

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

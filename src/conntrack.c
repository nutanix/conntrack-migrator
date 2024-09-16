/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the functions that interface with the
 * libnetfilter_conntrack library. This file is divided into 4
 * types of functions:
 *   1. Conntrack table dump (snapshot) related functions.
 *   2. Conntrack table events related functions.
 *   3. Creating entry in the conntrack table related functions.
 *   4. Deleting entry from the conntrack table relaed functions.
 */

#include <arpa/inet.h> // For struct in_addr.
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include <glib.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "common.h"
#include "conntrack.h"
#include "conntrack_entry.h"
#include "conntrack_store.h"
#include "ct_delete_args.h"
#include "lmct_config.h"
#include "log.h"

/* Type definition for CT dump callbacks. */
typedef int (*dump_cb)(enum nf_conntrack_msg_type type,
                       struct nf_conntrack *ct,
                       void *data);

/**
 * Structure to represent the callback arguments for the dump taken before
 * deleting the conntrack entries.
 */
struct delete_ct_dump_cb_args {
    GHashTable *ips_migrated; // IPs for which CT entries have been migrated
    GHashTable *ips_on_host;  // IPs that are currently present on the host
    GHashTable *ct_store;     // CT entries to be deleted
};

/**
 * Checks if either of src/dst IP address in present in the hashtable.
 *
 * Args:
 *   @src pointer to the in_addr struct containing the source address.
 *   @dst pointer to the in_addr struct containing the destination address.
 *   @ht pointer to the hashtable to perform the lookup.
 *
 * Returns:
 *   true in case, either of src/dst ip address is present in the hashtable,
 *   false otherwise.
 */
static bool
is_src_or_dst_in_hashtable(struct in_addr *src, struct in_addr *dst,
                           GHashTable *ht)
{
    bool src_in_ht, dst_in_ht;

    src_in_ht = g_hash_table_contains(ht, GUINT_TO_POINTER(src->s_addr));
    dst_in_ht = g_hash_table_contains(ht, GUINT_TO_POINTER(dst->s_addr));

    return (src_in_ht || dst_in_ht);
}

/**
 * Checks if the conntrack entry is valid.
 *
 * Conntrack entry is considered valid (migration supported) if:
 *  - source and destination IPv4 addresses are set.
 *  - Zone information is not present.
 *
 * Args:
 *   @type nf message type.
 *   @ct pointer to the conntrack entry.
 *
 * Returns:
 *   true in case the CT entry passes the above mentioned checks,
 *   false otherwise
 */
static bool
validate_ct_entry(enum nf_conntrack_msg_type type, struct nf_conntrack *ct)
{
    if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) <= 0 ||
        nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST) <= 0) {
        char *buf = g_malloc0(1024);
        // nfct_snprintf prints only the attributes set in the entry,
        // so we're safe wrt NULL attributes.
        nfct_snprintf(buf, 1024, ct, type, NFCT_O_DEFAULT,
                      NFCT_OF_SHOW_LAYER3);
        LOG(ERROR, "%s: IPv4 address not set in entry: %s", __func__, buf);
        g_free(buf);
        return false;
    }

    if(fltr_type == FILTER_BY_IP) {
        if (nfct_attr_is_set(ct, ATTR_ZONE) > 0 ||
            nfct_attr_is_set(ct, ATTR_ORIG_ZONE) > 0 ||
            nfct_attr_is_set(ct, ATTR_REPL_ZONE) > 0) {
            return false;
        }
    }

    return true;
}

//////////////////////////////////////////////////////////////////////
//          START OF DUMP related functions                         //
/////////////////////////////////////////////////////////////////////


/**
 * Function called for every ct entry returned during a CT dump call.
 *
 * For every conntrack entry received, if source or destination IP address
 * present in the entry is also present in ips_to_migrate, then update
 * the conntrack store for further processing of the entry, otherwise discard
 * the entry.
 *
 * Args:
 *   @type nf message type.
 *   @ct pointer to the conntrack entry received.
 *   @data pointer to the data sent to the callback. In this case it is
 *         struct ct_events_targs.
 *
 * Returns:
 *   NFCT_CB_CONTINUE representing continue processing of
 *   further events by this callback.
 */
static int
conntrack_dump_callback(enum nf_conntrack_msg_type type,
                        struct nf_conntrack *ct,
                        void *data)
{
    bool is_entry_useful;
    GHashTable *ips_to_migrate;
    GHashTable *ct_zones_to_migrate;
    struct in_addr *src_addr, *dst_addr;
    struct ct_events_targs *cb_args = (struct ct_events_targs *)data;
    uint16_t zone;

    if (!validate_ct_entry(type, ct)) {
        return NFCT_CB_CONTINUE;
    }

    if (fltr_type == FILTER_BY_IP) {
        ips_to_migrate = (GHashTable *)cb_args->ips_to_migrate;
        src_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC);
        dst_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_DST);

        is_entry_useful = is_src_or_dst_in_hashtable(src_addr, dst_addr,
                                                     ips_to_migrate);
        LOG(INFO, "Mansi: %s %s", __func__, is_entry_useful ? "true": false);
    } else {
        zone = nfct_get_attr_u16(ct, ATTR_ZONE);
        ct_zones_to_migrate = (GHashTable *)cb_args->ct_zones_to_migrate;
        is_entry_useful = g_hash_table_contains(ct_zones_to_migrate,
                                                GUINT_TO_POINTER(zone));
    }

    if (is_entry_useful) {
        LOG(INFO, "Mansi: adding for zone %u %s", zone, __func__);
        update_conntrack_store(conn_store, ct, type);
    }

    return NFCT_CB_CONTINUE;
}

/**
 * Boilerplate code for performing conntrack dump.
 *
 * Args:
 *   @h handle to the netlink socket.
 *   @cb callback function to be called for every CT entry received.
 *   @cb_args args to be passed to the callback function.
 *
 * Returns:
 *    -1 in case of failure. 0 otherwise.
 */
static int
_conntrack_dump(struct nfct_handle *h, dump_cb cb, void *cb_args)
{
    int ret;
    uint32_t family = AF_INET;

    if (cb != NULL) {
        nfct_callback_register(h, NFCT_T_ALL, cb, (void *)cb_args);
    }

    ret = nfct_query(h, NFCT_Q_DUMP, &family);
    if (ret == -1) {
        LOG(ERROR, "%s: Conntrack Dump failed. %s", __func__, strerror(errno));
    }

    if (cb != NULL) {
        nfct_callback_unregister(h);
    }

    return ret;
}

/**
 * Query the kernel conntrack for CT entries.
 *
 * This function queries the netlink socket for all the conntrack entries
 * present in the system and filters them based on the ip addresses provided
 * in the arguments. Note that this is a blocking call and this function
 * will return only after the response from the netlink socket.
 *
 * Args:
 *   @handle handle to the netlink socket.
 *   @struct ct_events_targs struct ct_events_targs ct_zones_to_migrate or
 *      ips_to_migrate need to be present depending upon filtr_type set.
 *
 * Returns:
 *   0 if the operation was successful. -1 otherwise.
 */
int
get_conntrack_dump(struct nfct_handle *handle, struct ct_events_targs *data)
{
    int ret;

    LOG(INFO, "%s: Conntrack dump start", __func__);
    ret = _conntrack_dump(handle, conntrack_dump_callback, data);
    LOG(INFO, "%s: Conntrack dump end", __func__);

    return ret;
}

//////////////////////////////////////////////////////////////////////
//          START of CT events related functions                    //
/////////////////////////////////////////////////////////////////////

/**
 * Function called for every ct entry returned from listening for conntrack
 * events.
 *
 * Args:
 *   @nlh pointer to the netlink message header.
 *   @data pointer to the data sent to the callback. Here it's the struct
 *     ct_events_targs.
 *
 * Returns:
 *  - MNL_CB_STOP if we need to stop further event processing.
 *  - MNL_CB_ERROR if there is an error processing the event.
 *  - MNL_CB_OK otherwise.
 */
static int
conntrack_events_callback(const struct nlmsghdr *nlh, void *data)
{
    enum nf_conntrack_msg_type type = NFCT_T_UNKNOWN;
    struct nf_conntrack *ct;
    bool *stop_flag;
    GHashTable *ct_zones_to_migrate;
    struct ct_events_targs *cb_args = (struct ct_events_targs *)data;
    stop_flag = (bool *)cb_args->stop_flag;
    ct_zones_to_migrate = (GHashTable *)cb_args->ct_zones_to_migrate;
    if (*stop_flag) {
        return MNL_CB_STOP;
    }

    switch (nlh->nlmsg_type & 0xFF) {
    case IPCTNL_MSG_CT_NEW:
        if (nlh->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) {
            type = NFCT_T_NEW;
        } else {
            type = NFCT_T_UPDATE;
        }
        break;
    case IPCTNL_MSG_CT_DELETE:
        type = NFCT_T_DESTROY;
        break;
    }

    ct = nfct_new();
    if (ct == NULL) {
        LOG(ERROR, "%s: Cannot allocate new ct struct", __func__);
        exit(EXIT_FAILURE);
    }

    nfct_nlmsg_parse(nlh, ct);

    if (!validate_ct_entry(type, ct)) {
        return MNL_CB_OK;
    }

    uint16_t zone;
    zone = nfct_get_attr_u16(ct, ATTR_ZONE);

    bool add_to_conntrack_store = true;
    if( fltr_type == FILTER_BY_CT_ZONE  &&
        !g_hash_table_contains(ct_zones_to_migrate, GUINT_TO_POINTER(zone))){
        add_to_conntrack_store = false;
    }

    if (add_to_conntrack_store){
        LOG(INFO, "%s : Updating zone %u entry in conntrack store", __func__,
            zone);
        update_conntrack_store(conn_store, ct, type);
    }
    nfct_destroy(ct);

    return MNL_CB_OK;
}

/**
 * Creates a nfct_filter depending upin nfct_filter.
 *
 * Returns:
 *   pointer to the nfct_filter if success, NULL otherwise.
 */
static struct nfct_filter *
create_nfct_filter(GHashTable *ips, bool is_src_filter)
{
    struct nfct_filter *filter;
    GHashTableIter iter;
    gpointer key = NULL;

    filter = nfct_filter_create();
    if (filter == NULL) {
        LOG(ERROR, "%s: Failed to create a filter for ct zones. %s", __func__,
            strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (fltr_type == FILTER_BY_IP) {
        LOG(INFO, "Mansi: Setting filter for IPS %s", __func__);
        GHashTableIter iter;
        gpointer key;

        g_hash_table_iter_init(&iter, ips);
        while (g_hash_table_iter_next(&iter, &key, NULL)) {
            uint32_t ip = GPOINTER_TO_UINT(key);
            LOG(INFO, "adding ip into filter %u %s", key, __func__);
            struct nfct_filter_ipv4 filter_ipv4 = {
                .addr = ntohl(ip),
                .mask = 0xffffffff,
            };

            enum nfct_filter_attr filter_type;
            if (is_src_filter) {
                filter_type = NFCT_FILTER_SRC_IPV4;
            } else {
                filter_type = NFCT_FILTER_DST_IPV4;
            }

            nfct_filter_add_attr(filter, filter_type, &filter_ipv4);
            nfct_filter_set_logic(filter, filter_type, NFCT_FILTER_LOGIC_POSITIVE);
        }
    }
    return filter;
}

/**
 * Listens for the changes in the kernel conntrack table and filter out the
 * events for particular entries based on the filter.
 *
 * This function listens on the netlink socket for the events on particular
 * IPs provided in the filter. These events include create/update/deletion of
 * CT entry with the particular IP addresses.
 *
 * NOTE: this is a blocking call and this function will return only when the
 * callbacks are unregistered on the handle. Set the stop_flag to prevent any
 * further processing and unblock the calling thread.
 *
 * Args:
 *   @nl pointer to the netlink socket.
 *   @ips_to_migrate IP addresses to be used for filtering the CT entries.
 *   @is_src_filter bool representing whether the filter is to be applied
 *     on the source ip or destination ip address.
 *   @stop_flag pointer to bool passed to the callbacks to stop processing
 *     any further events.
 *
 * Returns:
 *   0 if the operation was successful. -1 otherwise.
 */
int
listen_for_conntrack_events(struct mnl_socket *nl,
                            struct ct_events_targs *ct_events_targs)
{
    GHashTable *ips_to_migrate = ct_events_targs->ips_to_migrate;
    bool is_src_filter = ct_events_targs->is_src;
    bool *stop_flag = ct_events_targs->stop_flag;
    int ret = 0;
    int fd;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int filter_attach_ret;
    struct nfct_filter *filter;
    fd_set readfds;  // for select sync IO
    struct timeval tv = {
        .tv_sec = 2,
        .tv_usec = 0
    };

    fd = mnl_socket_get_fd(nl);
    filter = create_nfct_filter(ips_to_migrate, is_src_filter);
    // Attach the filter to the socket.
    filter_attach_ret = nfct_filter_attach(fd, filter);
    if (filter_attach_ret == -1) {
        LOG(ERROR, "%s: Failed to attach filter to the socket. %s", __func__,
            strerror(errno));
        nfct_filter_destroy(filter);
        return -1;
    }
    nfct_filter_destroy(filter);

    // Read from the socket using select synchronous IO
    // and every 2 secs check if stop flag is set or not.
    do {
        if (*stop_flag == true) {
            break;
        }

        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        tv.tv_sec = 2;
        tv.tv_usec = 0;

        ret = select(fd+1, &readfds, NULL, NULL, &tv);
        if (ret == -1) {
            if (errno == EINTR) {
                LOG(WARNING, "%s Failed to select socket. %s. Retrying.",
                    __func__, strerror(errno));
                continue;
            }
            LOG(ERROR, "%s: Failed to select the socket to read. %s", __func__,
                strerror(errno));
            return ret;
        }

        if (FD_ISSET(fd, &readfds) == 0) {
            continue;
        }

        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (ret == -1) {
            if (errno == EINTR) {
                LOG(WARNING, "%s Failed to receive from mnl socket. %s."
                    "Retrying.", __func__, strerror(errno));
                continue;
            }
            LOG(ERROR, "%s: Error in receiving message from mnl socket, %s",
                __func__, strerror(errno));
            break;
        }

        ret = mnl_cb_run(buf, ret, 0, 0, conntrack_events_callback, 
                         ct_events_targs);
        if (ret == MNL_CB_STOP) {
            LOG(INFO, "%s: Stopping the callback", __func__);
            break;
        }
    } while (ret >= 0);

    return ret;
}


//////////////////////////////////////////////////////////////////////
//          START of CT entry create related functions              //
/////////////////////////////////////////////////////////////////////

/**
 * Adds the conntrack entry to nlmsg batch.
 *
 * NOTE: this function expilcity takes label as a parameter because setting
 * label in nf_conntrack is a costly operation while setting it directly in
 * the netlink message is quite easy (memcopy).
 * Also we are using NLM_F_REPLACE flag, which will replace the conntrack
 * entry if already present in the kernel.
 *
 * Args:
 *   @send_buf buffer to which ct entry is to be appended.
 *   @ct pointer to the conntrack entry to be programmed in CT.
 *   @label pointer to the ct label. If not NULL, label attribute is set
 *     in the conntrack entry.
 *   @seq sequence number for ct entry to be used in the batch.
 *
 */
void
append_ct_to_batch(char *send_buf, struct nf_conntrack *ct,
                   uint32_t *label, int seq)
{
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfh;

    nlh = mnl_nlmsg_put_header(send_buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    nlh->nlmsg_seq = seq;

    nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
    nfh->nfgen_family = AF_INET;
    nfh->version = NFNETLINK_V0;
    nfh->res_id = 0;

    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
    nfct_nlmsg_build(nlh, ct);

    if (label != NULL) {
        mnl_attr_put(nlh, CTA_LABELS, CT_LABEL_NUM_WORDS * WORD_SIZE, label);
    }
}

/**
 * Programs the batch of CT entry in the kernel conntrack table.
 *
 * This function uses the mnl socket to the program the conntrack entries
 * to the kernel conntrack. If the entry to be programmed is already present
 * in the kernel conntrack, it replaces the kernel's CT entry with the one
 * received from QEMU. (see NLM_F_REPLACE flag in append_ct_to_batch)
 *
 * Args:
 *   @nl pointer to the mnl socket.
 *   @batch pointer to the nlmsg batch containing list of conntrack
 *     entries to be programmed in CT.
 *
 * Returns:
 *   0 if the operation was successful. -1 otherwise.
 */
int
create_batch_conntrack(struct mnl_socket *nl, struct mnl_nlmsg_batch *batch)
{
    int ret = 0;
    int fd = mnl_socket_get_fd(nl);
    int port_id = mnl_socket_get_portid(nl);
    size_t batch_size = mnl_nlmsg_batch_size(batch);
    struct timeval tv = {
        .tv_sec   = 0,
        .tv_usec  = 0
    };
    fd_set readfds;
    char recv_buf[MNL_SOCKET_BUFFER_SIZE];

    // Send the request to create batch conntrack.
    ret = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), batch_size);
    if (ret == -1) {
        LOG(ERROR, "%s: Failed to send data to mnl_socket. %s", __func__,
            strerror(errno));
        return ret;
    }

    // Receive and digest all the acknowledgments from the kernel.
    do {
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        tv.tv_sec = 0;
        tv.tv_usec = 0;

        ret = select(fd + 1, &readfds, NULL, NULL, &tv);
        if (ret == -1) {
            if (errno == EINTR) {
                LOG(WARNING, "%s Failed to select readfds. %s. Retrying.",
                    __func__, strerror(errno));
                continue;
            }
            LOG(ERROR, "%s: Failed to select readfds. %s", __func__,
                strerror(errno));
            return -1;
        }

        if (FD_ISSET(fd, &readfds) == 0) {
            break;
        }

        ret = mnl_socket_recvfrom(nl, recv_buf, sizeof(recv_buf));
        if (ret == -1) {
            if (errno == EINTR) {
                LOG(WARNING, "%s Failed to receive ack. %s. Retrying.",
                    __func__, strerror(errno));
                continue;
            }
            LOG(ERROR, "%s: Failed to receive ack. %s", __func__,
                strerror(errno));
            return -1;
        }

        ret = mnl_cb_run(recv_buf, ret, 0, port_id, NULL, NULL);
        if (ret == -1) {
            LOG(ERROR, "%s: mnl_cb_run failed. %s", __func__,
                strerror(errno));
            return -1;
        }
    } while (ret > 0);

    return 0;
}

//////////////////////////////////////////////////////////////////////
//          START of CT entry delete related functions              //
/////////////////////////////////////////////////////////////////////

/**
 * Function called for every ct entry returned during a CT dump call in the
 * delete workflow.
 *
 * The conntrack entries that have to be deleted from source hypervisor must
 * pass the following check:
 * 1. src/dest ip address in CT entry should be present in the ips_migrated list
 *                and
 * 2. src/dest ip address in CT should not be present in the ips_on_host list.
 * All such entries are stored in the hashtable passed as callback arguments.
 * These entries are eligible for deletion.
 *
 * Args:
 *  @type nf message type
 *  @ct pointer to the conntrack entry received
 *  @data pointer to the data sent to the callback.
 **
 * Returns:
 *   NFCT_CB_CONTINUE representing: continue processing of further
 *   events by this callback.
 */
static int
delete_conntrack_dump_callback(enum nf_conntrack_msg_type type,
                               struct nf_conntrack *ct, void *data)
{
    struct delete_ct_dump_cb_args *cb_args;
    struct in_addr *src_addr, *dst_addr;
    bool in_ips_migrated, in_ips_on_host;

    if (!validate_ct_entry(type, ct)) {
        return NFCT_CB_CONTINUE;
    }

    cb_args = data;
    src_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC);
    dst_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_DST);
    if (src_addr == NULL || dst_addr == NULL) {
        LOG(WARNING, "%s: ct entry with NULL src/dst IP received. Skipping.",
            __func__);
        return NFCT_CB_FAILURE;
    }
    in_ips_migrated = is_src_or_dst_in_hashtable(src_addr, dst_addr,
                                                 cb_args->ips_migrated);
    in_ips_on_host = is_src_or_dst_in_hashtable(src_addr, dst_addr,
                                                cb_args->ips_on_host);

    if (in_ips_migrated && !in_ips_on_host) {
        uint32_t ct_id = nfct_get_attr_u32(ct, ATTR_ID);
        if (ct_id == 0) {
            LOG(WARNING, "%s: ct entry with 0 id received. Skipping.",
                __func__);
            return NFCT_CB_FAILURE;
        }
        g_hash_table_insert(cb_args->ct_store, GUINT_TO_POINTER(ct_id), ct);
        return NFCT_CB_STOLEN;
    }

    return NFCT_CB_CONTINUE;
}

/**
 * Deletes the conntrack entry from CT table.
 *
 * Args:
 *   @h handle to netlink socket.
 *   @ct pointer to the CT entry to be deleted.
 *
 * Returns:
 *   return code of nfct_query().
 */
static int
ct_entry_delete(struct nfct_handle *h, struct nf_conntrack *ct)
{
    int ret;
    char buf[1024] = {0};

    ret = nfct_query(h, NFCT_Q_DESTROY, ct);
    if (ret == -1) {
        nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN,
                      NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);
        LOG(WARNING, "%s: Failed to delete the conntrack entry %s. "
            "Error (%d)(%s)", __func__, buf, ret, strerror(errno));
    }
    return ret;
}

/**
 * Wrapper used for destroying the values in the hashtable which contains the
 * CT entries to be deleted.
 *
 * Args:
 *   @ct pointer to the nf_conntrack struct
 */
static void
ct_destroy_g_wrapper(void *ct)
{
    nfct_destroy(ct);
}

/**
 * Performs the cleanup at the source hypervisor at the end of successful
 * migration.
 *
 * To clear up the conntrack entries the following procedure is followed:
 *   1. Create hashtables for ips_migrated and ips_on_host.
 *   2. Get the conntrack dump and filter the conntrack entries for which
 *      either of src/dest ips are present in the ips_migrated but not in
 *      ips_on_host.
 *   3. For each of the filtered entry, send the delete call to the netlink
 *      socket.
 *
 * Args:
 *   @handle handle to the netlink socket.
 *   @ips_migrated IP addresses for which CT entries have been migrated.
 *   @ips_on_host IP addresses that are currently present on this host.
 */
static void
_delete_ct_entries(struct nfct_handle *handle,
                   GHashTable *ips_migrated,
                   GHashTable *ips_on_host)
{
    struct delete_ct_dump_cb_args cb_args;
    int ret, failed, success;
    GHashTable *ct_store; // Hashtable to store the CT entries to be deleted
    GHashTableIter iter;  // Iterator for ct_store
    gpointer key, value = NULL;

    ct_store = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                     NULL, ct_destroy_g_wrapper);

    // Take conntrack dump to get the entries to be deleted.
    cb_args.ips_migrated = ips_migrated;
    cb_args.ips_on_host = ips_on_host;
    cb_args.ct_store = ct_store;

    ret = _conntrack_dump(handle, delete_conntrack_dump_callback, &cb_args);
    if (ret == -1) {
        LOG(ERROR, "%s: Skipping conntrack delete due to dump"
            " failure", __func__);
        goto finish;
    }

    LOG(INFO, "%s: starting conntrack entry delete. "
        "Entries to delete %d", __func__, g_hash_table_size(cb_args.ct_store));

    failed = success = 0;
    // Iterate over the ct_store to delete the entries.
    g_hash_table_iter_init(&iter, cb_args.ct_store);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        ret = ct_entry_delete(handle, value);
        if (ret == -1) {
            failed++;
        } else {
            success++;
        }
    }

    LOG(INFO, "%s: Finished conntrack entry delete. Success: %d, Failed: %d",
        __func__, success, failed);

finish:
    if (ct_store != NULL) {
      g_hash_table_destroy(ct_store);
    }
}

/**
 * Performs the cleanup at the source hypervisor at the end of successful
 * migration.
 *
 * The following procedure is performed for conntrack entry cleanup:
 * 1. Delete thread is started during initialisation phase of the binary.
 * 2. The ip address passed to the binary are reused as "ips_migrated"
 * 3. The thread waits on the clear_called condition. This dbus-server on
 *    Clear IPC will get the IP addresses present on this host (ips_on_host),
 *    and wake up this thread.
 * 4. The delete procedure is performed afterwards. See _delete_ct_entries for
 *    more details.
 *
 *  Args:
 *    @data Pointer to the delete arguments.
 *
 *  Returns:
 *    NULL
 */
void *
delete_ct_entries(void *data)
{
    struct ct_delete_args *ct_del_args;
    struct nfct_handle *h;

    ct_del_args = data;

    LOG(INFO, "%s: Starting conntrack delete thread", __func__);
    LOG(INFO, "%s: waiting on clear condition.", __func__);
    pthread_mutex_lock(&ct_del_args->mutex);
    while (!ct_del_args->clear_called) {
        pthread_cond_wait(&ct_del_args->clear_called_cond, &ct_del_args->mutex);
    }
    LOG(INFO, "%s: thread woke up", __func__);

    h = nfct_open(CONNTRACK, 0);
    if (h == NULL) {
        LOG(ERROR, "%s: nfct_open failed. %s", __func__, strerror(errno));
        goto unlock;
    }

    _delete_ct_entries(h, ct_del_args->ips_migrated, ct_del_args->ips_on_host);
    nfct_close(h);

unlock:
    pthread_mutex_unlock(&ct_del_args->mutex);
    LOG(INFO, "%s: Finished conntrack delete thread", __func__);

    return NULL;
}

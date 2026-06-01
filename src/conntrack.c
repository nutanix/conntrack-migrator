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
#include "log.h"

/* Type definition for CT dump callbacks. */
typedef int (*dump_cb)(enum nf_conntrack_msg_type type,
                       struct nf_conntrack *ct,
                       void *data);

/**
 * Structure to represent the callback arguments for the dump taken before
 * deleting the conntrack entries.
 *
 * Real C tagged union over the active SAVE sub-mode (same shape as
 * ct_delete_args):
 *   op_type == SAVE_IPS_OP        -> ips_migrated / ips_on_host valid.
 *   op_type == SAVE_PORT_ZONE_OP  -> zones_migrated / zones_on_host valid.
 * (the two pairs overlay the same memory; only the active arm is set.)
 *
 * ct_store is the per-pass output: CT entries that survive the filter are
 * stolen into it and later iterated for NFCT_Q_DESTROY.
 */
struct delete_ct_dump_cb_args {
    enum save_mode_op_type op_type; // selects which arm of the union below is valid

    /* Active sub-mode state, mirroring struct ct_delete_args. Anonymous
     * inner structs keep field access flat (cb_args->ips_migrated etc.). */
    union {
        /* op_type == SAVE_IPS_OP */
        struct {
            GHashTable *ips_migrated; // IPs for which CT entries have been migrated
            GHashTable *ips_on_host;  // IPs that are currently present on the host
        };
        /* op_type == SAVE_PORT_ZONE_OP */
        struct {
            GHashTable *zones_migrated; // CT zones for which entries have been migrated
            GHashTable *zones_on_host;  // CT zones currently owned by ports on this host
        };
    };

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
 * Returns the CT zone we filter on for migration via an out-parameter.
 *
 * Prefers ATTR_ZONE, falls back to ATTR_ORIG_ZONE. Returns false (without
 * touching @out) if neither attribute is set, so callers in hot paths can
 * distinguish "no zone attribute" from a valid zone value of 0 without
 * relying on validate_ct_entry having run first.
 *
 * Args:
 *   @ct  pointer to the conntrack entry. Must be non-NULL.
 *   @out output uint16_t (only written on success). Must be non-NULL.
 *
 * Returns:
 *   true if a zone was extracted into *out, false otherwise.
 */
static bool
ct_get_migration_zone(const struct nf_conntrack *ct, uint16_t *out)
{
    if (ct == NULL) {
        LOG(ERROR, "%s: ct is NULL", __func__);
        return false;
    }
    if (out == NULL) {
        LOG(ERROR, "%s: out is NULL", __func__);
        return false;
    }

    if (nfct_attr_is_set(ct, ATTR_ZONE) > 0) {
        *out = nfct_get_attr_u16(ct, ATTR_ZONE);
        return true;
    }
    return false;
}

/**
 * Checks if a CT zone is present in the hashtable.
 *
 * Mirrors is_src_or_dst_in_hashtable() for zone-keyed hashtables.
 *
 * Args:
 *   @zone CT zone to look up.
 *   @ht   pointer to the hashtable to perform the lookup.
 *
 * Returns:
 *   true if @zone is present in the hashtable, false otherwise.
 */
static bool
is_zone_in_hashtable(uint16_t zone, GHashTable *ht)
{
    return g_hash_table_contains(ht, GUINT_TO_POINTER((guint) zone));
}

/**
 * Checks if the conntrack entry is valid for the active SAVE sub-mode.
 *
 * Common to both modes:
 *  - source and destination IPv4 addresses are set.
 *
 * IP mode (SAVE_IPS_OP):
 *  - Zone information is not present (legacy paranoid check kept verbatim).
 *
 * Zone mode (SAVE_PORT_ZONE_OP):
 *  - At least one of ATTR_ZONE / ATTR_ORIG_ZONE is set so the dispatcher
 *    has a key to filter on.
 *
 * Args:
 *   @type nf message type.
 *   @ct pointer to the conntrack entry.
 *   @op_type active SAVE sub-mode.
 *
 * Returns:
 *   true in case the CT entry passes the above mentioned checks,
 *   false otherwise
 */
static bool
validate_ct_entry(enum nf_conntrack_msg_type type, const struct nf_conntrack *ct,
                  enum save_mode_op_type op_type)
{
    if (ct == NULL) {
        LOG(ERROR, "%s: ct is NULL", __func__);
        return false;
    }

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

    if (op_type == SAVE_IPS_OP) {
        if (nfct_attr_is_set(ct, ATTR_ZONE) > 0 ||
            nfct_attr_is_set(ct, ATTR_ORIG_ZONE) > 0 ||
            nfct_attr_is_set(ct, ATTR_REPL_ZONE) > 0) {
            return false;
        }
    } else {
        if (nfct_attr_is_set(ct, ATTR_ZONE) <= 0) {
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
 * present in the entry is also present in ips_to_migrate (IP mode), or the
 * entry's CT zone is present in zones_to_migrate (zone mode), then update
 * the conntrack store for further processing of the entry, otherwise
 * discard the entry.
 *
 * Args:
 *   @type nf message type.
 *   @ct pointer to the conntrack entry received.
 *   @data pointer to the data sent to the callback. In this case it is
 *         a struct save_mode_config *.
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
    struct save_mode_config *save_config;
    struct in_addr *src_addr, *dst_addr;

    if (ct == NULL) {
        LOG(ERROR, "%s: ct is NULL", __func__);
        return NFCT_CB_CONTINUE;
    }
    if (data == NULL) {
        LOG(ERROR, "%s: data is NULL", __func__);
        return NFCT_CB_CONTINUE;
    }

    save_config = data;

    if (!validate_ct_entry(type, ct, save_config->op_type)) {
        return NFCT_CB_CONTINUE;
    }

    if (save_config->op_type == SAVE_IPS_OP) {
        src_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC);
        dst_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_DST);

        is_entry_useful = is_src_or_dst_in_hashtable(src_addr, dst_addr,
                                                     save_config->ips_to_migrate);
    } else {
        uint16_t zone;
        if (!ct_get_migration_zone(ct, &zone)) {
            LOG(WARNING, "%s: dump entry has no zone attribute; skipping.",
                __func__);
            return NFCT_CB_CONTINUE;
        }
        is_entry_useful = is_zone_in_hashtable(zone,
                                               save_config->zones_to_migrate);
    }

    if (is_entry_useful) {
        update_conntrack_store(conn_store, ct, type, save_config->op_type);
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
 * present in the system and filters them based on the migration targets
 * provided. Note that this is a blocking call and this function will
 * return only after the response from the netlink socket.
 *
 * Args:
 *   @handle handle to the netlink socket.
 *   @save_config SAVE-mode config (mode-aware) to filter the CT entries.
 *
 * Returns:
 *   0 if the operation was successful. -1 otherwise.
 */
int
get_conntrack_dump(struct nfct_handle *handle,
                   struct save_mode_config *save_config)
{
    int ret;

    LOG(INFO, "%s: Conntrack dump start", __func__);
    ret = _conntrack_dump(handle, conntrack_dump_callback, save_config);
    LOG(INFO, "%s: Conntrack dump end", __func__);

    return ret;
}

//////////////////////////////////////////////////////////////////////
//          START of CT events related functions                    //
/////////////////////////////////////////////////////////////////////

/**
 * Closure context for conntrack_events_callback.
 *
 * mnl_cb_run takes a single void *user_data; this struct bundles the
 * SAVE-mode config pointer with the stop_flag so the callback can
 * dispatch on op_type and exit gracefully.
 */
struct events_cb_ctx {
    struct save_mode_config *save_config;
    bool *stop_flag;
};

/**
 * Function called for every ct entry returned from listening for conntrack
 * events.
 *
 * Args:
 *   @nlh pointer to the netlink message header.
 *   @data pointer to the data sent to the callback. Here it's an
 *     events_cb_ctx providing both the SAVE-mode config and the stop_flag.
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
    struct events_cb_ctx *ctx;

    if (nlh == NULL) {
        LOG(ERROR, "%s: nlh is NULL", __func__);
        return MNL_CB_OK;
    }
    if (data == NULL) {
        LOG(ERROR, "%s: data is NULL", __func__);
        return MNL_CB_OK;
    }

    ctx = (struct events_cb_ctx *)data;
    if (*ctx->stop_flag) {
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

    if (!validate_ct_entry(type, ct, ctx->save_config->op_type)) {
        goto out;
    }

    /* BPF couldn't pre-filter zone-mode events, so do it in-callback. */
    if (ctx->save_config->op_type == SAVE_PORT_ZONE_OP) {
        uint16_t zone;
        if (!ct_get_migration_zone(ct, &zone)) {
            LOG(WARNING, "%s: event has no zone attribute; skipping.",
                __func__);
            goto out;
        }
        if (!is_zone_in_hashtable(zone, ctx->save_config->zones_to_migrate)) {
            goto out;
        }
    }

    update_conntrack_store(conn_store, ct, type, ctx->save_config->op_type);

out:
    nfct_destroy(ct);
    return MNL_CB_OK;
}

/**
 * Creates a nfct_filter for the IP addresses to migrate.
 *
 * Args:
 * @ips pointer to the GHashTable containing IP addresses.
 * @is_src_filter bool representing if filter is to be applied on the
 *   src field of CT entries.
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
        LOG(ERROR, "%s: Failed to create a filter. %s", __func__,
            strerror(errno));
        exit(EXIT_FAILURE);
    }

    g_hash_table_iter_init(&iter, ips);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        uint32_t ip = GPOINTER_TO_UINT(key);

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

    return filter;
}

/**
 * Listens for the changes in the kernel conntrack table and filter out the
 * events for particular entries based on the filter.
 *
 * This function listens on the netlink socket for the events on particular
 * IPs / CT zones provided via the SAVE-mode config. These events include
 * create/update/deletion of CT entries.
 *
 * In IP mode a BPF filter is attached on the socket so the kernel only
 * delivers events for the relevant IPs. BPF cannot match on CT zone, so
 * in zone mode the socket is left unfiltered and the in-callback dispatch
 * does the zone match.
 *
 * NOTE: this is a blocking call and this function will return only when the
 * callbacks are unregistered on the handle. Set the stop_flag to prevent any
 * further processing and unblock the calling thread.
 *
 * Args:
 *   @nl pointer to the netlink socket.
 *   @save_config SAVE-mode config (mode-aware) used for filtering.
 *   @is_src_filter bool representing whether the filter is to be applied
 *     on the source ip or destination ip address. Ignored in zone mode.
 *   @stop_flag pointer to bool passed to the callbacks to stop processing
 *     any further events.
 *
 * Returns:
 *   0 if the operation was successful. -1 otherwise.
 */
int
listen_for_conntrack_events(struct mnl_socket *nl,
                            struct save_mode_config *save_config,
                            bool is_src_filter,
                            bool *stop_flag)
{
    int ret = 0;
    int fd;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    fd_set readfds;  // for select sync IO
    struct timeval tv = {
        .tv_sec = 2,
        .tv_usec = 0
    };
    struct events_cb_ctx ctx = {
        .save_config = save_config,
        .stop_flag = stop_flag,
    };

    fd = mnl_socket_get_fd(nl);

    // Attach the IP based filter to the socket. BPF can't filter on CT
    // zone, so zone-mode threads run unfiltered and the callback does the
    // zone match in-process. filter / filter_attach_ret live only inside
    // this branch -- the zone path never touches them.
    if (save_config->op_type == SAVE_IPS_OP) {
        struct nfct_filter *filter =
            create_nfct_filter(save_config->ips_to_migrate, is_src_filter);
        int filter_attach_ret = nfct_filter_attach(fd, filter);
        if (filter_attach_ret == -1) {
            LOG(ERROR, "%s: Failed to attach filter to the socket. %s",
                __func__, strerror(errno));
            nfct_filter_destroy(filter);
            return -1;
        }
        nfct_filter_destroy(filter);
    }

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

        ret = mnl_cb_run(buf, ret, 0, 0, conntrack_events_callback, &ctx);
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
 * On nfct_nlmsg_build failure the partial netlink header is left in the
 * buffer but no labels are appended; the caller MUST NOT advance the
 * batch (mnl_nlmsg_batch_next) so the malformed slot gets overwritten by
 * the next entry. Returning the error makes "knowingly enqueue garbage"
 * impossible by construction.
 *
 * Args:
 *   @send_buf buffer to which ct entry is to be appended.
 *   @ct pointer to the conntrack entry to be programmed in CT.
 *   @label pointer to the ct label. If not NULL, label attribute is set
 *     in the conntrack entry.
 *   @seq sequence number for ct entry to be used in the batch.
 *
 * Returns:
 *   0 on success, -1 if nfct_nlmsg_build failed (caller must drop entry).
 */
int
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

    /* Auto-derive the reply tuple from orig only when the wire didn't
     * carry one. Zone-mode payloads explicitly carry the reply 5-tuple
     * (NAT'd flows can have non-swap reply tuples), and SETUP_REPLY would
     * clobber those values. */
    if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_SRC) <= 0) {
        nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
    } else {
        if (nfct_attr_is_set(ct, ATTR_L3PROTO) > 0) {
            uint8_t l3 = nfct_get_attr_u8(ct, ATTR_L3PROTO);
            nfct_set_attr_u8(ct, ATTR_REPL_L3PROTO, l3);
        }
        if (nfct_attr_is_set(ct, ATTR_L4PROTO) > 0) {
            uint8_t l4 = nfct_get_attr_u8(ct, ATTR_L4PROTO);
            nfct_set_attr_u8(ct, ATTR_REPL_L4PROTO, l4);
        }
    }

    if (nfct_nlmsg_build(nlh, ct) < 0) {
        LOG(ERROR, "%s: seq=%d: nfct_nlmsg_build failed: %s. "
            "Dropping this entry; caller must not advance the batch.",
            __func__, seq, strerror(errno));
        return -1;
    }

    if (label != NULL) {
        mnl_attr_put(nlh, CTA_LABELS, CT_LABEL_NUM_WORDS * WORD_SIZE, label);
    }
    return 0;
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
    bool in_migrated, in_on_host;

    if (ct == NULL) {
        LOG(ERROR, "%s: ct is NULL", __func__);
        return NFCT_CB_CONTINUE;
    }
    if (data == NULL) {
        LOG(ERROR, "%s: data is NULL", __func__);
        return NFCT_CB_CONTINUE;
    }

    cb_args = data;

    if (!validate_ct_entry(type, ct, cb_args->op_type)) {
        return NFCT_CB_CONTINUE;
    }

    if (cb_args->op_type == SAVE_IPS_OP) {
        struct in_addr *src_addr, *dst_addr;

        src_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC);
        dst_addr = (struct in_addr *)nfct_get_attr(ct, ATTR_ORIG_IPV4_DST);
        if (src_addr == NULL || dst_addr == NULL) {
            LOG(WARNING, "%s: ct entry with NULL src/dst IP received. "
                "Skipping.", __func__);
            return NFCT_CB_FAILURE;
        }

        in_migrated = is_src_or_dst_in_hashtable(src_addr, dst_addr,
                                                 cb_args->ips_migrated);
        in_on_host  = is_src_or_dst_in_hashtable(src_addr, dst_addr,
                                                 cb_args->ips_on_host);
    } else {   /* SAVE_PORT_ZONE_OP */
        uint16_t zone;
        if (!ct_get_migration_zone(ct, &zone)) {
            LOG(WARNING, "%s: delete-dump entry has no zone attribute; "
                "skipping.", __func__);
            return NFCT_CB_CONTINUE;
        }

        in_migrated = is_zone_in_hashtable(zone, cb_args->zones_migrated);
        in_on_host  = (cb_args->zones_on_host != NULL) &&
                      is_zone_in_hashtable(zone, cb_args->zones_on_host);
    }

    if (in_migrated && !in_on_host) {
        uint32_t ct_id;

        if (nfct_attr_is_set(ct, ATTR_ID) <= 0) {
            LOG(WARNING, "%s: ct entry has no ATTR_ID set; skipping.",
                __func__);
            return NFCT_CB_FAILURE;
        }
        ct_id = nfct_get_attr_u32(ct, ATTR_ID);

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
 *   1. Take a CT dump from the kernel.
 *   2. For each dumped entry, decide via the mode-aware filter
 *      (delete_conntrack_dump_callback) whether it should be deleted.
 *      Selected entries are stolen into a local ct_store.
 *   3. For each entry in ct_store, send NFCT_Q_DESTROY to the kernel.
 *
 * Args:
 *   @handle handle to the netlink socket.
 *   @args   delete-thread arguments. Mode-aware via args->op_type.
 */
static void
_delete_ct_entries(struct nfct_handle *handle, struct ct_delete_args *args)
{
    struct delete_ct_dump_cb_args cb_args;
    int ret, failed, success;
    GHashTable *ct_store; // Hashtable to store the CT entries to be deleted
    GHashTableIter iter;  // Iterator for ct_store
    gpointer key, value = NULL;

    ct_store = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                     NULL, ct_destroy_g_wrapper);

    /* Take conntrack dump to get the entries to be deleted. Both
     * structs now use a tagged union for the per-mode pointers, so
     * we can only touch the arm selected by @op_type. Copying both arms
     * would (a) silently overwrite the active arm with NULLs from the
     * inactive arm via the union overlap and (b) lie about ownership. */
    cb_args.op_type  = args->op_type;
    cb_args.ct_store = ct_store;
    switch (args->op_type) {
    case SAVE_IPS_OP:
        cb_args.ips_migrated = args->ips_migrated;
        cb_args.ips_on_host  = args->ips_on_host;
        break;
    case SAVE_PORT_ZONE_OP:
        cb_args.zones_migrated = args->zones_migrated;
        cb_args.zones_on_host  = args->zones_on_host;
        break;
    }

    ret = _conntrack_dump(handle, delete_conntrack_dump_callback, &cb_args);
    if (ret == -1) {
        LOG(ERROR, "%s: Skipping conntrack delete due to dump"
            " failure", __func__);
        goto finish;
    }

    LOG(INFO, "%s: starting conntrack entry delete (op_type=%s). "
        "Entries to delete %d", __func__,
        convert_save_mode_op_type_to_string(args->op_type),
        g_hash_table_size(cb_args.ct_store));

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

    LOG(INFO, "%s: Finished conntrack entry delete (op_type=%s). "
        "Success: %d, Failed: %d", __func__,
        convert_save_mode_op_type_to_string(args->op_type), success, failed);

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
 * 1. Delete thread is started during initialisation phase of the binary
 *    (in both IP and zone sub-modes; see start_in_save_mode).
 * 2. The migrated set (ips_to_migrate / zones_to_migrate) is pinned on
 *    ct_del_args before this thread is created.
 * 3. The thread waits on the clear_called condition. dbus-server on
 *    Clear IPC populates the "on host" set (ips_on_host / zones_on_host),
 *    and wakes up this thread.
 * 4. The delete procedure is performed afterwards. See _delete_ct_entries
 *    for more details.
 *
 *  Args:
 *    @data Pointer to struct ct_delete_args.
 *
 *  Returns:
 *    NULL
 */
void *
delete_ct_entries(void *data)
{
    struct ct_delete_args *ct_del_args;
    struct nfct_handle *h;

    if (data == NULL) {
        LOG(ERROR, "%s: data is NULL", __func__);
        return NULL;
    }

    ct_del_args = data;

    LOG(INFO, "%s: Starting conntrack delete thread (op_type=%s)", __func__,
        convert_save_mode_op_type_to_string(ct_del_args->op_type));
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

    _delete_ct_entries(h, ct_del_args);
    nfct_close(h);

unlock:
    pthread_mutex_unlock(&ct_del_args->mutex);
    LOG(INFO, "%s: Finished conntrack delete thread", __func__);

    return NULL;
}

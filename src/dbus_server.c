/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the functions that interfaces with dbus.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <gio/gio.h>
#include <glib.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "common.h"
#include "conntrack.h"
#include "conntrack_entry.h"
#include "conntrack_store.h"
#include "ct_delete_args.h"
#include "dbus_server.h"
#include "data_template.h"
#include "dbus_vmstate1.h" // Will be auto-generated
#include "marshal.h"
#include "unmarshal.h"

static GDBusObjectManagerServer *manager = NULL;
static GMainLoop *loop = NULL;
static struct mnl_socket *nl = NULL;

static const char *dbus_name = "org.qemu.VMState1";
static const char *manager_export_path = "/org/qemu";
static const char *object_path = "/org/qemu/VMState1";

static gboolean
complete_on_load(VMState1 *object, GDBusMethodInvocation *invocation)
{
    vmstate1_complete_load(object, invocation);
    g_main_loop_quit(loop);
    return TRUE;
}

/**
 * LOAD-time zone rewrite hook.
 *
 * For each unmarshalled CT entry, looks up its CT zone in the
 * (old_zone -> new_zone) map and overwrites ATTR_ZONE in place. Entries
 * whose old_zone is not in the map are dropped: the source migrated a
 * zone that the destination wasn't told about, which is a control-plane
 * mismatch we'd rather log than silently land in the wrong zone.
 *
 * Note: only ATTR_ZONE is on the wire (see ct_entry_attr_to_nf_attr in
 * conntrack_entry.c); the kernel populates orig/repl-zone from this
 * single value when it inserts the entry.
 *
 * Args:
 *   @ct          pointer to the freshly-unmarshalled nf_conntrack object.
 *   @load_config LOAD-mode config. NULL is treated as legacy pass-through.
 *
 * Returns:
 *   true  -> proceed with this entry (rewrite applied or pass-through).
 *   false -> drop this entry; caller must not append it to the batch.
 */
static bool
apply_zone_rewrite(struct nf_conntrack *ct,
                   const struct load_mode_config *load_config)
{
    uint16_t old_zone, new_zone;
    gpointer val;

    if (ct == NULL) {
        LOG(ERROR, "%s: ct is NULL", __func__);
        return false;
    }

    if (load_config == NULL || load_config->kind == LOAD_INPUT_LEGACY) {
        return true;
    }

    /* Zone-mode LOAD: every entry must carry a CT zone. SAVE-side
     * validate_ct_entry (Step 2) enforces this, but defend anyway so we
     * never silently land an unzoned entry in the kernel's default zone. */
    if (nfct_attr_is_set(ct, ATTR_ZONE) <= 0) {
        LOG(WARNING, "%s: zone-mode LOAD received entry with no ATTR_ZONE; "
            "dropping.", __func__);
        return false;
    }

    old_zone = nfct_get_attr_u16(ct, ATTR_ZONE);

    /* _extended distinguishes "key not in map" from "key maps to value
     * whose GUINT_TO_POINTER is NULL". The latter is a legitimate remap
     * to zone 0; plain g_hash_table_lookup conflates the two and would
     * silently drop a valid old_zone -> 0 mapping. */
    if (!g_hash_table_lookup_extended(load_config->src_dst_zone_map,
                                      GUINT_TO_POINTER((guint) old_zone),
                                      NULL, &val)) {
        LOG(WARNING, "%s: old_zone %u not in src_dst_zone_map; dropping entry.",
            __func__, (unsigned) old_zone);
        return false;
    }
    new_zone = (uint16_t) GPOINTER_TO_UINT(val);

    nfct_set_attr_u16(ct, ATTR_ZONE, new_zone);

    LOG(VERBOSE, "%s: rewrote zone %u -> %u",
        __func__, (unsigned) old_zone, (unsigned) new_zone);
    return true;
}

/**
 * IPC endpoint for Load message.
 *
 * This function is called at the destination host where it receives the
 * conntrack entries from QEMU. Its main responsibility is to program the
 * conntrack entries in kernel conntrack table.
 *
 *   Data format received from QEMU:
 *   - [payload_size | data_template | ct_entry1 ... ct_entry-n]
 *
 *   payload_size - uint32_t : size of the complete array end to end.
 *
 *   data_template format:
 *   - [num_of_bits | size field-1 ... size field-n]
 *
 *   ct_entry format:
 *   - [bitmap | data]
 *
 *   At the end, it calls the g_main_loop_quit(), so that thread can
 *   exit gracefully.
 *
 * Args:
 *   @object VMState1 object on which the RPC is called.
 *   @invocation invocation context
 *   @arg_data arguments passed to the RPC.
 *   @user_data any user data that is passed to the callbacks. Here
 *   it is dbus server thread args (dbus_targs).
 *
 * Returns:
 *   TRUE on success, FALSE otherwise
 */
static gboolean
on_load(VMState1 *object, GDBusMethodInvocation *invocation,
        const gchar *arg_data, gpointer user_data)
{

    struct dbus_targs *targs = user_data;
    GVariant *args, *var;
    gsize size;
    void *payload;
    uint32_t payload_size;
    uint32_t *label = NULL;
    struct data_template data_tmpl;
    struct nf_conntrack *ct;
    uint32_t bytes_read;
    uint32_t total_bytes_read = 0;

    // netlink batch create related variables.
    char send_buf[MNL_SOCKET_BUFFER_SIZE * 2];
    void *curr_batch_offset;
    struct mnl_nlmsg_batch *batch;
    struct timespec tp;
    int seq = 1;

    if (clock_gettime(CLOCK_REALTIME, &tp) != -1) {
        seq = (int)tp.tv_sec;
    }

    LOG(INFO, "%s: Load start", __func__);
    args = g_dbus_method_invocation_get_parameters(invocation);
    var = g_variant_get_child_value(args, 0);
    payload = (void *)g_variant_get_fixed_array(var, &size, sizeof(char));

    if (nl == NULL) {
        LOG(ERROR, "%s: Cannot create conntrack in kernel CT. socket is NULL",
            __func__);
        return complete_on_load(object, invocation);
    }

    if (payload == NULL) {
        LOG(INFO, "%s: Received NULL payload. Exiting.", __func__);
        return complete_on_load(object, invocation);
    }

    ct = nfct_new();
    if (ct == NULL) {
        LOG(ERROR, "%s: cannot allocate nf_conntrack", __func__);
        return complete_on_load(object, invocation);
    }

    // unmarshal payload size
    bytes_read = unmarshal_payload_size(payload, &payload_size);
    payload += bytes_read;
    total_bytes_read += bytes_read;

    if (payload_size == 0) {
        LOG(WARNING, "%s: received payload size as 0", __func__);
        return complete_on_load(object, invocation);
    }

    // unmarshal data_template
    bytes_read = unmarshal_data_template(payload, &data_tmpl);
    payload += bytes_read;
    total_bytes_read += bytes_read;

    // initialise the batch msg
    batch = mnl_nlmsg_batch_start(send_buf, MNL_SOCKET_BUFFER_SIZE);
    if (batch == NULL) {
        LOG(ERROR, "%s: Cannot create a batch.", __func__);
        return complete_on_load(object, invocation);
    }

    // unmarshal conntrack_entry and append it to the batch
    while (total_bytes_read < payload_size) {
        bytes_read = unmarshal_conntrack_entry(payload, &data_tmpl, ct, &label);

        payload += bytes_read;
        total_bytes_read += bytes_read;

        // Apply the LOAD-time zone rewrite (no-op in legacy mode). Entries
        // whose source zone isn't in src_dst_zone_map are dropped here so
        // they never reach the batch builder.
        if (!apply_zone_rewrite(ct, targs->load_config)) {
            label = NULL;
            continue;
        }

        curr_batch_offset = mnl_nlmsg_batch_current(batch);

        // Do the programming here. If the build failed the partial header
        // is left in place at curr_batch_offset; skip mnl_nlmsg_batch_next
        // so the next iteration overwrites it.
        if (append_ct_to_batch(curr_batch_offset, ct, label, seq++) < 0) {
            label = NULL;
            continue;
        }
        label = NULL;
        // If there is space in batch, add the entry to it
        if (mnl_nlmsg_batch_next(batch)) {
            continue;
        }

        // If batch is completed, send it to kernel
        create_batch_conntrack(nl, batch);

        // Reset the batch
        mnl_nlmsg_batch_reset(batch);
    }

    // Send the last batch, if there are entries left in it.
    if (!mnl_nlmsg_batch_is_empty(batch)) {
        create_batch_conntrack(nl, batch);
    }
    mnl_nlmsg_batch_stop(batch);

    LOG(INFO, "%s: Load end. Bytes read %d", __func__, payload_size);
    return complete_on_load(object, invocation);
}

/**
 * RPC endpoint for Save message.
 *
 * This function is called at the source host where it
 *   reads the conntrack entries from conntrack_store and send it to QEMU.
 *
 *   Data format send to QEMU:
 *   - [payload_size | data_template | ct_entry1 ... ct_entry-n]
 *
 *   payload_size - uint32_t : size of the complete array end to end.
 *
 *   data_template format:
 *   - [num_of_bits | size field-1 ... size field-n]
 *
 *   ct_entry format:
 *   - [bitmap | data]
 *
 * Args:
 *   @object VMState1 object on which the RPC is called.
 *   @invocation invocation context
 *   @user_data any user data that is passed to the callbacks. Here
 *     it is dbus server thread args (dbus_targs)
 *
 * Returns:
 *   TRUE on success, FALSE otherwise
 */
static gboolean
on_save(VMState1 *object, GDBusMethodInvocation *invocation, gpointer user_data)
{
    LOG(INFO, "%s: Save start.", __func__);

    struct dbus_targs *targs = user_data;
    struct data_template *data_tmpl;
    uint32_t data_size = 0;
    void *buf;
    GVariant *child;

    // Set the boolean flag to true, so that netlink threads can
    // gracefully exit.
    *(targs->stop_flag) = true;

    data_tmpl = data_template_new(targs->save_kind);

    buf = marshal(conn_store, data_tmpl, &data_size);
    if (buf == NULL) {
        LOG(WARNING, "%s: Buffer allocation failed.", __func__);
        // If buffer is NULL them send only data_size.
        child = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, &data_size,
                                          data_size, UINT8_T_SIZE);
    } else {
        // Send the entries to dbus.
        child = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, buf,
                                          data_size, UINT8_T_SIZE);
    }
    g_variant_ref(child);
    g_dbus_method_invocation_return_value(invocation,
                                          g_variant_new("(@ay)", child));
    data_template_destroy(data_tmpl);
    free(buf);
    g_variant_unref(child);

    LOG(INFO, "%s: Save completed. Bytes sent: %d", __func__, data_size);
    return TRUE;
}

static gboolean
complete_on_clear(LmctMgmt *object, GDBusMethodInvocation *invocation)
{
    lmct_mgmt_complete_clear(object, invocation);
    g_main_loop_quit(loop);
    return TRUE;
}

/**
 * RPC endpoint for Clear message.
 *
 * Called at the source host at the end of a successful migration to
 * remove the CT entries of the VM that has been migrated.
 *
 * Payload shape, in both modes, is "as" (array of strings). The
 * interpretation depends on the helper's active SAVE sub-mode, which
 * is fixed at start-up in start_in_save_mode and recorded on
 * ct_del_args.kind (an extern global declared in ct_delete_args.h):
 *
 *   - IP mode  (SAVE_INPUT_IPS)        : each string is an IPv4 address
 *                                        currently present on this host.
 *   - Zone mode (SAVE_INPUT_PORT_ZONES): a flat strv of paired entries
 *                                        [port_uuid_0, zone_0,
 *                                         port_uuid_1, zone_1, ...] where
 *                                        each zone is a decimal CT zone
 *                                        currently owned by the named
 *                                        port still on this host. Length
 *                                        must be even; the helper only
 *                                        retains the zone half.
 *
 * On success the parsed set is published to ct_del_args under the lock,
 * the clear_called condition is signalled, and the delete thread wakes
 * up to do the actual NFCT_Q_DESTROY work.
 *
 * NOTE: the reason for performing this operation asynchronously is that
 * migrate task should not be held up just for the cleanup. And also since
 * we are aiming for the best effort cleanup cases, async is a better choice.
 *
 * NOTE2: In case on-clear IPC is not invoked, manual cleanup is required
 * before starting the new migration of this VM from/to this host.
 *
 * Args:
 *   @object LmctMgmt object on which the RPC is called.
 *   @invocation invocation context
 *   @arg_data arguments passed to the RPC.
 *   @user_data any user data that is passed to the callbacks. Here
 *     it is dbus server thread args (dbus_targs).
 *
 * Returns
 *   TRUE on success, FALSE otherwise
 */
static gboolean
on_clear(LmctMgmt *object, GDBusMethodInvocation *invocation,
                 const gchar *arg_data, gpointer user_data)
{
    LOG(INFO, "%s: Clear start (kind=%s)", __func__,
        save_input_kind_to_string(ct_del_args.kind));
    GVariant *args, *var;
    gsize num_entries = 0;
    char **payload;
    GHashTable *ips_on_host   = NULL;
    GHashTable *zones_on_host = NULL;
    bool parse_ok;

    args = g_dbus_method_invocation_get_parameters(invocation);
    var = g_variant_get_child_value(args, 0);
    payload = g_variant_dup_strv(var, &num_entries);

    /* Both downstream parsers take an int. g_variant_dup_strv reports a
     * gsize, so guard against a (theoretical) D-Bus payload that would
     * silently narrow to a negative or truncated int on the call below.
     * In practice num_entries is tiny, but failing fast at the IPC
     * boundary is cheaper than reasoning about it later. */
    if (num_entries > INT_MAX) {
        LOG(ERROR, "%s: clear payload too large for int (%zu entries)",
            __func__, num_entries);
        g_strfreev(payload);
        return complete_on_clear(object, invocation);
    }

    /* Zone-mode clear payload is paired (port_uuid, zone). Catch a
     * malformed odd-length strv up front so the parser doesn't have to
     * own this protocol-level invariant on its own. */
    if (ct_del_args.kind == SAVE_INPUT_PORT_ZONES &&
        (num_entries % 2) != 0) {
        LOG(ERROR, "%s: zone-mode clear payload must be paired "
            "(port_uuid, zone); got odd length %zu",
            __func__, num_entries);
        g_strfreev(payload);
        return complete_on_clear(object, invocation);
    }

    if (ct_del_args.kind == SAVE_INPUT_IPS) {
        ips_on_host = create_hashtable_from_ip_list(
                          (const char **)payload, (int) num_entries);
        parse_ok = (ips_on_host != NULL);
    } else {   /* SAVE_INPUT_PORT_ZONES */
        zones_on_host = create_hashtable_from_port_zone_pairs(
                            (const char **)payload, (int) num_entries);
        parse_ok = (zones_on_host != NULL);
    }
    g_strfreev(payload);

    if (!parse_ok) {
        LOG(ERROR, "%s: Failed to parse %s payload", __func__,
            ct_del_args.kind == SAVE_INPUT_IPS ? "ips_on_host"
                                              : "zones_on_host");
        return complete_on_clear(object, invocation);
    }

    pthread_mutex_lock(&ct_del_args.mutex);
    if (ct_del_args.kind == SAVE_INPUT_IPS) {
        ct_del_args.ips_on_host = ips_on_host;
    } else {
        ct_del_args.zones_on_host = zones_on_host;
    }
    ct_del_args.clear_called = true;
    pthread_cond_signal(&ct_del_args.clear_called_cond);
    pthread_mutex_unlock(&ct_del_args.mutex);

    if (ct_del_args.kind == SAVE_INPUT_IPS) {
        LOG(INFO, "%s: Clear completed (received %zu IPs)",
            __func__, num_entries);
    } else {
        LOG(INFO, "%s: Clear completed (received %zu port/zone pairs)",
            __func__, num_entries / 2);
    }
    return complete_on_clear(object, invocation);
}

/**
 * Function called when the connection to dbus is successful.
 *
 * After conecting to dbus, this function exports the
 * dbus-vmstate1 objects at the given path. Also register the
 * handle_load, handle_save and handle_clear interface functions.
 *
 * Args:
 *  @connection dbus_connection object
 *  @name The name that is requested to be owned on dbus.
 *  @user_data any user data that is passed to the callbacks. Here
 *         it is dbus server thread args (dbus_targs).
 */
static void
on_bus_acquired(GDBusConnection *connection, const gchar *name,
                gpointer user_data)
{
    LOG(INFO, "%s: Acquired a message bus connection.", __func__);

    manager = g_dbus_object_manager_server_new(manager_export_path);
    struct dbus_targs *args = user_data;
    VMState1 *vmstate1_obj;
    const gchar *helper_id = args->helper_id;
    vmstate1_obj = vmstate1_skeleton_new();
    vmstate1_set_id(vmstate1_obj, helper_id);
    g_signal_connect(vmstate1_obj,
                     "handle_load",
                     G_CALLBACK(on_load),
                     user_data);
    g_signal_connect(vmstate1_obj,
                     "handle_save",
                     G_CALLBACK(on_save),
                     user_data);

    LmctMgmt *lmct_mgmt_obj;
    lmct_mgmt_obj = lmct_mgmt_skeleton_new();
    lmct_mgmt_set_id(lmct_mgmt_obj, helper_id);
    g_signal_connect(lmct_mgmt_obj,
                     "handle_clear",
                     G_CALLBACK(on_clear),
                     user_data);

    ObjectSkeleton *obj_skeleton;
    const gchar *g_obj_path;
    g_obj_path  = g_strdup_printf("%s", object_path);
    obj_skeleton = object_skeleton_new(g_obj_path);
    g_free((gpointer)g_obj_path);
    object_skeleton_set_vmstate1(obj_skeleton, vmstate1_obj);
    object_skeleton_set_lmct_mgmt(obj_skeleton, lmct_mgmt_obj);

    GDBusObjectSkeleton *gdbus_obj_skeleton;
    gdbus_obj_skeleton = G_DBUS_OBJECT_SKELETON(obj_skeleton);
    g_dbus_object_manager_server_export(manager, gdbus_obj_skeleton);
    g_object_unref(obj_skeleton);
    g_object_unref(vmstate1_obj);

    g_dbus_object_manager_server_set_connection(manager, connection);
}

/**
 * Function called when this process becomes the owner of requested name on
 * dbus.
 *
 * Args:
 *   @connection dbus_connection object
 *   @name The name being owned on dbus
 *   @user_data any user data that is passed to the callbacks. Here
 *   it is dbus server thread args (dbus_targs).
 */
static void
on_name_acquired(GDBusConnection *connection, const gchar *name,
                 gpointer user_data)
{
    LOG(INFO, "%s: Acquired the name %s", __func__, name);
}

/**
 * Function called when this process loses ownership of requested name on dbus.
 * This can happen if we are connecting to a dbus which already has an owner.
 *
 * Args:
 *   @connection dbus_connection object
 *   @name The name being owned on dbus
 *   @user_data any user data that is passed to the callbacks. Here
 *     it is dbus server thread args (dbus_targs).
 */
static void
on_name_lost(GDBusConnection *connection, const gchar *name,
             gpointer user_data)
{
    LOG(WARNING, "%s: Lost the name %s.", __func__, name);
}

/**
 * Creates a mnl socket connection to netlink to program conntrack entries.
 *
 * Returns:
 *   0 if successful, -1 otherwise.
 */
static int
connect_to_netlink_conntrack(void)
{
    int buffersize = 16 * 1024 * 1024;
    int on = 1;
    int ret = 0;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        LOG(ERROR, "%s: Failed to open mnl socket. %s", __func__,
            strerror(errno));
        return -1;
    }

    // Increase buffer size to 16MB to accomodate 10k-100k ct entries.
    ret = setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVBUFFORCE,
                     &buffersize, sizeof(int));
    if (ret != 0) {
        LOG(ERROR, "%s: Failed to set the socket size. %s", __func__,
            strerror(errno));
        goto err;
    }

    ret = mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &on, sizeof(int));
    if (ret != 0) {
        LOG(ERROR, "%s: Failed to set the socket options. %s", __func__,
            strerror(errno));
        goto err;
    }

    ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
    if (ret != 0) {
        LOG(ERROR, "%s: Failed to bind to mnl socket. %s", __func__,
             strerror(errno));
        goto err;
    }

    return 0;

err:
    mnl_socket_close(nl);
    nl = NULL;
    return ret;
}

/**
 * Asks the dbus thread to exit its main loop gracefully.
 *
 * See declaration in dbus_server.h for the full contract.
 */
void
dbus_server_request_quit(struct dbus_targs *targs)
{
    if (targs == NULL) {
        return;
    }

    pthread_mutex_lock(&targs->loop_mu);
    targs->should_quit = true;
    if (targs->loop != NULL) {
        g_main_loop_quit(targs->loop);
    }
    pthread_mutex_unlock(&targs->loop_mu);
}

/**
 * Starts the dbus server.
 *
 * This function performs the following tasks:
 *  - connect to the mnl socket for programming of CT entries.
 *  - connect to the session dbus. DBUS_SESSION_BUS_ADDRESS environment
 *    variable must be set. otherwise it will connect to default session
 *    dbus.
 *  - create a dbus-vmstate1 object with the helper-id passed.
 *  - register the handle_load and handle_save interface functions.
 *
 * Args:
 * @data user data passed to the functions. Here it is a dbus_targs struct.
 */
void *
dbus_server_init(void *data)
{
    guint dbus_id;
    GMainLoop *local_loop;
    bool quit_early;

    struct dbus_targs *targs = data;

    // If we are operating in save mode, connect to netlink for CT programming
    if (targs->mode == LOAD_MODE) {
        int ret = connect_to_netlink_conntrack();

        // we are not taking any action if there is any error in case of
        // connecting to netlink conntrack. Migrating CT entries is done on a
        // best effort basis and if for some reason we can't open netlink
        // socket, we will ignore the incoming conntrack entries.
        if (ret == 0) {
            LOG(INFO, "%s: Successfully connected to netlink socket for CT "
                "programming", __func__);
        }
    }

    /* Publish the loop atomically with the should_quit check so any quit
     * request that arrived while we were still booting is honoured before
     * we ever enter g_main_loop_run. Mirroring to the file-static `loop`
     * keeps complete_on_load / complete_on_clear working unchanged. */
    local_loop = g_main_loop_new(NULL, FALSE);
    pthread_mutex_lock(&targs->loop_mu);
    targs->loop = local_loop;
    loop = local_loop;
    quit_early = targs->should_quit;
    pthread_mutex_unlock(&targs->loop_mu);

    if (quit_early) {
        LOG(INFO, "%s: shutdown requested before loop start; exiting.",
            __func__);
        pthread_mutex_lock(&targs->loop_mu);
        targs->loop = NULL;
        loop = NULL;
        pthread_mutex_unlock(&targs->loop_mu);
        g_main_loop_unref(local_loop);
        *(targs->stop_flag) = true;
        return NULL;
    }

    dbus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
                             dbus_name,
                             G_BUS_NAME_OWNER_FLAGS_NONE,
                             on_bus_acquired,
                             on_name_acquired,
                             on_name_lost,
                             data,
                             NULL);

    g_main_loop_run(local_loop);
    g_bus_unown_name(dbus_id);

    pthread_mutex_lock(&targs->loop_mu);
    targs->loop = NULL;
    loop = NULL;
    pthread_mutex_unlock(&targs->loop_mu);
    g_main_loop_unref(local_loop);

    // Set the boolean flag to true, so that netlink threads can
    // gracefully exit
    *(targs->stop_flag) = true;

    return NULL;
}

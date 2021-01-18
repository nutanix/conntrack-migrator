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
    int seq = time(NULL);

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

        curr_batch_offset = mnl_nlmsg_batch_current(batch);

        // Do the programming here
        append_ct_to_batch(curr_batch_offset, ct, label, seq++);
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

    data_tmpl = data_template_new();

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
 * This function is called at the source host. At the end of
 * successful migration, we want to remove the CT entries of the VM that has
 * been migrated from the host. This function receives the list of ip_address
 * that are currently present on this host. The list of ip_address that have
 * been migrated are already available to us when we started the helper.
 * Thus, on receiving the clear call we signal the conntrack delete thread to
 * clear the migrated conntrack entries.
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
    LOG(INFO, "%s: Clear start", __func__);
    GVariant *args, *var;
    gsize num_ip_address;
    char **ip_addresses;
    GHashTable *ips_on_host;

    args = g_dbus_method_invocation_get_parameters(invocation);
    var = g_variant_get_child_value(args, 0);
    ip_addresses = g_variant_dup_strv(var, &num_ip_address);

    ips_on_host = create_hashtable_from_ip_list((const char **)ip_addresses,
                                                num_ip_address);
    g_strfreev(ip_addresses);
    if (ips_on_host == NULL) {
        LOG(ERROR, "%s: Failed to create ips_on_host", __func__);
        return complete_on_clear(object, invocation);
    }

    pthread_mutex_lock(&ct_del_args.mutex);
    ct_del_args.ips_on_host = ips_on_host;
    ct_del_args.clear_called = true;
    pthread_cond_signal(&ct_del_args.clear_called_cond);
    pthread_mutex_unlock(&ct_del_args.mutex);

    LOG(INFO, "%s: Clear completed", __func__);
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
    loop = g_main_loop_new(NULL, FALSE);
    dbus_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
                             dbus_name,
                             G_BUS_NAME_OWNER_FLAGS_NONE,
                             on_bus_acquired,
                             on_name_acquired,
                             on_name_lost,
                             data,
                             NULL);

    g_main_loop_run(loop);
    g_bus_unown_name(dbus_id);
    g_main_loop_unref(loop);

    // Set the boolean flag to true, so that netlink threads can
    // gracefully exit
    *(targs->stop_flag) = true;

    return NULL;
}

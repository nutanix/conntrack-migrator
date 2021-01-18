/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <check.h>
#include <glib.h>
#include <gio/gio.h>
#include <pthread.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libmnl/libmnl.h>

#include "dbus_vmstate1.h"
#include "dbus_server.h"
#include "ct_delete_args.h"
#include "data_template.h"
#include "conntrack_store.h"
#include "marshal.h"
#include "unmarshal.h"
#include "conntrack.h"

struct ct_delete_args ct_del_args = {
    .ips_migrated = NULL,
    .ips_on_host = NULL,
    .clear_called = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .clear_called_cond = PTHREAD_COND_INITIALIZER
};

struct conntrack_store *conn_store;

//=====================START of dependencies==================================

bool fail_marshal = false;
bool fail_clear = false;
bool fail_load = false;
int batch_size = 0;
int load_size = 0;
int fail_netlink = false;

struct data_template *
data_template_new(void)
{
    return NULL;
}

void
data_template_destroy(struct data_template *data_tmpl)
{
    return;
}

// this is used in CLEAR ipc only.
GHashTable *
create_hashtable_from_ip_list(const char *ip_list[],  int num_ips)
{
    if (fail_clear) {
        return NULL;
    }

    return g_hash_table_new(g_direct_hash, g_direct_equal);
}

// This is used in save ipc only.
void *
marshal(struct conntrack_store *conn_store, struct data_template *tmpl,
              uint32_t *data_size)
{
    char *buf;
    int written = 0;

    if (fail_marshal) {
        *data_size = sizeof(uint32_t);
        return NULL;
    }

    buf = g_malloc(sizeof(char) * 10);
    written = snprintf(buf, 10, "save");
    *data_size = written + 1;

    return buf;
}

uint32_t
unmarshal_payload_size(void *start, uint32_t *payload_size)
{
    if (fail_load) {
        *payload_size = 0;
        return 0;
    }

    *payload_size = load_size;
    return sizeof(uint32_t);
}

uint32_t
unmarshal_data_template(void *start, struct data_template *tmpl)
{
    return sizeof(uint32_t);
}

uint32_t
unmarshal_conntrack_entry(void *start, struct data_template *data_tmpl,
                          struct nf_conntrack *ct, uint32_t **label)
{
    return sizeof(uint32_t);
}

int
create_batch_conntrack(struct mnl_socket *nl, struct mnl_nlmsg_batch *batch)
{
    return -1;
}

void
append_ct_to_batch(char *send_buf, struct nf_conntrack *ct,
                   uint32_t *label, int seq)
{
    if (batch_size > 0) {
        return;
    }

    // For 0 batch_size, append one entry to it.
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfh;

    nlh = mnl_nlmsg_put_header(send_buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
    nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE|NLM_F_ACK;
    nlh->nlmsg_seq = seq;

    nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
    nfh->nfgen_family = AF_INET;
    nfh->version = NFNETLINK_V0;
    nfh->res_id = 0;

    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
    nfct_nlmsg_build(nlh, ct);

    batch_size++;
}

int
mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid)
{
    if (fail_netlink) {
        return -1;
    }

    return 0;
}
//============================================================================

//////////////////////////////////////////////////////////////////////////////
//Helper functions and struct for creating a test dbus client
struct save_ret {
    const char *data;
    gsize size;
};

GDBusConnection *
create_client(const char *dbus_addr)
{
    g_autoptr(GError) err = NULL;
    GDBusConnection *bus;

    bus = g_dbus_connection_new_for_address_sync(dbus_addr,
            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
            G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
            NULL, NULL, &err);
    ck_assert_msg(err == NULL, "Error connecting to dbus: %s",
                  err ? err->message : "");

    return bus;
}

void
close_dbus(GDBusConnection *bus)
{
    g_autoptr(GError) err = NULL;

    g_dbus_connection_close_sync(bus, NULL, &err);
    ck_assert_msg(err == NULL, "Error closing connection to dbus: %s",
                  err ? err->message : "");
}

GDBusProxy *
get_dbus_vmstate_proxy(GDBusConnection *bus)
{
    GDBusProxy *proxy = NULL;
    g_autoptr(GError) error = NULL;

    proxy = g_dbus_proxy_new_sync(bus, G_DBUS_PROXY_FLAGS_NONE,
                                  vmstate1_interface_info(),
                                  "org.qemu.VMState1", // well known name
                                  "/org/qemu/VMState1", // object path
                                  "org.qemu.VMState1",
                                  NULL, &error);
    ck_assert_msg(error == NULL, "Error connecting to dbus: %s",
                  error ? error->message : "");

    return proxy;
}

GDBusProxy *
get_lmct_mgmt_proxy(GDBusConnection *bus)
{
    GDBusProxy *proxy = NULL;
    g_autoptr(GError) error = NULL;

    proxy = g_dbus_proxy_new_sync(bus, G_DBUS_PROXY_FLAGS_NONE,
                                  lmct_mgmt_interface_info(),
                                  "org.qemu.VMState1", // well known name
                                  "/org/qemu/VMState1", // object path
                                  "org.qemu.lmct.Mgmt", // interface name
                                  NULL, &error);
    ck_assert_msg(error == NULL, "Error connecting to dbus: %s",
                  error ? error->message : "");

    return proxy;
}

void
call_load_for_test(GDBusProxy *proxy, const void *data, size_t size)
{
    g_autoptr(GError) err = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value = NULL;

    value = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE,
                                      data, size, sizeof(char));
    result = g_dbus_proxy_call_sync(proxy, "Load",
                                    g_variant_new("(@ay)",
                                    g_steal_pointer(&value)),
                                    G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                    -1, NULL, &err);

    ck_assert_msg(err == NULL, "Failed to load %s", err ? err->message : "");
}

struct save_ret *
call_save_for_test(GDBusProxy *proxy)
{
    g_autoptr(GError) err = NULL;
    GVariant *result = NULL;
    GVariant *child = NULL;
    struct save_ret *ret;

    ret = g_malloc(sizeof(struct save_ret *));

    result = g_dbus_proxy_call_sync(proxy, "Save",
                                    NULL, G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                    -1, NULL, &err);
    ck_assert_msg(err == NULL, "Failed to save %s", err ? err->message : "");

    child = g_variant_get_child_value(result, 0);
    ret->data = g_variant_get_fixed_array(child, &ret->size, sizeof(char));

    return ret;
}

void
call_clear_for_test(GDBusProxy *proxy, GStrv data)
{
    g_autoptr(GError) err = NULL;
    g_autoptr(GVariant) result = NULL;
    g_autoptr(GVariant) value = NULL;

    // -1 since our strings are null terminated.
    value = g_variant_new_strv((const gchar * const *)data, -1);
    result = g_dbus_proxy_call_sync(proxy, "Clear",
                                    g_variant_new("(@as)",
                                    g_steal_pointer(&value)),
                                    G_DBUS_CALL_FLAGS_NO_AUTO_START,
                                    -1, NULL, &err);

    ck_assert_msg(err == NULL, "Failed to load %s", err ? err->message : "");
}

pthread_t
create_dbus_thread(const char *helper_id, int mode, bool *stop_flag)
{
    struct dbus_targs *args = NULL;
    int ret;

    args = g_malloc(sizeof(struct dbus_targs));
    args->helper_id = helper_id;
    args->stop_flag = stop_flag;
    args->mode = mode;

    ret = pthread_create(&args->tid, NULL, dbus_server_init, args);
    ck_assert_msg(ret == 0, "Failed to create dbus thread. %s",
                  strerror(ret));

    return args->tid;
}
//////////////////////////////////////////////////////////////////////////////

START_TEST(test_src_save_pass_clear_fail)
{
    const char address[] = "unix:path=/tmp/dbus/system_bus_socket";
    const char helper_id[] = "helper_test_save";
    bool stop_flag = false;
    GDBusConnection *client;
    GDBusProxy *proxy;
    struct save_ret *ret;
    pthread_t tid;

    // create a client
    client = create_client(address);

    // start the dbus server in a diff thread
    tid = create_dbus_thread(helper_id, SAVE_MODE, &stop_flag);
    sleep(2); // sleep for 2 secs to get the server active.

    // call save
    proxy = get_dbus_vmstate_proxy(client);
    fail_marshal = false;
    ret = call_save_for_test(proxy);

    // verify
    ck_assert(ret->data != NULL);
    ck_assert(ret->size != 0);
    ck_assert_msg(strcmp("save", ret->data) == 0,
                  "expected: save, got: %s\n", ret->data);

    // call clear
    proxy = get_lmct_mgmt_proxy(client);
    GStrv ips = g_new(char *, 2);
    ips[0] = g_strdup("1.2.3.4");
    ips[1] = NULL;
    fail_clear = true;
    call_clear_for_test(proxy, ips);

    pthread_join(tid, NULL);
}
END_TEST

START_TEST(test_src_save_fail_clear_fail)
{
    const char address[] = "unix:path=/tmp/dbus/system_bus_socket";
    const char helper_id[] = "helper_test_save";
    bool stop_flag = false;
    GDBusConnection *client;
    GDBusProxy *proxy;
    struct save_ret *ret;

    // create a client
    client = create_client(address);

    // start the dbus server in a diff thread
    pthread_t tid = create_dbus_thread(helper_id, SAVE_MODE, &stop_flag);
    sleep(2); // sleep for 2 secs to get the server active.

    proxy = get_dbus_vmstate_proxy(client);
    fail_marshal = true;
    ret = call_save_for_test(proxy);
    fail_marshal = false;

    // verify
    ck_assert(ret->data != NULL);
    ck_assert(ret->size != 0);

    // call clear
    proxy = get_lmct_mgmt_proxy(client);
    GStrv ips = g_new(char *, 2);
    ips[0] = g_strdup("1.2.3.4");
    ips[1] = NULL;
    fail_clear = true;
    call_clear_for_test(proxy, ips);

    pthread_join(tid, NULL);
}
END_TEST

START_TEST(test_src_save_fail_clear_pass)
{
    const char address[] = "unix:path=/tmp/dbus/system_bus_socket";
    const char helper_id[] = "helper_test_save";

    GDBusConnection *client;
    GDBusProxy *proxy;
    bool stop_flag = false;
    struct save_ret *ret;

    // create a client
    client = create_client(address);

    // start the dbus server in a diff thread
    pthread_t tid = create_dbus_thread(helper_id, SAVE_MODE, &stop_flag);
    sleep(2); // sleep for 2 secs to get the server active.

    proxy = get_dbus_vmstate_proxy(client);
    fail_marshal = true;
    ret = call_save_for_test(proxy);
    fail_marshal = false;
    ck_assert(ret->data != NULL);
    ck_assert(ret->size != 0);

    // call clear
    // prepare ct_del_args
    ct_del_args.clear_called = false;

    proxy = get_lmct_mgmt_proxy(client);
    GStrv ips = g_new(char *, 2);
    ips[0] = g_strdup("1.2.3.4");
    ips[1] = NULL;

    fail_clear = false;
    call_clear_for_test(proxy, ips);
    ck_assert(ct_del_args.clear_called == true);

    pthread_join(tid, NULL);
}
END_TEST

START_TEST(test_src_save_pass_clear_pass)
{
    const char address[] = "unix:path=/tmp/dbus/system_bus_socket";
    const char helper_id[] = "helper_test_save";

    GDBusConnection *client;
    bool stop_flag = false;
    GDBusProxy *proxy;
    struct save_ret *ret;

    // create a client
    client = create_client(address);

    // start the dbus server in a diff thread
    pthread_t tid = create_dbus_thread(helper_id, SAVE_MODE, &stop_flag);
    sleep(2); // sleep for 2 secs to get the server active.

    // call save
    proxy = get_dbus_vmstate_proxy(client);
    fail_marshal = false;
    ret = call_save_for_test(proxy);

    ck_assert(ret->data != NULL);
    ck_assert(ret->size != 0);
    ck_assert_msg(strcmp("save", ret->data) == 0,
                  "expected: save, got: %s\n", ret->data);

    // prepare ct_del_args
    ct_del_args.clear_called = false;

    // call clear
    proxy = get_lmct_mgmt_proxy(client);
    GStrv ips = g_new(char *, 2);
    ips[0] = g_strdup("1.2.3.4");
    ips[1] = NULL;

    fail_clear = false;
    call_clear_for_test(proxy, ips);
    ck_assert(ct_del_args.clear_called == true);

    pthread_join(tid, NULL);
}
END_TEST

START_TEST(test_dst_load_payload_zero)
{
    const char address[] = "unix:path=/tmp/dbus/system_bus_socket";
    const char helper_id[] = "helper_test_save";
    const char data[] = "load";

    GDBusConnection *client;
    GDBusProxy *proxy;
    bool stop_flag = false;

    // create a client
    client = create_client(address);

    fail_netlink = false;
    // start the dbus server in a diff thread
    pthread_t tid = create_dbus_thread(helper_id, LOAD_MODE, &stop_flag);
    sleep(2); // sleep for 2 secs to get the server active.

    // call load
    fail_load = true;
    proxy = get_dbus_vmstate_proxy(client);
    call_load_for_test(proxy, data, 5);
    pthread_join(tid, NULL);
}
END_TEST

START_TEST(test_dst_load_netlink_fail)
{
    const char address[] = "unix:path=/tmp/dbus/system_bus_socket";
    const char helper_id[] = "helper_test_save";
    const char data[] = "load";

    GDBusConnection *client;
    GDBusProxy *proxy;
    bool stop_flag = false;

    // create a client
    client = create_client(address);

    fail_netlink = true;
    // start the dbus server in a diff thread
    pthread_t tid = create_dbus_thread(helper_id, LOAD_MODE, &stop_flag);
    sleep(2); // sleep for 2 secs to get the server active.

    // call load
    fail_load = true;
    proxy = get_dbus_vmstate_proxy(client);
    call_load_for_test(proxy, data, 5);
    pthread_join(tid, NULL);
}
END_TEST

START_TEST(test_dst_load_pass)
{
    const char address[] = "unix:path=/tmp/dbus/system_bus_socket";
    const char helper_id[] = "helper_test_save";

    GDBusConnection *client;
    GDBusProxy *proxy;
    bool stop_flag = false;
    uint32_t data[3] = { 1, 2, 3 };

    // create a client
    client = create_client(address);
    fail_netlink = false;

    // start the dbus server in a diff thread
    pthread_t tid = create_dbus_thread(helper_id, LOAD_MODE, &stop_flag);
    sleep(2); // sleep for 2 secs to get the server active.

    // call load
    fail_load = false;
    batch_size = 0;
    load_size = sizeof(uint32_t) * 3;
    proxy = get_dbus_vmstate_proxy(client);
    call_load_for_test(proxy, data, load_size);
    pthread_join(tid, NULL);
}
END_TEST

Suite *
dbus_server_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("DbusServer");

    /* Core test case */
    tc_core = tcase_create("Core");
    tcase_set_timeout(tc_core, 120);

    tcase_add_test(tc_core, test_src_save_pass_clear_fail);
    tcase_add_test(tc_core, test_src_save_fail_clear_fail);
    tcase_add_test(tc_core, test_src_save_fail_clear_pass);
    tcase_add_test(tc_core, test_src_save_pass_clear_pass);
    tcase_add_test(tc_core, test_dst_load_payload_zero);
    tcase_add_test(tc_core, test_dst_load_netlink_fail);
    tcase_add_test(tc_core, test_dst_load_pass);

    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = dbus_server_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

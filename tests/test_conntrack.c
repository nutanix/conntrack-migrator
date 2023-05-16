/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include <check.h>
#include <glib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <libmnl/libmnl.h>
#include <pthread.h>

#include "conntrack_store.h"
#include "conntrack.h"

//====================Start of dependencies===================================
struct conntrack_store *conn_store;
bool stop_flag = false;

struct conntrack_store *
create_conntrack_store(void)
{
    struct conntrack_store *store;
    store = g_malloc(sizeof(struct conntrack_store));

    store->store = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                         NULL, NULL);
    pthread_mutex_init(&store->lock, NULL);
    return store;
}

uint32_t insert_id = 1;
uint32_t update_id = 2;

void
update_conntrack_store(struct conntrack_store *conn_store,
                       struct nf_conntrack *ct,
                       enum nf_conntrack_msg_type type)
{
    // for the purpose of testing we are using ct mark as id. because
    // ct_id is not known while programming so validation becomes easier.
    uint32_t ct_mark;
    struct nf_conntrack *ct_clone = nfct_clone(ct);
    ct_mark = nfct_get_attr_u32(ct, ATTR_MARK);

    switch(type) {
    case NFCT_T_NEW:
        printf("Received new event!! %d\n\n", ct_mark);
        g_hash_table_insert(conn_store->store, GUINT_TO_POINTER(ct_mark),
                            ct_clone);
        break;
    case NFCT_T_UPDATE:
        printf("Received update event!! %d\n\n", ct_mark);
        g_hash_table_insert(conn_store->store, GUINT_TO_POINTER(ct_mark),
                            ct_clone);
        break;
    case NFCT_T_DESTROY:
        printf("Received delete event!! %d\n\n", ct_mark);
        g_hash_table_remove(conn_store->store, GUINT_TO_POINTER(ct_mark));
        break;
    default:
        break;
    }
}
//=========================End of dependencies=================================

//=========================Start of HELPER Functions =========================
GHashTable *
ht_from_ip_list(const char *ip_list[], int num_ips)
{
    int i;
    GHashTable *ht;
    ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    for (i = 0; i < num_ips; i++) {
        struct in_addr ip;
        inet_aton(ip_list[i], &ip);
        g_hash_table_insert(ht, GUINT_TO_POINTER(ip.s_addr),
                            GINT_TO_POINTER(1));
    }
    return ht;
}

struct nf_conntrack *
ct_new(const char *src_ip, const char *dst_ip,
       uint16_t src_port, uint16_t dst_port,
       enum tcp_state state, uint32_t timeout,
       uint32_t mark)
{
    struct nf_conntrack *ct;

    ct = nfct_new();
    if (!ct) {
        perror("nfct_new");
        return NULL;
    }

    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr(src_ip));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr(dst_ip));

    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(src_port));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(dst_port));

    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

    nfct_set_attr_u8(ct, ATTR_TCP_STATE, state);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
    nfct_set_attr_u32(ct, ATTR_MARK, mark);

    return ct;
}

struct nf_conntrack *
ct_new_ipv6(const char *src_ip, const char *dst_ip,
       uint16_t src_port, uint16_t dst_port,
       enum tcp_state state, uint32_t timeout,
       uint32_t mark)
{
    struct nf_conntrack *ct;
    struct in6_addr src, dst;
    int ret;

    ct = nfct_new();
    if (!ct) {
        perror("nfct_new");
        return NULL;
    }
    ret = inet_pton(AF_INET6, src_ip, &src);
    ck_assert(ret == 1);
    ret = inet_pton(AF_INET6, dst_ip, &dst);
    ck_assert(ret == 1);

    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET6);
    nfct_set_attr(ct, ATTR_IPV6_SRC, &src);
    nfct_set_attr(ct, ATTR_IPV6_DST, &dst);

    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(src_port));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(dst_port));

    nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);

    nfct_set_attr_u8(ct, ATTR_TCP_STATE, state);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
    nfct_set_attr_u32(ct, ATTR_MARK, mark);

    return ct;
}

int
conntrack_op_for_test(struct nf_conntrack *ct_list[], int num,
                      enum nf_conntrack_query op)
{
    struct nfct_handle *h;
    int i,ret;

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        printf("(%s)\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < num; i++) {
        ret = nfct_query(h, op, ct_list[i]);
        if (ret == -1) {
            printf("(%d)(%s)\n", ret, strerror(errno));
            return -1;
        }
    }

    nfct_close(h);
    return 0;
}

void
verify_ct(struct nf_conntrack *ct1, struct nf_conntrack *ct2)
{
    ck_assert((nfct_get_attr_u8(ct1, ATTR_L4PROTO) ==
               nfct_get_attr_u8(ct2, ATTR_L4PROTO)));

    ck_assert((nfct_get_attr_u8(ct1, ATTR_L3PROTO) ==
               nfct_get_attr_u8(ct2, ATTR_L3PROTO)));

    ck_assert((nfct_get_attr_u32(ct1, ATTR_IPV4_SRC) ==
               nfct_get_attr_u32(ct2, ATTR_IPV4_SRC)));

    ck_assert((nfct_get_attr_u32(ct1, ATTR_IPV4_DST) ==
               nfct_get_attr_u32(ct2, ATTR_IPV4_DST)));

    ck_assert((nfct_get_attr_u16(ct1, ATTR_PORT_SRC) ==
               nfct_get_attr_u16(ct2, ATTR_PORT_SRC)));

    ck_assert((nfct_get_attr_u16(ct1, ATTR_PORT_DST) ==
               nfct_get_attr_u16(ct2, ATTR_PORT_DST)));

    ck_assert((nfct_get_attr_u8(ct1, ATTR_TCP_STATE) ==
               nfct_get_attr_u8(ct2, ATTR_TCP_STATE)));

    ck_assert((nfct_get_attr_u32(ct1, ATTR_MARK) ==
               nfct_get_attr_u32(ct2, ATTR_MARK)));
}

int
flush_conntrack_for_test()
{
    int ret;
    uint8_t family = AF_INET;
    struct nfct_handle *h;

    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return -1;
    }

    ret = nfct_query(h, NFCT_Q_FLUSH, &family);

    printf("TEST: flush conntrack ");
    if (ret == -1) {
        printf("(%d)(%s)\n", ret, strerror(errno));
        return -1;
    }

    nfct_close(h);
    return 0;
}
//=========================End of helper functions ===========================

START_TEST(test_conntrack_dump)
{
    printf("Running test_conntrack_dump\n\n");
    conn_store = create_conntrack_store();
    int num = 9;

    // Entries having zone information must be ignored.
    struct nf_conntrack *zone_entry1 = ct_new(
        "1.1.1.1", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 6);
    nfct_set_attr_u16(zone_entry1, ATTR_ZONE, 2);
    struct nf_conntrack *zone_entry2 = ct_new(
        "1.1.1.1", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 7);
    nfct_set_attr_u16(zone_entry2, ATTR_ORIG_ZONE, 3);
    struct nf_conntrack *zone_entry3 = ct_new(
        "1.1.1.1", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 8);
    nfct_set_attr_u16(zone_entry3, ATTR_REPL_ZONE, 4);

    struct nf_conntrack *ct_list[9] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
        ct_new("5.5.5.5", "7.7.7.7", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 5),
        zone_entry1,
        zone_entry2,
        zone_entry3,
        ct_new_ipv6("::1", "fe80::1ff:fe23:4567:890a", 1024, 9090,
                    TCP_CONNTRACK_ESTABLISHED, 1000, 9)
    };
    struct nf_conntrack *exp[4] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
    };

    int ret = flush_conntrack_for_test();
    ck_assert(ret == 0);

    ret = conntrack_op_for_test(ct_list, num, NFCT_Q_CREATE);
    ck_assert(ret == 0);

    struct nfct_handle *h = nfct_open(CONNTRACK, 0);
    ck_assert(h != NULL);

    const char *ips[] = { "1.1.1.1", "2.2.2.2" };
    GHashTable *ips_to_migrate = ht_from_ip_list(ips, 5);
    ck_assert(ips_to_migrate != NULL);

    ret = get_conntrack_dump(h, ips_to_migrate);

    ck_assert(ret == 0);
    ck_assert(g_hash_table_size(conn_store->store) == 4);
    int i;

    for (i = 0; i < 4; i++) {
        struct nf_conntrack *ct;
        ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(i+1));
        verify_ct(ct, exp[i]);
    }

}
END_TEST

START_TEST(test_append_ct_to_batch)
{
    printf("Running test_append_ct_to_batch\n\n");
    struct nf_conntrack *ct_list[5] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
        ct_new("5.5.5.5", "7.7.7.7", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 5)
    };

    char send_buf[MNL_SOCKET_BUFFER_SIZE * 2];
    void *curr_batch_offset;
    struct mnl_nlmsg_batch *batch;
    int seq = time(NULL);

    // initialise the batch msg
    batch = mnl_nlmsg_batch_start(send_buf, MNL_SOCKET_BUFFER_SIZE);
    ck_assert(batch != NULL);

    int i = 0;

    uint32_t label[4] = { 1, 2, 3, 4 };
    while (i < 5) {
        curr_batch_offset = mnl_nlmsg_batch_current(batch);
        append_ct_to_batch(curr_batch_offset, ct_list[i], label, seq++);
        mnl_nlmsg_batch_next(batch);

        ck_assert(!mnl_nlmsg_batch_is_empty(batch));
        i++;
    }
    mnl_nlmsg_batch_stop(batch);
}
END_TEST

START_TEST(test_create_batch_conntrack)
{
    printf("Running test_create_batch_conntrack\n\n");
    struct nf_conntrack *ct_list[5] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
        ct_new("5.5.5.5", "7.7.7.7", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 5)
    };

    char send_buf[MNL_SOCKET_BUFFER_SIZE * 2];
    void *curr_batch_offset;
    struct mnl_nlmsg_batch *batch;
    int seq = time(NULL);

    int ret = flush_conntrack_for_test();
    ck_assert(ret == 0);

    batch = mnl_nlmsg_batch_start(send_buf, MNL_SOCKET_BUFFER_SIZE);
    ck_assert(batch != NULL);

    int i = 0;
    while (i < 5) {
        curr_batch_offset = mnl_nlmsg_batch_current(batch);
        append_ct_to_batch(curr_batch_offset, ct_list[i], NULL, seq++);
        mnl_nlmsg_batch_next(batch);

        i++;
    }
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    ck_assert(nl != NULL);
    ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
    ck_assert(ret >= 0);

    ret = create_batch_conntrack(nl, batch);
    ck_assert(ret == 0);

    mnl_nlmsg_batch_stop(batch);
}
END_TEST

START_TEST(test_delete_conntrack)
{
    printf("Running test_delete_conntrack\n\n");
    conn_store = create_conntrack_store();
    int num = 9;
    // Entries having zone information must be ignored.
    struct nf_conntrack *zone_entry1 = ct_new(
        "1.1.1.1", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 6);
    nfct_set_attr_u16(zone_entry1, ATTR_ZONE, 2);
    struct nf_conntrack *zone_entry2 = ct_new(
        "1.1.1.1", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 7);
    nfct_set_attr_u16(zone_entry2, ATTR_ORIG_ZONE, 3);
    struct nf_conntrack *zone_entry3 = ct_new(
        "2.2.2.2", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 8);
    nfct_set_attr_u16(zone_entry3, ATTR_REPL_ZONE, 4);

    // create 8 entries in the kernel.
    struct nf_conntrack *ct_list[9] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
        ct_new("5.5.5.5", "7.7.7.7", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 5),
        zone_entry1,
        zone_entry2,
        zone_entry3,
        ct_new_ipv6("::1", "fe80::1ff:fe23:4567:890a", 1024, 9090,
                    TCP_CONNTRACK_ESTABLISHED, 1000, 9)
    };

    int ret = flush_conntrack_for_test();
    ck_assert(ret == 0);

    ret = conntrack_op_for_test(ct_list, num, NFCT_Q_CREATE);
    ck_assert(ret == 0);

    struct nfct_handle *h = nfct_open(CONNTRACK, 0);
    ck_assert(h != NULL);

    // Now migrate two ips "1.1.1.1" and "2.2.2.2"
    const char *ips[] = { "1.1.1.1", "2.2.2.2" };
    GHashTable *ips_migrated = ht_from_ip_list(ips, 2);
    const char *_ips_on_host[] = { "4.4.4.4", "5.5.5.5" };
    GHashTable *ips_on_host = ht_from_ip_list(_ips_on_host, 2);

    ck_assert(ips_migrated != NULL);
    ck_assert(ips_on_host != NULL);

    struct ct_delete_args args  = {
        .ips_migrated = ips_migrated,
        .ips_on_host = ips_on_host,
        .clear_called = true,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .clear_called_cond = PTHREAD_COND_INITIALIZER
    };

    delete_ct_entries(&args);

    // verify that only 2 CT entries are left in the system
    struct nf_conntrack *exp[2] = {
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
        ct_new("5.5.5.5", "7.7.7.7", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 5)
    };
    const char *_ips_to_mig[] = { "1.1.1.1", "2.2.2.2", "3.3.3.3",
                            "4.4.4.4", "5.5.5.5", "7.7.7.7" };
    GHashTable *ips_to_migrate = ht_from_ip_list(_ips_to_mig, 6);

    ret = get_conntrack_dump(h, ips_to_migrate);
    ck_assert(ret == 0);
    ck_assert(g_hash_table_size(conn_store->store) == 2);

    struct nf_conntrack *ct;
    ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(4));
    verify_ct(ct, exp[0]);

    ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(5));
    verify_ct(ct, exp[1]);
}
END_TEST

static void *
pthread_wrapper_ct_events(void *data)
{
    struct ct_events_targs *targs;
    struct mnl_socket *nl;

    targs = (struct ct_events_targs *) data;
    nl = mnl_socket_open(NETLINK_NETFILTER);
    ck_assert(nl != NULL);

    int ret = mnl_socket_bind(nl, NF_NETLINK_CONNTRACK_NEW |
                        NF_NETLINK_CONNTRACK_UPDATE |
                        NF_NETLINK_CONNTRACK_DESTROY,
                        MNL_SOCKET_AUTOPID);
    ck_assert(ret >=0);
    listen_for_conntrack_events(nl, targs->ips_to_migrate,
                                targs->is_src, targs->stop_flag);
    mnl_socket_close(nl);

    return NULL;
}

START_TEST(test_conntrack_events_for_src)
{
    printf("Running test_conntrack_events_for_src\n\n");
    conn_store = create_conntrack_store();
    int num = 9;
    // Entries having zone information must be ignored.
    struct nf_conntrack *zone_entry1 = ct_new(
        "1.1.1.1", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 6);
    nfct_set_attr_u16(zone_entry1, ATTR_ZONE, 2);
    struct nf_conntrack *zone_entry2 = ct_new(
        "1.1.1.1", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 7);
    nfct_set_attr_u16(zone_entry2, ATTR_ORIG_ZONE, 3);
    struct nf_conntrack *zone_entry3 = ct_new(
        "2.2.2.2", "9.9.9.9", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 8);
    nfct_set_attr_u16(zone_entry3, ATTR_REPL_ZONE, 4);

    struct nf_conntrack *ct_list[9] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
        ct_new("5.5.5.5", "7.7.7.7", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 5),
        zone_entry1,
        zone_entry2,
        zone_entry3,
        ct_new_ipv6("::1", "fe80::1ff:fe23:4567:890a", 1024, 9090,
                    TCP_CONNTRACK_ESTABLISHED, 1000, 9)
    };

    int ret = flush_conntrack_for_test();
    ck_assert(ret == 0);

    const char *ips[] = { "1.1.1.1", "2.2.2.2" };
    GHashTable *ips_to_migrate = ht_from_ip_list(ips, 2);
    ck_assert(ips_to_migrate != NULL);

    stop_flag = false;
    struct ct_events_targs args;
    args.ips_to_migrate = ips_to_migrate;
    args.stop_flag = &stop_flag;
    args.is_src = true;

    ret = pthread_create(&args.tid, NULL, &pthread_wrapper_ct_events, &args);
    ck_assert(ret == 0);
    fflush(stdout);
    sleep(1);

    // create 5 CTs
    ret = conntrack_op_for_test(ct_list, num, NFCT_Q_CREATE);
    ck_assert(ret == 0);
    fflush(stdout);
    sleep(3);

    // verify that we should have received events for 3 entries
    struct nf_conntrack *exp[3] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
    };
    ck_assert(g_hash_table_size(conn_store->store) == 3);
    int i;

    for (i = 0; i < 3; i++) {
        struct nf_conntrack *ct;
        ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(i+1));
        verify_ct(ct, exp[i]);
    }

    // Now send update to the 2nd entry. syn_sent -> established
    struct nf_conntrack *upd[1] = {
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_ESTABLISHED, 1000, 2)
    };
    ret = conntrack_op_for_test(upd, 1, NFCT_Q_UPDATE);
    ck_assert(ret == 0);
    fflush(stdout);
    sleep(3);

    // verify that the entry is updated in our local store as well
    ck_assert(g_hash_table_size(conn_store->store) == 3);
    struct nf_conntrack *ct;
    ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(2));
    verify_ct(ct, upd[0]);

    // Finally delete 1 entries
    struct nf_conntrack *delete[1] = {
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
    };
    ret = conntrack_op_for_test(delete, 1, NFCT_Q_DESTROY);
    ck_assert(ret == 0);
    fflush(stdout);
    sleep(1);
    system("conntrack -L");
    fflush(stdout);
    sleep(4);
    // verify that hashtable size is reduced to 2 now.
    uint32_t hash_size = g_hash_table_size(conn_store->store);
    ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(3));
    ck_assert(ct == NULL);
    ck_assert_msg(hash_size == 2, "hashtaable size %d", hash_size);

    stop_flag = true;
    pthread_join(args.tid, NULL);
}
END_TEST

START_TEST(test_conntrack_events_for_dst)
{
    conn_store = create_conntrack_store();
    int num = 9;
    // Entries having zone information must be ignored.
    struct nf_conntrack *zone_entry1 = ct_new(
        "6.6.6.6", "2.2.2.2", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 6);
    nfct_set_attr_u16(zone_entry1, ATTR_ZONE, 2);
    struct nf_conntrack *zone_entry2 = ct_new(
        "7.7.7.7", "2.2.2.2", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 7);
    nfct_set_attr_u16(zone_entry2, ATTR_ORIG_ZONE, 3);
    struct nf_conntrack *zone_entry3 = ct_new(
        "8.8.8.8", "1.1.1.1", 1024, 9099, TCP_CONNTRACK_ESTABLISHED, 1000, 8);
    nfct_set_attr_u16(zone_entry3, ATTR_REPL_ZONE, 4);

    struct nf_conntrack *ct_list[9] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
        ct_new("2.2.2.2", "3.3.3.3", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 4),
        ct_new("5.5.5.5", "7.7.7.7", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 5),
        zone_entry1,
        zone_entry2,
        zone_entry3,
        ct_new_ipv6("::1", "fe80::1ff:fe23:4567:890a", 1024, 9090,
                    TCP_CONNTRACK_ESTABLISHED, 1000, 9)
    };

    int ret = flush_conntrack_for_test();
    ck_assert(ret == 0);

    const char *ips[] = { "1.1.1.1", "2.2.2.2" };
    GHashTable *ips_to_migrate = ht_from_ip_list(ips, 2);
    ck_assert(ips_to_migrate != NULL);

    stop_flag = false;
    struct ct_events_targs args;
    args.ips_to_migrate = ips_to_migrate;
    args.stop_flag = &stop_flag;
    args.is_src = false;

    ret = pthread_create(&args.tid, NULL, &pthread_wrapper_ct_events, &args);
    ck_assert(ret == 0);
    sleep(1);

    // create 5 CTs
    ret = conntrack_op_for_test(ct_list, num, NFCT_Q_CREATE);
    ck_assert(ret == 0);
    sleep(1);

    // verify that we should have received events for 3 entries
    struct nf_conntrack *exp[3] = {
        ct_new("1.1.1.1", "2.2.2.2", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 1),
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_SYN_SENT, 1000, 2),
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
    };
    ck_assert(g_hash_table_size(conn_store->store) == 3);
    int i;

    for (i = 0; i < 3; i++) {
        struct nf_conntrack *ct;
        ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(i+1));
        verify_ct(ct, exp[i]);
    }

    // Now send update to the 2nd entry. syn_sent -> established
    struct nf_conntrack *upd[1] = {
        ct_new("1.1.1.1", "2.2.2.2", 1029, 9091,
               TCP_CONNTRACK_ESTABLISHED, 1000, 2)
    };
    ret = conntrack_op_for_test(upd, 1, NFCT_Q_UPDATE);
    ck_assert(ret == 0);
    sleep(1);

    // verify that the entry is updated in our local store as well
    ck_assert(g_hash_table_size(conn_store->store) == 3);
    struct nf_conntrack *ct;
    ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(2));
    verify_ct(ct, upd[0]);

    // Finally delete 1 entries
    struct nf_conntrack *delete[1] = {
        ct_new("4.4.4.4", "1.1.1.1", 1024, 9090,
               TCP_CONNTRACK_ESTABLISHED, 1000, 3),
    };
    ret = conntrack_op_for_test(delete, 1, NFCT_Q_DESTROY);
    ck_assert(ret == 0);
    sleep(1);

    // verify that hashtable size is reduced to 2 now.
    ck_assert(g_hash_table_size(conn_store->store) == 2);
    ct = g_hash_table_lookup(conn_store->store, GUINT_TO_POINTER(3));
    ck_assert(ct == NULL);

    stop_flag = true;
    pthread_join(args.tid, NULL);
}
END_TEST

Suite *
conntrack_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Conntrack");

    /* Core test case */
    tc_core = tcase_create("Core");
    tcase_set_timeout(tc_core, 100);

//    tcase_add_test(tc_core, test_conntrack_dump);
//    tcase_add_test(tc_core, test_append_ct_to_batch);
//    tcase_add_test(tc_core, test_create_batch_conntrack);
//    tcase_add_test(tc_core, test_delete_conntrack);
    tcase_add_test(tc_core, test_conntrack_events_for_src);
//    tcase_add_test(tc_core, test_conntrack_events_for_dst);

    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = conntrack_suite();
    sr = srunner_create(s);
    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

#include <arpa/inet.h>
#include <stdlib.h>
#include <check.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <stdio.h>

#include <glib.h>

#include "conntrack_entry.h"
#include "conntrack_store.h"

// ========================= START of dummy functions =========================
void
conntrack_entry_destroy_g_wrapper(void *obj)
{
    if (obj) {
        g_free(obj);
    }
}

/*
 * CT-MARK - 1: return NULL
 * CT-MARK - 0: return correct entry
* */
struct conntrack_entry *
conntrack_entry_from_nf_conntrack(struct nf_conntrack *ct)
{
    struct conntrack_entry *entry = g_malloc(sizeof(struct conntrack_entry));
    entry->data_size = nfct_get_attr_u32(ct, ATTR_TIMEOUT);
    uint32_t ct_mark = nfct_get_attr_u32(ct, ATTR_MARK);

    if (ct_mark == 1) {
        return NULL;
    }
    return entry;
}

struct conntrack_entry *
get_conntrack_entry_from_update(struct conntrack_entry *e,
                                struct nf_conntrack *ct)
{
    struct conntrack_entry *entry = g_malloc(sizeof(struct conntrack_entry));
    entry->data_size = nfct_get_attr_u32(ct, ATTR_TIMEOUT);
    uint32_t ct_mark = nfct_get_attr_u32(ct, ATTR_MARK);
    if (ct_mark == 1)
        return NULL;
    return entry;
}
// ============================== END of dummy functions =====================


START_TEST(test_conntrack_store_new)
{
    struct conntrack_store *store;

    store = conntrack_store_new();

    ck_assert(store != NULL);
    ck_assert(store->store != NULL);
    ck_assert_int_eq(g_hash_table_size(store->store), 0);
}
END_TEST

START_TEST(test_update_conntrack_store_new_event)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;
    int t = 10;
    struct conntrack_entry *ct_entry;

    store = conntrack_store_new();

    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_ID, t);
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    update_conntrack_store(store, ct, NFCT_T_NEW);

    ck_assert_int_eq(g_hash_table_size(store->store), 1);

    const gpointer key = GINT_TO_POINTER(t);
    ct_entry = g_hash_table_lookup(store->store, key);

    ck_assert(ct_entry != NULL); // entry should be present in the hashtable
    ck_assert(ct_entry->data_size == 100); // this should be equal to timeout
}
END_TEST

START_TEST(test_update_conntrack_store_new_event_ct_entry_failed)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;
    struct conntrack_entry *ct_entry;
    int t = 10;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_ID, t);

    // this makes the dummy fn conntrack_entry_from_nf_conntrack return NULL
    nfct_set_attr_u32(ct, ATTR_MARK, 1);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    update_conntrack_store(store, ct, NFCT_T_NEW);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);
    const gpointer key = GINT_TO_POINTER(t);
    ct_entry = g_hash_table_lookup(store->store, key);
    ck_assert(ct_entry == NULL); // entry should not be present in the hashtable
}
END_TEST

START_TEST(test_update_conntrack_store_new_event_ct_entry_invalid_id)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new(); // ID not present => invalid entry
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    update_conntrack_store(store, ct, NFCT_T_NEW);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);
}
END_TEST

START_TEST(test_update_conntrack_store_update_event)
{
    struct conntrack_store *store;
    int t = 10;
    struct nf_conntrack *ct;
    struct conntrack_entry *ct_entry;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_ID, t);
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    // first create an entry in the store
    update_conntrack_store(store, ct, NFCT_T_NEW);

    // update the entry
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 200);
    update_conntrack_store(store, ct, NFCT_T_UPDATE);

    ck_assert_int_eq(g_hash_table_size(store->store), 1);
    const gpointer key = GINT_TO_POINTER(t);
    ct_entry = g_hash_table_lookup(store->store, key);
    ck_assert(ct_entry != NULL); // entry should be present in the hashtable
    ck_assert(ct_entry->data_size == 200); // this should be equal to timeout
}
END_TEST

START_TEST(test_update_conntrack_store_update_event_for_non_existent_entry)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;
    int t = 20;
    struct conntrack_entry *ct_entry;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_ID, t);
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 200);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);

    // Directly send the update
    update_conntrack_store(store, ct, NFCT_T_UPDATE);

    ck_assert_int_eq(g_hash_table_size(store->store), 1);
    const gpointer key = GINT_TO_POINTER(t);
    ct_entry = g_hash_table_lookup(store->store, key);
    ck_assert(ct_entry != NULL); // Entry should be present in the hashtable
    ck_assert(ct_entry->data_size == 200); // this shoukld be equal to timeout
}
END_TEST

START_TEST(test_update_conntrack_store_update_event_ct_entry_failed)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;
    int t = 10;
    struct conntrack_entry *ct_entry;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_ID, t);
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    update_conntrack_store(store, ct, NFCT_T_NEW);
    ck_assert_int_eq(g_hash_table_size(store->store), 1);

    // send the update, but make get_conntrack_entry_from_update to return NULL
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 200);

    // this makes the dummy fn get_conntrack_entry_from_update return NULL
    nfct_set_attr_u32(ct, ATTR_MARK, 1);
    update_conntrack_store(store, ct, NFCT_T_UPDATE);

    ck_assert_int_eq(g_hash_table_size(store->store), 1);
    const gpointer key = GINT_TO_POINTER(t);
    ct_entry = g_hash_table_lookup(store->store, key);
    ck_assert(ct_entry != NULL); //old entry should be present in the hashtable
    ck_assert(ct_entry->data_size == 100);
}
END_TEST

START_TEST(test_update_conntrack_store_update_event_ct_entry_invalid_id)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new(); // id is not present. hence an invalid ct entry
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    update_conntrack_store(store, ct, NFCT_T_UPDATE);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);
}
END_TEST

START_TEST(test_update_conntrack_store_destroy_event)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_ID, 10);
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    // first create an entry in the store
    update_conntrack_store(store, ct, NFCT_T_NEW);

    // destroy the entry
    update_conntrack_store(store, ct, NFCT_T_DESTROY);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);
}
END_TEST

START_TEST(test_update_conntrack_store_destroy_event_non_existent_entry)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_ID, 10);
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);

    // Directly send destroy with creating the entry.
    update_conntrack_store(store, ct, NFCT_T_DESTROY);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);
}
END_TEST

START_TEST(test_update_conntrack_store_destroy_event_ct_entry_invalid_id)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new(); // id is not present. Hence invalid ct entry.
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

    // destroy the entry
    update_conntrack_store(store, ct, NFCT_T_DESTROY);

    ck_assert_int_eq(g_hash_table_size(store->store), 0);
}
END_TEST

START_TEST(test_update_conntrack_store_unknown_event)
{
    struct conntrack_store *store;
    struct nf_conntrack *ct;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    ct = nfct_new();
    nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, htons(20));
    nfct_set_attr_u16(ct, ATTR_PORT_DST, htons(10));
    nfct_set_attr_u32(ct, ATTR_MARK, 0);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);
    nfct_set_attr_u32(ct, ATTR_ID, 10);

    // Send an unknown event
    update_conntrack_store(store, ct, NFCT_T_UNKNOWN);

    // check no change to hashtable size
    ck_assert_int_eq(g_hash_table_size(store->store), 0);
}
END_TEST

START_TEST(test_conntrack_store_destroy)
{
    struct conntrack_store *store;

    store = conntrack_store_new();
    ck_assert(store != NULL);
    ck_assert(store->store != NULL);

    // Case-1 destroying a non-null store
    conntrack_store_destroy(store);

    // Case-2 destroying a null store
    store = NULL;
    conntrack_store_destroy(store);

    //Case-3 Destroying a non-null store with null hashtable
    store = conntrack_store_new();
    store->store = NULL;
    conntrack_store_destroy(store);
}
END_TEST

Suite *
conntrack_store_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ConntrackStore");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_conntrack_store_new);
    tcase_add_test(tc_core, test_update_conntrack_store_new_event);
    tcase_add_test(tc_core, test_update_conntrack_store_new_event_ct_entry_failed);
    tcase_add_test(tc_core, test_update_conntrack_store_new_event_ct_entry_invalid_id);
    tcase_add_test(tc_core, test_update_conntrack_store_update_event);
    tcase_add_test(tc_core, test_update_conntrack_store_update_event_for_non_existent_entry);
    tcase_add_test(tc_core, test_update_conntrack_store_update_event_ct_entry_failed);
    tcase_add_test(tc_core, test_update_conntrack_store_update_event_ct_entry_invalid_id);
    tcase_add_test(tc_core, test_update_conntrack_store_destroy_event);
    tcase_add_test(tc_core, test_update_conntrack_store_destroy_event_non_existent_entry);
    tcase_add_test(tc_core, test_update_conntrack_store_destroy_event_ct_entry_invalid_id);
    tcase_add_test(tc_core, test_update_conntrack_store_unknown_event);
    tcase_add_test(tc_core, test_conntrack_store_destroy);

    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = conntrack_store_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

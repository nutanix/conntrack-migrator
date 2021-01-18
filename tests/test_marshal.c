/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

#include <stdlib.h>
#include <check.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <glib.h>

#include "conntrack_entry.h"
#include "conntrack_store.h"
#include "data_template.h"
#include "marshal.h"
#include "lmct_config.h"
#include "log.h"

// ======================= Start of dependencies =================
int ct_entry_attr_to_size[CT_ATTR_MAX] =
{
    [CT_ATTR_L3_SRC_V4] = UINT32_T_SIZE,
    [CT_ATTR_L3_DST_V4] = UINT32_T_SIZE,
    [CT_ATTR_L3_PROTONUM] = UINT8_T_SIZE,
    [CT_ATTR_PROTONUM] = UINT8_T_SIZE,
    [CT_ATTR_ZONE] = UINT16_T_SIZE,
    [CT_ATTR_L4_SRC_PORT] = UINT16_T_SIZE,
    [CT_ATTR_L4_DST_PORT] = UINT16_T_SIZE,
    [CT_ATTR_ICMP_SRC_ID] = UINT16_T_SIZE,
    [CT_ATTR_ICMP_DST_TYPE] = UINT8_T_SIZE,
    [CT_ATTR_ICMP_DST_CODE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_STATE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_ORIG_FLAGS_VALUE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_ORIG_FLAGS_MASK] = UINT8_T_SIZE,
    [CT_ATTR_TCP_ORIG_WSCALE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_REPL_FLAGS_VALUE] = UINT8_T_SIZE,
    [CT_ATTR_TCP_REPL_FLAGS_MASK] = UINT8_T_SIZE,
    [CT_ATTR_TCP_REPL_WSCALE] = UINT8_T_SIZE,
    [CT_ATTR_TIMEOUT] = UINT32_T_SIZE,
    [CT_ATTR_MARK] = UINT32_T_SIZE,
    [CT_ATTR_STATUS] = UINT32_T_SIZE,
    [CT_ATTR_LABEL] = UINT32_T_SIZE * CT_LABEL_NUM_WORDS
};

struct data_template *
create_template()
{
    struct data_template *tmpl;

    tmpl = g_malloc(sizeof(struct data_template));
    tmpl->num_bits = CT_ATTR_MAX;
    tmpl->payload_size = CT_ATTR_MAX * UINT8_T_SIZE;
    tmpl->payload = g_malloc(tmpl->payload_size);
    int i;
    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        tmpl->payload[i] = ct_entry_attr_to_size[i];
    }
    return tmpl;
}

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

struct conntrack_entry *
create_conntrack_entry(void *data, uint32_t data_size)
{
    struct conntrack_entry *entry;
    entry = g_malloc0(sizeof(struct conntrack_entry));

    entry->bitmap = g_malloc0(BITMAP_NUM_WORDS * WORD_SIZE);
    entry->data = data;
    entry->data_size = data_size;
    return entry;
}

struct lmct_config lmct_conf;

void
init_lmct_config()
{
    lmct_conf.max_entries_to_migrate = 10000;
    lmct_conf.log_lvl = INFO;
}

// ========================= END of dependencies ==================

START_TEST(test_marshal)
{
    init_lmct_config();
    struct data_template *tmpl;
    tmpl = create_template();
    struct conntrack_store *store;
    store = create_conntrack_store();

    struct conntrack_entry *e1, *e2, *e3;
    uint32_t d1, d2, d3;
    d1 = 1;
    d2 = 2;
    d3 = 3;
    e1 = create_conntrack_entry(&d1, sizeof(uint32_t));
    e2 = create_conntrack_entry(&d2, sizeof(uint32_t));
    e3 = create_conntrack_entry(&d3, sizeof(uint32_t));
    g_hash_table_insert(store->store, GINT_TO_POINTER(d1), e1);
    g_hash_table_insert(store->store, GINT_TO_POINTER(d2), e2);
    g_hash_table_insert(store->store, GINT_TO_POINTER(d3), e3);

    uint32_t data_size;
    uint32_t exp_data_size;
    void *buffer = marshal(store, tmpl, &data_size);
    void *buffer_end = buffer + data_size;
    exp_data_size = sizeof(data_size) +  // data size
                    (UINT8_T_SIZE + tmpl->payload_size) + // template size
                    3 * ((BITMAP_NUM_WORDS * WORD_SIZE) + sizeof(uint32_t)); // size of 3 entries
    ck_assert(exp_data_size == data_size);
    // check the values written in the buffer
    // Check 1: Total size of data to be sent is correct
    uint32_t read_data_size;
    memcpy(&read_data_size, buffer, sizeof(read_data_size));
    buffer += sizeof(read_data_size);
    ck_assert(read_data_size == exp_data_size);

    // check 2: Template is correctly marshalled.
    uint8_t tmpl_bits;
    memcpy(&tmpl_bits, buffer, sizeof(tmpl_bits));
    buffer += sizeof(tmpl_bits);
    ck_assert(tmpl_bits == tmpl->num_bits);

    uint8_t *payload = g_malloc(tmpl->payload_size);
    memcpy(payload, buffer, tmpl->payload_size);
    buffer += tmpl->payload_size;
    int i;
    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        ck_assert(tmpl->payload[i] == payload[i]);
    }

    // check 3.1: entry-1 is correctly marshalled
    // skip bitmap check because we didn't set any bits there
    buffer += (BITMAP_NUM_WORDS * WORD_SIZE);
    // check the data
    uint32_t exp_d1;
    memcpy(&exp_d1, buffer, sizeof(uint32_t));
    buffer += sizeof(exp_d1);
    ck_assert(exp_d1 == d1);

    // check 3.2: entry-2 is correctly marshalled
    // skip bitmap check because we didn't set any bits there
    buffer += (BITMAP_NUM_WORDS * WORD_SIZE);
    // check the data
    uint32_t exp_d2;
    memcpy(&exp_d2, buffer, sizeof(uint32_t));
    buffer += sizeof(exp_d2);
    ck_assert(exp_d2 == d2);

    // check 3.3: entry-3 is correctly marshalled
    // skip bitmap check because we didn't set any bits there
    buffer += (BITMAP_NUM_WORDS * WORD_SIZE);
    // check the data
    uint32_t exp_d3;
    memcpy(&exp_d3, buffer, sizeof(uint32_t));
    buffer += sizeof(exp_d3);
    ck_assert(exp_d3 == d3);

    // check we've reached end of buffer
    ck_assert(buffer == buffer_end);
}
END_TEST

START_TEST(test_marshal_empty_conntrack_store)
{
    init_lmct_config();
    struct data_template *tmpl;
    tmpl = create_template();
    struct conntrack_store *store;
    store = create_conntrack_store();

    uint32_t data_size;
    uint32_t exp_data_size;
    void *buffer = marshal(store, tmpl, &data_size);
    void *buffer_end = buffer + data_size;
    exp_data_size = sizeof(data_size);

    ck_assert(exp_data_size == data_size);
    // check the values written in the buffer
    // Check 1: Total size of data to be sent is correct
    uint32_t read_data_size;
    memcpy(&read_data_size, buffer, sizeof(read_data_size));
    buffer += sizeof(read_data_size);
    ck_assert(read_data_size == 0);

    // Check we've reached end of buffer
    ck_assert(buffer == buffer_end);

}
END_TEST

START_TEST(test_marshal_null_conntrack_store)
{
    init_lmct_config();
    struct data_template *tmpl;
    tmpl = create_template();

    uint32_t data_size;
    uint32_t exp_data_size;
    void *buffer = marshal(NULL, tmpl, &data_size);
    void *buffer_end = buffer + data_size;
    exp_data_size = sizeof(data_size);   // data size

    ck_assert(exp_data_size == data_size);
    // check the values written in the buffer
    // Check 1: Total size of data to be sent is correct
    uint32_t read_data_size;
    memcpy(&read_data_size, buffer, sizeof(read_data_size));
    buffer += sizeof(read_data_size);
    ck_assert(read_data_size == 0);

    // Check we've reached end of buffer
    ck_assert(buffer == buffer_end);
}
END_TEST

START_TEST(test_marshal_null_template)
{
    init_lmct_config();
    struct conntrack_store *store;
    store = create_conntrack_store();

    uint32_t data_size;
    uint32_t exp_data_size;
    void *buffer = marshal(store, NULL, &data_size);
    void *buffer_end = buffer + data_size;
    exp_data_size = sizeof(data_size);   // data size

    ck_assert(exp_data_size == data_size);
    // check the values written in the buffer
    // Check 1: Total size of data to be sent is correct
    uint32_t read_data_size;
    memcpy(&read_data_size, buffer, sizeof(read_data_size));
    buffer += sizeof(read_data_size);
    ck_assert(read_data_size == 0);

    // Check we've reached end of buffer
    ck_assert(buffer == buffer_end);
}
END_TEST

START_TEST(test_marshal_null_template_null_conntrack_store)
{
    init_lmct_config();
    uint32_t data_size;
    uint32_t exp_data_size;
    void *buffer = marshal(NULL, NULL, &data_size);
    void *buffer_end = buffer + data_size;
    exp_data_size = sizeof(data_size);   // data size

    ck_assert(exp_data_size == data_size);
    // check the values written in the buffer
    // Check 1: Total size of data to be sent is correct
    uint32_t read_data_size;
    memcpy(&read_data_size, buffer, sizeof(read_data_size));
    buffer += sizeof(read_data_size);
    ck_assert(read_data_size == 0);

    // Check we've reached end of buffer
    ck_assert(buffer == buffer_end);
}
END_TEST

START_TEST(test_marshal_conntrack_store_exceeded_limits)
{
    init_lmct_config();
    lmct_conf.max_entries_to_migrate = 2;

    struct data_template *tmpl;
    tmpl = create_template();
    struct conntrack_store *store;
    store = create_conntrack_store();

    struct conntrack_entry *e1, *e2, *e3;
    uint32_t d1, d2, d3;
    d1 = 1;
    d2 = 2;
    d3 = 3;
    e1 = create_conntrack_entry(&d1, sizeof(uint32_t));
    e2 = create_conntrack_entry(&d2, sizeof(uint32_t));
    e3 = create_conntrack_entry(&d3, sizeof(uint32_t));
    g_hash_table_insert(store->store, GINT_TO_POINTER(d1), e1);
    g_hash_table_insert(store->store, GINT_TO_POINTER(d2), e2);
    g_hash_table_insert(store->store, GINT_TO_POINTER(d3), e3);

    uint32_t data_size;
    uint32_t exp_data_size;
    void *buffer = marshal(store, tmpl, &data_size);
    void *buffer_end = buffer + data_size;
    exp_data_size = sizeof(data_size);
    ck_assert(exp_data_size == data_size);

    // check that nothing should be marshalled.
    uint32_t read_data_size;
    memcpy(&read_data_size, buffer, sizeof(read_data_size));
    buffer += sizeof(read_data_size);
    ck_assert(read_data_size == 0);

    // check we've reached end of buffer
    ck_assert(buffer == buffer_end);
}
END_TEST

Suite *
marshal_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Marshal");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_marshal);
    tcase_add_test(tc_core, test_marshal_empty_conntrack_store);
    tcase_add_test(tc_core, test_marshal_null_conntrack_store);
    tcase_add_test(tc_core, test_marshal_null_template);
    tcase_add_test(tc_core, test_marshal_null_template_null_conntrack_store);
    tcase_add_test(tc_core, test_marshal_conntrack_store_exceeded_limits);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = marshal_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

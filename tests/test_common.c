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
#include <glib.h>

#include "common.h"

START_TEST(test_create_hashtable_from_ip_list)
{
    const char *ip_list[] = { "1.1.1.1", "2.2.2.2", "3.3.3.3" };
    uint32_t exp[3];
    int i;

    for (i = 0; i < 3; i++) {
        struct in_addr ip;
        inet_aton(ip_list[i], &ip);
        exp[i] = ip.s_addr;
    }

    GHashTable *ht = create_hashtable_from_ip_list(ip_list, 3);

    ck_assert(ht != NULL);
    for (i = 0; i < 3; i++) {
        ck_assert(g_hash_table_contains(ht, GUINT_TO_POINTER(exp[i])));
    }
    ck_assert_int_eq(g_hash_table_size(ht), 3);
}
END_TEST

START_TEST(test_create_hashtable_from_ip_list_empty)
{
    GHashTable *ht = create_hashtable_from_ip_list(NULL, 0);

    ck_assert(ht != NULL);
    ck_assert_int_eq(g_hash_table_size(ht), 0);
}
END_TEST

START_TEST(test_create_hashtable_from_ip_list_one_invalid)
{
    const char *ip_list[] = { "1.1.1.1", "2.2.2.2", "a.b.c.d" };
    GHashTable *ht = create_hashtable_from_ip_list(ip_list, 3);

    ck_assert(ht == NULL);
}
END_TEST

START_TEST(test_create_hashtable_from_ip_list_all_invalid)
{
    const char *ip_list[] = { "w.x.y.z", "pqrs", "a.b.c.d" };
    GHashTable *ht = create_hashtable_from_ip_list(ip_list, 3);

    ck_assert(ht == NULL);
}
END_TEST

START_TEST(test_create_hashtable_from_ip_list_negative_int)
{
    const char *ip_list[] = { "-1" };
    GHashTable *ht = create_hashtable_from_ip_list(ip_list, 3);

    ck_assert(ht == NULL);
}
END_TEST

START_TEST(test_create_hashtable_from_ip_list_with_ipv6)
{
    const char *ip_list[] = { "1.1.1.1", "2.2.2.2", "3.3.3.3",
                              "1:0:0:0:0:0:0:8",
                              "0:0:0:0:0:FFFF:204.152.189.116" };
    uint32_t exp[3];
    int i;

    for (i = 0; i < 3; i++) {
        struct in_addr ip;
        inet_aton(ip_list[i], &ip);
        exp[i] = ip.s_addr;
    }

    GHashTable *ht = create_hashtable_from_ip_list(ip_list, 5);

    ck_assert(ht != NULL);
    for (i = 0; i < 3; i++) {
        ck_assert(g_hash_table_contains(ht, GUINT_TO_POINTER(exp[i])));
    }
    ck_assert_int_eq(g_hash_table_size(ht), 3);
}
END_TEST

Suite *common_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Common");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_create_hashtable_from_ip_list);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_empty);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_one_invalid);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_all_invalid);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_negative_int);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_with_ipv6);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = common_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

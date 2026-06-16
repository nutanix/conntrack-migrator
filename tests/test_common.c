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
    GHashTable *ht = create_hashtable_from_ip_list(ip_list, 1);

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

START_TEST(test_create_hashtable_from_ip_list_null_list_positive_count)
{
    GHashTable *ht = create_hashtable_from_ip_list(NULL, 3);

    ck_assert(ht == NULL);
}
END_TEST

START_TEST(test_convert_save_mode_op_type_to_string)
{
    const char *ips_str = convert_save_mode_op_type_to_string(SAVE_IPS_OP);
    const char *zone_str =
        convert_save_mode_op_type_to_string(SAVE_PORT_ZONE_OP);

    ck_assert_str_eq(ips_str, "IPS");
    ck_assert_str_eq(zone_str, "PORT_ZONE");
}
END_TEST

START_TEST(test_is_valid_uuid_string_valid)
{
    bool ok = is_valid_uuid_string(
        "port_12345678-1234-1234-1234-123456789abc");

    ck_assert(ok);
}
END_TEST

START_TEST(test_is_valid_uuid_string_null)
{
    bool ok = is_valid_uuid_string(NULL);

    ck_assert(!ok);
}
END_TEST

START_TEST(test_is_valid_uuid_string_missing_prefix)
{
    /* A bare canonical UUID is rejected: the "port_" prefix is required. */
    bool ok = is_valid_uuid_string("12345678-1234-1234-1234-123456789abc");

    ck_assert(!ok);
}
END_TEST

START_TEST(test_parse_ct_zone_valid)
{
    uint16_t out = 99;
    bool ok;

    ok = parse_ct_zone("0", &out);
    ck_assert(ok);
    ck_assert_int_eq(out, 0);

    ok = parse_ct_zone("1234", &out);
    ck_assert(ok);
    ck_assert_int_eq(out, 1234);

    ok = parse_ct_zone("65535", &out);   /* UINT16_MAX boundary */
    ck_assert(ok);
    ck_assert_int_eq(out, 65535);
}
END_TEST

START_TEST(test_parse_ct_zone_overflow)
{
    uint16_t out = 7;
    bool ok;

    ok = parse_ct_zone("65536", &out);                 /* > UINT16_MAX */
    ck_assert(!ok);

    ok = parse_ct_zone("99999999999999999999", &out);  /* ERANGE */
    ck_assert(!ok);

    ck_assert_int_eq(out, 7);                           /* untouched on fail */
}
END_TEST

START_TEST(test_parse_ct_zone_trailing_junk)
{
    uint16_t out = 7;
    bool ok;

    ok = parse_ct_zone("10abc", &out);
    ck_assert(!ok);

    ok = parse_ct_zone("0x10", &out);   /* base 10: stops at 'x' */
    ck_assert(!ok);
}
END_TEST

START_TEST(test_ensure_cli_arg_valid)
{
    int out = -1;
    ensure_cli_arg_is_int_at_least("5", &out, "mode", 1);
    ck_assert_int_eq(out, 5);
}
END_TEST

START_TEST(test_ensure_cli_arg_null_exits)
{
    int out = 0;
    /* errx() -> exit(1), asserted via tcase_add_exit_test(). */
    ensure_cli_arg_is_int_at_least(NULL, &out, "mode", 1);
}
END_TEST

START_TEST(test_ensure_cli_arg_non_numeric_exits)
{
    int out = 0;
    /* errx() -> exit(1), asserted via tcase_add_exit_test(). */
    ensure_cli_arg_is_int_at_least("abc", &out, "mode", 1);
}
END_TEST

START_TEST(test_ensure_cli_arg_below_min_exits)
{
    int out = 0;
    /* errx() -> exit(1), asserted via tcase_add_exit_test(). */
    ensure_cli_arg_is_int_at_least("0", &out, "mode", 1);
}
END_TEST

START_TEST(test_create_hashtable_from_zone_list_valid)
{
    const char *zones[] = { "10", "20", "30" };
    GHashTable *ht = create_hashtable_from_zone_list(zones, 3);

    ck_assert(ht != NULL);
    ck_assert_int_eq(g_hash_table_size(ht), 3);
    ck_assert(g_hash_table_contains(ht, GUINT_TO_POINTER(10)));
    ck_assert(g_hash_table_contains(ht, GUINT_TO_POINTER(20)));
    ck_assert(g_hash_table_contains(ht, GUINT_TO_POINTER(30)));
}
END_TEST

START_TEST(test_create_hashtable_from_zone_list_empty)
{
    GHashTable *ht = create_hashtable_from_zone_list(NULL, 0);

    ck_assert(ht != NULL);
    ck_assert_int_eq(g_hash_table_size(ht), 0);
}
END_TEST

START_TEST(test_create_hashtable_from_zone_list_invalid_zone)
{
    const char *zones[] = { "10", "abc", "30" };
    GHashTable *ht = create_hashtable_from_zone_list(zones, 3);

    ck_assert(ht == NULL);
}
END_TEST

START_TEST(test_create_hashtable_from_port_zone_pairs_valid)
{
    const char *strv[] = {
        "port_12345678-1234-1234-1234-123456789abc", "10",
        "port_87654321-4321-4321-4321-cba987654321", "20"
    };
    GHashTable *ht = create_hashtable_from_port_zone_pairs(strv, 4);

    ck_assert(ht != NULL);
    ck_assert_int_eq(g_hash_table_size(ht), 2);
    ck_assert(g_hash_table_contains(ht, GUINT_TO_POINTER(10)));
    ck_assert(g_hash_table_contains(ht, GUINT_TO_POINTER(20)));
}
END_TEST

START_TEST(test_create_hashtable_from_port_zone_pairs_odd_count)
{
    const char *strv[] = {
        "port_12345678-1234-1234-1234-123456789abc", "10",
        "port_87654321-4321-4321-4321-cba987654321"
    };
    GHashTable *ht = create_hashtable_from_port_zone_pairs(strv, 3);

    ck_assert(ht == NULL);
}
END_TEST

START_TEST(test_create_hashtable_from_port_zone_pairs_bad_uuid)
{
    const char *strv[] = { "not_a_port_uuid", "10" };
    GHashTable *ht = create_hashtable_from_port_zone_pairs(strv, 2);

    ck_assert(ht == NULL);
}
END_TEST

START_TEST(test_create_save_mode_config_for_ip_mode)
{
    GHashTable *ips = g_hash_table_new(g_direct_hash, g_direct_equal);
    struct save_mode_config *cfg = create_save_mode_config_for_ip_mode(ips);

    ck_assert(cfg != NULL);
    ck_assert_int_eq(cfg->op_type, SAVE_IPS_OP);
    ck_assert(cfg->ips_to_migrate == ips);

    destroy_save_mode_config(cfg);
}
END_TEST

START_TEST(test_create_save_mode_config_for_port_zone_mode)
{
    GHashTable *zones = g_hash_table_new(g_direct_hash, g_direct_equal);
    struct save_mode_config *cfg =
        create_save_mode_config_for_port_zone_mode(zones);

    ck_assert(cfg != NULL);
    ck_assert_int_eq(cfg->op_type, SAVE_PORT_ZONE_OP);
    ck_assert(cfg->zones_to_migrate == zones);

    destroy_save_mode_config(cfg);
}
END_TEST

START_TEST(test_create_save_mode_config_for_ip_mode_null_exits)
{
    /* errx() -> exit(1), asserted via tcase_add_exit_test(). */
    create_save_mode_config_for_ip_mode(NULL);
}
END_TEST

START_TEST(test_destroy_save_mode_config_null)
{
    destroy_save_mode_config(NULL);   /* NULL-tolerant: must not crash */
}
END_TEST

START_TEST(test_create_load_mode_config_for_legacy_mode)
{
    struct load_mode_config *cfg = create_load_mode_config_for_legacy_mode();

    ck_assert(cfg != NULL);
    ck_assert_int_eq(cfg->op_type, LOAD_IPS_OP);
    ck_assert(cfg->src_dst_zone_map == NULL);

    destroy_load_mode_config(cfg);
}
END_TEST

START_TEST(test_create_load_mode_config_for_port_zone_mode)
{
    GHashTable *map = g_hash_table_new(g_direct_hash, g_direct_equal);
    struct load_mode_config *cfg =
        create_load_mode_config_for_port_zone_mode(map);

    ck_assert(cfg != NULL);
    ck_assert_int_eq(cfg->op_type, LOAD_PORT_ZONE_OP);
    ck_assert(cfg->src_dst_zone_map == map);

    destroy_load_mode_config(cfg);
}
END_TEST

START_TEST(test_create_load_mode_config_for_port_zone_mode_null_exits)
{
    /* errx() -> exit(1), asserted via tcase_add_exit_test(). */
    create_load_mode_config_for_port_zone_mode(NULL);
}
END_TEST

START_TEST(test_destroy_load_mode_config_null)
{
    destroy_load_mode_config(NULL);   /* NULL-tolerant: must not crash */
}
END_TEST

Suite *common_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Common");

    /* Core test case */
    tc_core = tcase_create("Core");

    /* create_hashtable_from_ip_list */
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_empty);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_one_invalid);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_all_invalid);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_negative_int);
    tcase_add_test(tc_core, test_create_hashtable_from_ip_list_with_ipv6);
    tcase_add_test(tc_core,
                   test_create_hashtable_from_ip_list_null_list_positive_count);

    /* convert_save_mode_op_type_to_string */
    tcase_add_test(tc_core, test_convert_save_mode_op_type_to_string);

    /* is_valid_uuid_string */
    tcase_add_test(tc_core, test_is_valid_uuid_string_valid);
    tcase_add_test(tc_core, test_is_valid_uuid_string_null);
    tcase_add_test(tc_core, test_is_valid_uuid_string_missing_prefix);

    /* parse_ct_zone */
    tcase_add_test(tc_core, test_parse_ct_zone_valid);
    tcase_add_test(tc_core, test_parse_ct_zone_overflow);
    tcase_add_test(tc_core, test_parse_ct_zone_trailing_junk);

    /* ensure_cli_arg_is_int_at_least */
    tcase_add_test(tc_core, test_ensure_cli_arg_valid);
    tcase_add_exit_test(tc_core, test_ensure_cli_arg_null_exits, 1);
    tcase_add_exit_test(tc_core, test_ensure_cli_arg_non_numeric_exits, 1);
    tcase_add_exit_test(tc_core, test_ensure_cli_arg_below_min_exits, 1);

    /* create_hashtable_from_zone_list */
    tcase_add_test(tc_core, test_create_hashtable_from_zone_list_valid);
    tcase_add_test(tc_core, test_create_hashtable_from_zone_list_empty);
    tcase_add_test(tc_core, test_create_hashtable_from_zone_list_invalid_zone);

    /* create_hashtable_from_port_zone_pairs */
    tcase_add_test(tc_core, test_create_hashtable_from_port_zone_pairs_valid);
    tcase_add_test(tc_core,
                   test_create_hashtable_from_port_zone_pairs_odd_count);
    tcase_add_test(tc_core, test_create_hashtable_from_port_zone_pairs_bad_uuid);

    /* save_mode_config lifecycle */
    tcase_add_test(tc_core, test_create_save_mode_config_for_ip_mode);
    tcase_add_test(tc_core, test_create_save_mode_config_for_port_zone_mode);
    tcase_add_exit_test(tc_core,
                        test_create_save_mode_config_for_ip_mode_null_exits, 1);
    tcase_add_test(tc_core, test_destroy_save_mode_config_null);

    /* load_mode_config lifecycle */
    tcase_add_test(tc_core, test_create_load_mode_config_for_legacy_mode);
    tcase_add_test(tc_core, test_create_load_mode_config_for_port_zone_mode);
    tcase_add_exit_test(tc_core,
                  test_create_load_mode_config_for_port_zone_mode_null_exits, 1);
    tcase_add_test(tc_core, test_destroy_load_mode_config_null);

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

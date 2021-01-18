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
#include "data_template.h"

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
// ========================= END of dependencies ==================

START_TEST(test_data_template_new)
{
    struct data_template *tmpl;
    int i;

    tmpl = data_template_new();
    ck_assert(tmpl != NULL);
    ck_assert(tmpl->num_bits == CT_ATTR_MAX);
    ck_assert(tmpl->payload_size == CT_ATTR_MAX * UINT8_T_SIZE);
    ck_assert(tmpl->payload != NULL);
    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        ck_assert(tmpl->payload[i] == ct_entry_attr_to_size[i]);
    }
}
END_TEST

START_TEST(test_data_template_destroy)
{
    struct data_template *tmpl;

    tmpl = data_template_new();

    /* Test 1: Destroying template with payload does not cause core-dump */
    data_template_destroy(tmpl);

    /* Test 2: Destroying tempalte without any payload does not cause
     * any SIGSEGV
     */
    tmpl = g_malloc(sizeof(struct data_template));
    tmpl->payload = NULL;
    data_template_destroy(tmpl);

    /* Test 3: Destroying NULL template does not cause any SIGSEGV */
    data_template_destroy(NULL);
}
END_TEST

Suite *
data_template_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("DataTemplate");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_data_template_new);
    tcase_add_test(tc_core, test_data_template_destroy);
    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = data_template_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

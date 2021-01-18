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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <stdio.h>

#include <glib.h>

#include "conntrack_entry.h"

static int
calculate_offset(int attr, uint32_t *bm)
{
    int i = 0;
    int offset = 0;
    for (i = CT_ATTR_MIN; i < attr; i++) {
        if (is_set_in_bitmap(bm, i))
            offset += ct_entry_attr_to_size[i];
    }
    return offset;
}

static void
check_attr(int attr, void *exp, struct conntrack_entry *ct)
{
    ck_assert(is_set_in_bitmap(ct->bitmap, attr) == 1);
    int seek = calculate_offset(attr, ct->bitmap);
    void *offset = ct->data + seek;
    uint8_t *tmp_u8 = NULL;
    uint16_t *tmp_u16 = NULL;
    uint32_t *tmp_u32 = NULL;

    uint8_t *exp_u8 = NULL;
    uint16_t *exp_u16 = NULL;
    uint32_t *exp_u32 = NULL;

    int i = 0;
    switch(attr) {
    case CT_ATTR_L3_PROTONUM:
    case CT_ATTR_PROTONUM:
    case CT_ATTR_ICMP_DST_TYPE:
    case CT_ATTR_ICMP_DST_CODE:
    case CT_ATTR_TCP_STATE:
    case CT_ATTR_TCP_ORIG_FLAGS_VALUE:
    case CT_ATTR_TCP_ORIG_FLAGS_MASK:
    case CT_ATTR_TCP_ORIG_WSCALE:
    case CT_ATTR_TCP_REPL_FLAGS_VALUE:
    case CT_ATTR_TCP_REPL_FLAGS_MASK:
    case CT_ATTR_TCP_REPL_WSCALE:
        tmp_u8 = offset;
        exp_u8 = exp;
        ck_assert(*tmp_u8 == *exp_u8);
        break;
    case CT_ATTR_ZONE:
    case CT_ATTR_L4_SRC_PORT:
    case CT_ATTR_L4_DST_PORT:
    case CT_ATTR_ICMP_SRC_ID:
        tmp_u16 = offset;
        exp_u16 = exp;
        ck_assert(*tmp_u16 == *exp_u16);
        break;
    case CT_ATTR_L3_SRC_V4:
    case CT_ATTR_L3_DST_V4:
    case CT_ATTR_TIMEOUT:
    case CT_ATTR_MARK:
    case CT_ATTR_STATUS:
        tmp_u32 = offset;
        exp_u32 = exp;
        ck_assert(*tmp_u32 == *exp_u32);
        break;
    case CT_ATTR_LABEL:
        tmp_u32 = offset;
        exp_u32 = exp;
        for (i = 0; i < CT_LABEL_NUM_WORDS; i++) {
            ck_assert(tmp_u32[i] == exp_u32[i]);
        }
        return;
    }
    return;
}

START_TEST(test_conntrack_entry_new)
{
    struct conntrack_entry *ct = NULL;
    int i = 0;

    ct = conntrack_entry_new();
    ck_assert(ct != NULL);
    ck_assert(ct->bitmap != NULL);
    ck_assert_int_eq(ct->data_size, 0);
    ck_assert_int_eq(sizeof(ct->bitmap), BITMAP_NUM_WORDS * WORD_SIZE);
    for ( ; i < BITMAP_NUM_WORDS; i++) {
        ck_assert_int_eq(ct->bitmap[i], 0);
    }
}
END_TEST

START_TEST(test_conntrack_entry_from_nf_conntrack_without_label_tcp)
{
    struct nf_conntrack *ct;
    struct conntrack_entry *entry = NULL;
    struct in_addr inp;
    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_TCP;
    uint16_t src_port = htons(20);
    uint16_t dst_port = htons(10);
    uint8_t tcp_state = TCP_CONNTRACK_SYN_SENT;
    uint32_t timeout = 100;

    ct = nfct_new();
    ck_assert(ct != NULL);

    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, dst_port);
    nfct_set_attr_u8(ct, ATTR_TCP_STATE, tcp_state);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), entry);
    check_attr(CT_ATTR_L4_SRC_PORT, &src_port, entry);
    check_attr(CT_ATTR_L4_DST_PORT, &dst_port, entry);
    check_attr(CT_ATTR_TCP_STATE, &tcp_state, entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, entry);
}
END_TEST

START_TEST(test_conntrack_entry_from_nf_conntrack_without_label_udp)
{
    struct conntrack_entry *entry = NULL;
    struct nf_conntrack *ct;
    struct in_addr inp;
    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_UDP;
    uint16_t src_port = htons(20);
    uint16_t dst_port = htons(10);
    uint32_t timeout = 1000;

    ct = nfct_new();
    ck_assert(ct != NULL);

    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, dst_port);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), entry);
    check_attr(CT_ATTR_L4_SRC_PORT, &src_port, entry);
    check_attr(CT_ATTR_L4_DST_PORT, &dst_port, entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, entry);
}
END_TEST

START_TEST(test_conntrack_entry_from_nf_conntrack_without_label_icmp)
{
    struct conntrack_entry *entry = NULL;
    struct nf_conntrack *ct;
    struct in_addr inp;
    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_ICMP;
    uint16_t id = 0;
    uint8_t type = 3;
    uint8_t code = 13;
    uint32_t timeout = 1000;

    ct = nfct_new();
    ck_assert(ct != NULL);

    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_ICMP_ID, id);
    nfct_set_attr_u8(ct, ATTR_ICMP_CODE, code);
    nfct_set_attr_u8(ct, ATTR_ICMP_TYPE, type);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), entry);
    check_attr(CT_ATTR_ICMP_SRC_ID, &id, entry);
    check_attr(CT_ATTR_ICMP_DST_TYPE, &type, entry);
    check_attr(CT_ATTR_ICMP_DST_CODE, &code, entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, entry);
}
END_TEST

START_TEST(test_conntrack_entry_from_nf_conntrack_with_label_tcp)
{
    struct conntrack_entry *entry = NULL;
    struct nfct_bitmask *label;
    struct nf_conntrack *ct;
    struct in_addr inp;

    uint32_t exp_labels[4] = { 1, 1, 1, 1 };
    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_TCP;
    uint16_t src_port = htons(20);
    uint16_t dst_port = htons(10);
    uint8_t tcp_state = TCP_CONNTRACK_SYN_SENT;
    uint32_t timeout = 100;

    label = nfct_bitmask_new(128);
    ck_assert(label != NULL);
    nfct_bitmask_set_bit(label, 0);
    nfct_bitmask_set_bit(label, 32);
    nfct_bitmask_set_bit(label, 64);
    nfct_bitmask_set_bit(label, 96);

    ct = nfct_new();
    ck_assert(ct != NULL);
    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, dst_port);
    nfct_set_attr_u8(ct, ATTR_TCP_STATE, tcp_state);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
    nfct_set_attr(ct, ATTR_CONNLABELS, label);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), entry);
    check_attr(CT_ATTR_L4_SRC_PORT, &src_port, entry);
    check_attr(CT_ATTR_L4_DST_PORT, &dst_port, entry);
    check_attr(CT_ATTR_TCP_STATE, &tcp_state, entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, entry);
    check_attr(CT_ATTR_LABEL, exp_labels, entry);
}
END_TEST

START_TEST(test_conntrack_entry_from_nf_conntrack_with_label_udp)
{
    struct conntrack_entry *entry = NULL;
    struct nfct_bitmask *label;
    struct nf_conntrack *ct;
    struct in_addr inp;
    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_UDP;
    uint16_t src_port = htons(20);
    uint16_t dst_port = htons(10);
    uint32_t timeout = 1000;
    uint32_t exp_labels[4] = { 1, 1, 1, 1 };

    label = nfct_bitmask_new(128);
    ck_assert(label != NULL);
    nfct_bitmask_set_bit(label, 0);
    nfct_bitmask_set_bit(label, 32);
    nfct_bitmask_set_bit(label, 64);
    nfct_bitmask_set_bit(label, 96);

    ct = nfct_new();
    ck_assert(ct != NULL);
    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, dst_port);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
    nfct_set_attr(ct, ATTR_CONNLABELS, label);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), entry);
    check_attr(CT_ATTR_L4_SRC_PORT, &src_port, entry);
    check_attr(CT_ATTR_L4_DST_PORT, &dst_port, entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, entry);
    check_attr(CT_ATTR_LABEL, exp_labels, entry);
}
END_TEST

START_TEST(test_conntrack_entry_from_nf_conntrack_with_label_icmp)
{
    struct nf_conntrack *ct;
    struct conntrack_entry *entry = NULL;
    struct in_addr inp;
    struct nfct_bitmask *label;
    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_ICMP;
    uint16_t id = 0;
    uint8_t type = 3;
    uint8_t code = 13;
    uint32_t timeout = 1000;
    uint32_t exp_labels[4] = { 1, 1, 1, 1 };

    label = nfct_bitmask_new(128);
    ck_assert(label != NULL);
    nfct_bitmask_set_bit(label, 0);
    nfct_bitmask_set_bit(label, 32);
    nfct_bitmask_set_bit(label, 64);
    nfct_bitmask_set_bit(label, 96);

    ct = nfct_new();
    ck_assert(ct != NULL);
    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_ICMP_ID, id);
    nfct_set_attr_u8(ct, ATTR_ICMP_CODE, code);
    nfct_set_attr_u8(ct, ATTR_ICMP_TYPE, type);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);
    nfct_set_attr(ct, ATTR_CONNLABELS, label);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), entry);
    check_attr(CT_ATTR_ICMP_SRC_ID, &id, entry);
    check_attr(CT_ATTR_ICMP_DST_TYPE, &type, entry);
    check_attr(CT_ATTR_ICMP_DST_CODE, &code, entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, entry);
    check_attr(CT_ATTR_LABEL, exp_labels, entry);
}
END_TEST

START_TEST(test_get_conntrack_entry_from_update_attr_added)
{
    struct conntrack_entry *entry = NULL;
    struct nf_conntrack *ct = nfct_new();
    struct nf_conntrack *updated_ct;
    struct nfct_bitmask *label;
    struct conntrack_entry *updated_entry = NULL;
    struct in_addr inp;

    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_TCP;
    uint16_t src_port = htons(20);
    uint16_t dst_port = htons(10);
    uint8_t tcp_state = TCP_CONNTRACK_SYN_SENT;
    uint32_t timeout = 100;
    uint32_t exp_labels[4] = { 1, 1, 1, 1 };

    ct = nfct_new();
    ck_assert(ct != NULL);
    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, dst_port);
    nfct_set_attr_u8(ct, ATTR_TCP_STATE, tcp_state);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    updated_ct = nfct_clone(ct);
    ck_assert(updated_ct != NULL);
    label = nfct_bitmask_new(128);
    ck_assert(label != NULL);
    nfct_bitmask_set_bit(label, 0);
    nfct_bitmask_set_bit(label, 32);
    nfct_bitmask_set_bit(label, 64);
    nfct_bitmask_set_bit(label, 96);
    nfct_set_attr(updated_ct, ATTR_CONNLABELS, label);

    updated_entry = get_conntrack_entry_from_update(entry, updated_ct);
    ck_assert(updated_entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, updated_entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, updated_entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), updated_entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), updated_entry);
    check_attr(CT_ATTR_L4_SRC_PORT, &src_port, updated_entry);
    check_attr(CT_ATTR_L4_DST_PORT, &dst_port, updated_entry);
    check_attr(CT_ATTR_TCP_STATE, &tcp_state, updated_entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, updated_entry);
    check_attr(CT_ATTR_LABEL, exp_labels, updated_entry);
}
END_TEST

START_TEST(test_get_conntrack_entry_from_update_attr_updated)
{
    struct nf_conntrack *ct;
    struct in_addr inp;
    struct conntrack_entry *entry = NULL;
    struct nf_conntrack *updated_ct;
    struct conntrack_entry *updated_entry = NULL;

    uint8_t l3proto = AF_INET;
    uint8_t l4proto = IPPROTO_TCP;
    uint16_t src_port = htons(20);
    uint16_t dst_port = htons(10);
    uint8_t tcp_state = TCP_CONNTRACK_SYN_SENT;
    uint32_t timeout = 100;
    uint8_t new_tcp_state = TCP_CONNTRACK_ESTABLISHED;

    ct = nfct_new();
    ck_assert(ct != NULL);
    nfct_set_attr_u8(ct, ATTR_L3PROTO, l3proto);
    nfct_set_attr_u32(ct, ATTR_IPV4_SRC, inet_addr("1.1.1.1"));
    nfct_set_attr_u32(ct, ATTR_IPV4_DST, inet_addr("2.2.2.2"));
    nfct_set_attr_u8(ct, ATTR_L4PROTO, l4proto);
    nfct_set_attr_u16(ct, ATTR_PORT_SRC, src_port);
    nfct_set_attr_u16(ct, ATTR_PORT_DST, dst_port);
    nfct_set_attr_u8(ct, ATTR_TCP_STATE, tcp_state);
    nfct_set_attr_u32(ct, ATTR_TIMEOUT, timeout);

    entry = conntrack_entry_from_nf_conntrack(ct);
    ck_assert(entry != NULL);

    updated_ct = nfct_clone(ct);
    nfct_set_attr_u8(updated_ct, ATTR_TCP_STATE, new_tcp_state);

    updated_entry = get_conntrack_entry_from_update(entry, updated_ct);
    ck_assert(updated_entry != NULL);

    inet_aton("1.1.1.1", &inp);
    check_attr(CT_ATTR_L3_PROTONUM, &l3proto, updated_entry);
    check_attr(CT_ATTR_PROTONUM, &l4proto, updated_entry);
    check_attr(CT_ATTR_L3_SRC_V4, &(inp.s_addr), updated_entry);
    inet_aton("2.2.2.2", &inp);
    check_attr(CT_ATTR_L3_DST_V4, &(inp.s_addr), updated_entry);
    check_attr(CT_ATTR_L4_SRC_PORT, &src_port, updated_entry);
    check_attr(CT_ATTR_L4_DST_PORT, &dst_port, updated_entry);
    check_attr(CT_ATTR_TCP_STATE, &new_tcp_state, updated_entry);
    check_attr(CT_ATTR_TIMEOUT, &timeout, updated_entry);
}
END_TEST

START_TEST(test_conntrack_entry_destroy)
{
    struct conntrack_entry *ct_entry;

    ct_entry = conntrack_entry_new();
    ck_assert(ct_entry != NULL);

    conntrack_entry_destroy(ct_entry);
    conntrack_entry_destroy(NULL);
}
END_TEST

START_TEST(test_conntrack_entry_destroy_g_wrapper)
{
    struct conntrack_entry *ct_entry;

    ct_entry = conntrack_entry_new();
    ck_assert(ct_entry != NULL);

    conntrack_entry_destroy_g_wrapper(ct_entry);
    conntrack_entry_destroy_g_wrapper(NULL);
}
END_TEST

Suite *
conntrack_entry_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ConntrackEntry");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_conntrack_entry_new);
    tcase_add_test(tc_core, test_conntrack_entry_from_nf_conntrack_without_label_tcp);
    tcase_add_test(tc_core, test_conntrack_entry_from_nf_conntrack_with_label_tcp);
    tcase_add_test(tc_core, test_conntrack_entry_from_nf_conntrack_without_label_udp);
    tcase_add_test(tc_core, test_conntrack_entry_from_nf_conntrack_with_label_udp);
    tcase_add_test(tc_core, test_conntrack_entry_from_nf_conntrack_without_label_icmp);
    tcase_add_test(tc_core, test_conntrack_entry_from_nf_conntrack_with_label_icmp);
    tcase_add_test(tc_core, test_get_conntrack_entry_from_update_attr_added);
    tcase_add_test(tc_core, test_get_conntrack_entry_from_update_attr_updated);
    tcase_add_test(tc_core, test_conntrack_entry_destroy);
    tcase_add_test(tc_core, test_conntrack_entry_destroy_g_wrapper);

    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = conntrack_entry_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

#include <stdlib.h>
#include <string.h>
#include <check.h>

#include <glib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "conntrack_entry.h"
#include "data_template.h"
#include "unmarshal.h"

//=============== START of dependencies =================
enum nf_conntrack_attr ct_entry_attr_to_nf_attr[CT_ATTR_MAX] =
{
    [CT_ATTR_L3_SRC_V4] = ATTR_IPV4_SRC,
    [CT_ATTR_L3_DST_V4] = ATTR_IPV4_DST,
    [CT_ATTR_L3_PROTONUM] = ATTR_L3PROTO,
    [CT_ATTR_PROTONUM] = ATTR_L4PROTO,
    [CT_ATTR_ZONE] = ATTR_ZONE,
    [CT_ATTR_L4_SRC_PORT] = ATTR_PORT_SRC,
    [CT_ATTR_L4_DST_PORT] = ATTR_PORT_DST,
    [CT_ATTR_ICMP_SRC_ID] = ATTR_ICMP_ID,
    [CT_ATTR_ICMP_DST_TYPE] = ATTR_ICMP_TYPE,
    [CT_ATTR_ICMP_DST_CODE] = ATTR_ICMP_CODE,
    [CT_ATTR_TCP_STATE] = ATTR_TCP_STATE,
    [CT_ATTR_TCP_ORIG_FLAGS_VALUE] = ATTR_TCP_FLAGS_ORIG,
    [CT_ATTR_TCP_ORIG_FLAGS_MASK] = ATTR_TCP_MASK_ORIG,
    [CT_ATTR_TCP_ORIG_WSCALE] = ATTR_TCP_WSCALE_ORIG,
    [CT_ATTR_TCP_REPL_FLAGS_VALUE] = ATTR_TCP_FLAGS_REPL,
    [CT_ATTR_TCP_REPL_FLAGS_MASK] = ATTR_TCP_MASK_REPL,
    [CT_ATTR_TCP_REPL_WSCALE] = ATTR_TCP_WSCALE_REPL,
    [CT_ATTR_TIMEOUT] = ATTR_TIMEOUT,
    [CT_ATTR_MARK] = ATTR_MARK,
    [CT_ATTR_STATUS] = ATTR_STATUS,
    [CT_ATTR_LABEL] = ATTR_CONNLABELS,
    [CT_ATTR_L3_SRC_V4_REPL] = ATTR_REPL_IPV4_SRC,
    [CT_ATTR_L3_DST_V4_REPL] = ATTR_REPL_IPV4_DST,
    [CT_ATTR_L4_SRC_PORT_REPL] = ATTR_REPL_PORT_SRC,
    [CT_ATTR_L4_DST_PORT_REPL] = ATTR_REPL_PORT_DST,
};

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
    [CT_ATTR_LABEL] = UINT32_T_SIZE * CT_LABEL_NUM_WORDS,
    [CT_ATTR_L3_SRC_V4_REPL] = UINT32_T_SIZE,
    [CT_ATTR_L3_DST_V4_REPL] = UINT32_T_SIZE,
    [CT_ATTR_L4_SRC_PORT_REPL] = UINT16_T_SIZE,
    [CT_ATTR_L4_DST_PORT_REPL] = UINT16_T_SIZE
};

struct data_template *
create_template()
{
    struct data_template *tmpl;
    int i;

    tmpl = g_malloc(sizeof(struct data_template));
    tmpl->num_bits = CT_ATTR_MAX;
    tmpl->payload_size = CT_ATTR_MAX * UINT8_T_SIZE;
    tmpl->payload = g_malloc(tmpl->payload_size);

    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        tmpl->payload[i] = ct_entry_attr_to_size[i];
    }

    return tmpl;
}

//=============== END of dependencies       ==================

START_TEST(test_unmarshal_payload_size)
{
    uint32_t payload_size = 200;
    uint32_t read_payload_size;
    uint32_t bytes_read;

    bytes_read = unmarshal_payload_size(&payload_size, &read_payload_size);

    ck_assert(read_payload_size == payload_size);
    ck_assert(bytes_read == sizeof(uint32_t));
}
END_TEST

START_TEST(test_unmarshal_data_template)
{
    /* Prepare the marshalled data */
    uint32_t data_size = UINT8_T_SIZE + (CT_ATTR_MAX * UINT8_T_SIZE);
    uint8_t *data = g_malloc(data_size);
    uint8_t i;
    uint8_t cnt = 0;
    struct data_template *tmpl;
    uint32_t bytes_read;

    data[0] = CT_ATTR_MAX;
    for (i = CT_ATTR_MIN + 1; i <= CT_ATTR_MAX; i++) {
        data[i] = cnt++;
    }

    tmpl = g_malloc(sizeof(struct data_template));

    // unmarshal
    bytes_read = unmarshal_data_template(data, tmpl);

    // verify
    ck_assert(bytes_read == data_size);
    ck_assert(tmpl->num_bits == CT_ATTR_MAX);
    ck_assert(tmpl->payload_size == CT_ATTR_MAX * UINT8_T_SIZE);

    cnt = 0;
    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        ck_assert(tmpl->payload[i] == cnt++);
    }
}
END_TEST

START_TEST(test_unmarshal_conntrack_entry)
{
    uint32_t bitmap[2];
    uint32_t data[7];
    uint32_t bytes_read;
    struct data_template *tmpl;
    struct nf_conntrack *ct;

    bitmap[0] = (1 << CT_ATTR_TIMEOUT)   |
                (1 << CT_ATTR_MARK)      |
                (1 << CT_ATTR_STATUS)    |
                (1 << CT_ATTR_L3_SRC_V4) |
                (1 << CT_ATTR_L3_DST_V4);
    bitmap[1] = 0;

    // First two entries are bitmap, all other ct data
    data[0] = bitmap[0];
    data[1] = bitmap[1];
    data[2] = 2;    // SRC IP --- 0.0.0.2
    data[3] = 3;    // DST IP ---- 0.0.0.3
    data[4] = 4;    // TIMEOUT
    data[5] = 5;    // MARK
    data[6] = IPS_ASSURED;  // STATUS

    tmpl = create_template();
    ct = nfct_new();

    bytes_read = unmarshal_conntrack_entry(data, tmpl, ct, NULL);

    ck_assert(bytes_read == 28);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_SRC) == 2);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_DST) == 3);
    ck_assert(nfct_get_attr_u32(ct, ATTR_TIMEOUT) == 4);
    ck_assert(nfct_get_attr_u32(ct, ATTR_MARK) == 5);
    ck_assert(nfct_get_attr_u32(ct, ATTR_STATUS) == IPS_ASSURED);
}
END_TEST

START_TEST(test_unmarshal_conntrack_entry_with_label)
{
    uint32_t bitmap[2];
    uint32_t data[11];
    uint32_t bytes_read;
    uint32_t *label;
    struct data_template *tmpl;
    struct nf_conntrack *ct;

    bitmap[0] = (1 << CT_ATTR_TIMEOUT)   |
                (1 << CT_ATTR_MARK)      |
                (1 << CT_ATTR_STATUS)    |
                (1 << CT_ATTR_L3_SRC_V4) |
                (1 << CT_ATTR_L3_DST_V4) |
                (1 << CT_ATTR_LABEL);

    bitmap[1] = 0;

    // First two entries are bitmap, all other ct data
    data[0] = bitmap[0];
    data[1] = bitmap[1];
    data[2] = 2;    // SRC IP --- 0.0.0.2
    data[3] = 3;    // DST IP ---- 0.0.0.3
    data[4] = 4;    // TIMEOUT
    data[5] = 5;    // MARK
    data[6] = IPS_ASSURED;  // STATUS
    data[7] = 10;  // ct label
    data[8] = 11;
    data[9] = 12;
    data[10] = 13;

    tmpl = create_template();
    ct = nfct_new();

    label = g_malloc0(sizeof(uint32_t) * 4);
    bytes_read = unmarshal_conntrack_entry(data, tmpl, ct, &label);

    ck_assert(bytes_read == 44);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_SRC) == 2);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_DST) == 3);
    ck_assert(nfct_get_attr_u32(ct, ATTR_TIMEOUT) == 4);
    ck_assert(nfct_get_attr_u32(ct, ATTR_MARK) == 5);
    ck_assert(nfct_get_attr_u32(ct, ATTR_STATUS) == IPS_ASSURED);
    ck_assert(label[0] = 10);
    ck_assert(label[1] = 11);
    ck_assert(label[2] = 12);
    ck_assert(label[3] = 13);
}
END_TEST

START_TEST(test_unmarshal_conntrack_entry_unsupported_bit)
{
    uint32_t bitmap[2];
    uint32_t data[8]; // First two entries are bitmap, all other ct data
    struct data_template *tmpl;
    int i;
    struct nf_conntrack *ct;
    uint32_t bytes_read;

    bitmap[0] = (1 << CT_ATTR_TIMEOUT)   |
                (1 << CT_ATTR_MARK)      |
                (1 << CT_ATTR_STATUS)    |
                (1 << CT_ATTR_L3_SRC_V4) |
                (1 << CT_ATTR_L3_DST_V4) |
                (1 << CT_ATTR_MAX);       // this is an unsupported bit.
                                          // assume it to be ATTR_DNAT_IPV4

    bitmap[1] = 0;
    data[0] = bitmap[0];
    data[1] = bitmap[1];
    data[2] = 2;    // SRC IP --- 0.0.0.2
    data[3] = 3;    // DST IP ---- 0.0.0.3
    data[4] = 4;    // TIMEOUT
    data[5] = 5;    // MARK
    data[6] = IPS_ASSURED;  // STATUS
    data[7] = 7; //DNAT IP -- 0.0.0.7

    ct = nfct_new();

    tmpl = g_malloc(sizeof(struct data_template));
    tmpl->num_bits = CT_ATTR_MAX + 1;
    tmpl->payload_size = (CT_ATTR_MAX + 1) * UINT8_T_SIZE;
    tmpl->payload = g_malloc(tmpl->payload_size);

    for (i = CT_ATTR_MIN; i < CT_ATTR_MAX; i++) {
        tmpl->payload[i] = ct_entry_attr_to_size[i];
    }
    tmpl->payload[CT_ATTR_MAX] = 4;

    bytes_read = unmarshal_conntrack_entry(data, tmpl, ct, NULL);

    /* 8 (bitmap) + 5x4 (known attrs) + 4 (skipped unsupported attr) = 32. */
    ck_assert(bytes_read == 32);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_SRC) == 2);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_DST) == 3);
    ck_assert(nfct_get_attr_u32(ct, ATTR_TIMEOUT) == 4);
    ck_assert(nfct_get_attr_u32(ct, ATTR_MARK) == 5);
    ck_assert(nfct_get_attr_u32(ct, ATTR_STATUS) == IPS_ASSURED);
    ck_assert(nfct_attr_is_set(ct, ATTR_DNAT_IPV4) == 0); // this should not
                                                          // be set since it
                                                          // is unsupported.
}
END_TEST

START_TEST(test_unmarshal_conntrack_entry_for_zone)
{
    /* A zone-mode payload: original 5-tuple + CT zone + the NAT'd reply
     * 5-tuple. */
    uint32_t databuf[9]; // 36 bytes, 4-byte aligned; we use 34.
    uint8_t *data = (uint8_t *)databuf;
    uint8_t *p;
    uint32_t bytes_read;
    struct data_template *tmpl;
    struct nf_conntrack *ct;

    uint32_t bitmap[2];
    uint32_t src_ip = 2;
    uint32_t dst_ip = 3;
    uint16_t zone = 10;
    uint16_t src_port = 1024;
    uint16_t dst_port = 9090;
    uint32_t repl_src_ip = 4;
    uint32_t repl_dst_ip = 5;
    uint16_t repl_src_port = 5555;
    uint16_t repl_dst_port = 6666;

    bitmap[0] = (1 << CT_ATTR_L3_SRC_V4)        |
                (1 << CT_ATTR_L3_DST_V4)        |
                (1 << CT_ATTR_ZONE)             |
                (1 << CT_ATTR_L4_SRC_PORT)      |
                (1 << CT_ATTR_L4_DST_PORT)      |
                (1 << CT_ATTR_L3_SRC_V4_REPL)   |
                (1 << CT_ATTR_L3_DST_V4_REPL)   |
                (1 << CT_ATTR_L4_SRC_PORT_REPL) |
                (1 << CT_ATTR_L4_DST_PORT_REPL);
    bitmap[1] = 0;

    // Bitmap first, then the attribute values in ascending bit order.
    p = data;
    memcpy(p, bitmap, sizeof(bitmap));             p += sizeof(bitmap);
    memcpy(p, &src_ip, sizeof(src_ip));             p += sizeof(src_ip);
    memcpy(p, &dst_ip, sizeof(dst_ip));             p += sizeof(dst_ip);
    memcpy(p, &zone, sizeof(zone));                 p += sizeof(zone);
    memcpy(p, &src_port, sizeof(src_port));         p += sizeof(src_port);
    memcpy(p, &dst_port, sizeof(dst_port));         p += sizeof(dst_port);
    memcpy(p, &repl_src_ip, sizeof(repl_src_ip));   p += sizeof(repl_src_ip);
    memcpy(p, &repl_dst_ip, sizeof(repl_dst_ip));   p += sizeof(repl_dst_ip);
    memcpy(p, &repl_src_port, sizeof(repl_src_port)); p += sizeof(repl_src_port);
    memcpy(p, &repl_dst_port, sizeof(repl_dst_port)); p += sizeof(repl_dst_port);

    tmpl = create_template();
    ct = nfct_new();

    bytes_read = unmarshal_conntrack_entry(data, tmpl, ct, NULL);

    /* 8 (bitmap) + 4+4 (orig ips) + 2 (zone) + 2+2 (orig ports)
     * + 4+4 (repl ips) + 2+2 (repl ports) = 34. */
    ck_assert(bytes_read == 34);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_SRC) == src_ip);
    ck_assert(nfct_get_attr_u32(ct, ATTR_IPV4_DST) == dst_ip);
    ck_assert(nfct_get_attr_u16(ct, ATTR_ZONE) == zone);
    ck_assert(nfct_get_attr_u16(ct, ATTR_PORT_SRC) == src_port);
    ck_assert(nfct_get_attr_u16(ct, ATTR_PORT_DST) == dst_port);
    ck_assert(nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC) == repl_src_ip);
    ck_assert(nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST) == repl_dst_ip);
    ck_assert(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC) == repl_src_port);
    ck_assert(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST) == repl_dst_port);
}
END_TEST

Suite *
unmarshal_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("UnMarshal");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_unmarshal_payload_size);
    tcase_add_test(tc_core, test_unmarshal_data_template);
    tcase_add_test(tc_core, test_unmarshal_conntrack_entry);
    tcase_add_test(tc_core, test_unmarshal_conntrack_entry_with_label);
    tcase_add_test(tc_core, test_unmarshal_conntrack_entry_unsupported_bit);
    tcase_add_test(tc_core, test_unmarshal_conntrack_entry_for_zone);

    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = unmarshal_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the functionality to print the conntrack_entry struct
 * to the stdout/log file.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <glib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <netinet/in.h>

#include "conntrack_entry.h"
#include "log.h"

#define UPDATE_OFFSET(size_left, buf_offset, written) \
    size_left -= written; \
    buf_offset += written;

/* L3 protocol number to string array */
const char *const ct_l3proto2str[AF_MAX] = {
    [AF_INET]  = "ipv4",
    [AF_INET6] = "ipv6",
};

/* L4 protocol number to string array */
const char *const ct_proto2str[IPPROTO_MAX] = {
    [IPPROTO_TCP]     = "tcp",
    [IPPROTO_UDP]     = "udp",
    [IPPROTO_UDPLITE] = "udplite",
    [IPPROTO_ICMP]    = "icmp",
    [IPPROTO_ICMPV6]  = "icmpv6",
    [IPPROTO_SCTP]    = "sctp",
    [IPPROTO_GRE]     = "gre",
    [IPPROTO_DCCP]    = "dccp",
};

/* TCP states number to string array */
const char *const tcp_states[TCP_CONNTRACK_MAX] = {
    [TCP_CONNTRACK_NONE]        = "NONE",
    [TCP_CONNTRACK_SYN_SENT]    = "SYN_SENT",
    [TCP_CONNTRACK_SYN_RECV]    = "SYN_RECV",
    [TCP_CONNTRACK_ESTABLISHED] = "ESTABLISHED",
    [TCP_CONNTRACK_FIN_WAIT]    = "FIN_WAIT",
    [TCP_CONNTRACK_CLOSE_WAIT]  = "CLOSE_WAIT",
    [TCP_CONNTRACK_LAST_ACK]    = "LAST_ACK",
    [TCP_CONNTRACK_TIME_WAIT]   = "TIME_WAIT",
    [TCP_CONNTRACK_CLOSE]       = "CLOSE",
    [TCP_CONNTRACK_SYN_SENT2]   = "SYN_SENT2",
};

static int
snprintf_l3_v4(char *buf, unsigned int len, uint32_t ip_v4, bool is_src)
{
    struct in_addr ip_address = { .s_addr = ip_v4 };
    return (snprintf(buf, len, "%s_ip=%s ",
                     is_src ? "src" : "dst",
                     inet_ntoa(ip_address)));
}

static int
snprintf_l3protocol(char *buf, unsigned int len, uint8_t l3protonum)
{
    return (snprintf(buf, len, "l3proto=%s %u ",
                     ct_l3proto2str[l3protonum] == NULL ?
                     "unknown" : ct_l3proto2str[l3protonum],
                     l3protonum));
}

static int
snprintf_protocol(char *buf, unsigned int len, uint8_t protonum)
{
    return (snprintf(buf, len, "l4proto=%s %u ",
                     ct_proto2str[protonum] == NULL ?
                     "unknown" : ct_proto2str[protonum],
                     protonum));
}

static int
snprintf_zone(char *buf, unsigned int len, uint16_t zone)
{
    return snprintf(buf, len, "zone=%u ", zone);
}

static int
snprintf_l4_port(char *buf, unsigned int len, uint16_t port, bool is_src)
{
    return snprintf(buf, len, "%s_sport=%u ", is_src ? "src" : "dst",
                    ntohs(port));
}

static int
snprintf_icmp_id(char *buf, unsigned int len, uint16_t icmp_id)
{
    return snprintf(buf, len, "icmp_id=%u ", ntohs(icmp_id));
}

static int
snprintf_icmp_type(char *buf, unsigned int len, uint8_t icmp_type)
{
    return snprintf(buf, len, "icmp_type=%u ", icmp_type);
}

static int
snprintf_icmp_code(char *buf, unsigned int len, uint16_t icmp_code)
{
    return snprintf(buf, len, "icmp_code=%u ", icmp_code);
}

static int
snprintf_tcp_state(char *buf, unsigned int len, uint8_t tcp_state)
{
    return snprintf(buf, len, "tcp_state=%s ", tcp_states[tcp_state]);
}

static int
snprintf_tcp_flags(char *buf, unsigned int len, uint8_t tcp_flag,
                     bool is_src)
{
    return snprintf(buf, len, "%s_tcp_flags=%u ", is_src ? "src" : "dst",
                    tcp_flag);
}

static int
snprintf_tcp_flags_mask(char *buf, unsigned int len, uint8_t tcp_mask,
                          bool is_src)
{
    return snprintf(buf, len, "%s_tcp_flags_mask=%u ", is_src ? "src" : "dst",
                    tcp_mask);
}

static int
snprintf_tcp_wscale(char *buf, unsigned int len, uint8_t tcp_wscale,
                      bool is_src)
{
    return snprintf(buf, len, "%s_tcp_wscale=%u ", is_src ? "src" : "dst",
                    tcp_wscale);
}

static int
snprintf_timeout(char *buf, unsigned int len, uint32_t timeout)
{
    return snprintf(buf, len, "timeout=%u ", timeout);
}

static int
snprintf_mark(char *buf, unsigned int len, uint32_t mark)
{
    return snprintf(buf, len, "mark=%u ", mark);
}

static int
snprintf_status(char *buf, unsigned int len, uint32_t status)
{
    return snprintf(buf, len, "status=%u ", status);
}

static int
snprintf_label(char *buf, unsigned int len, uint32_t label[4])
{
    return snprintf(buf, len,
                    "label[0]=%x label[1]=%x label[2]=%x label[3]=%x ",
                    label[0], label[1], label[2], label[3]);
}

/**
 * Gives the string representation of the conntrack entry.
 *
 * Args:
 *   @ct_entry pointer to conntrack_entry
 *
 * Returns:
 *   pointer to the string representation of the conntrack entry.
 */
static char *
conntrack_entry_to_string(struct conntrack_entry *ct_entry)
{
    char *buf;
    int buffer_size = 1024;
    int size_left = buffer_size;
    int cur_offset = 0;
    void *offset_ptr = ct_entry->data;
    int written = 0;

    uint32_t *tmp_u32;
    uint32_t *tmp_u16;
    uint32_t *tmp_u8;

    buf = g_malloc0(sizeof(char) * buffer_size);

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_L3_SRC_V4)) {
        tmp_u32 = offset_ptr;
        written = snprintf_l3_v4(buf+cur_offset, size_left, *tmp_u32, true);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_L3_SRC_V4];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_L3_DST_V4)) {
        tmp_u32 = offset_ptr;
        written = snprintf_l3_v4(buf+cur_offset, size_left, *tmp_u32, false);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_L3_DST_V4];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_L3_PROTONUM)) {
        tmp_u8 = offset_ptr;
        written = snprintf_l3protocol(buf+cur_offset, size_left, *tmp_u8);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_L3_PROTONUM];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_PROTONUM)) {
        tmp_u8 = offset_ptr;
        written = snprintf_protocol(buf+cur_offset, size_left, *tmp_u8);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_PROTONUM];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_ZONE)) {
        tmp_u16 = offset_ptr;
        written = snprintf_zone(buf+cur_offset, size_left, *tmp_u16);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_ZONE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_L4_SRC_PORT)) {
        tmp_u16 = offset_ptr;
        written = snprintf_l4_port(buf+cur_offset, size_left, *tmp_u16,
                                     true);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_L4_SRC_PORT];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_L4_DST_PORT)) {
        tmp_u16 = offset_ptr;
        written = snprintf_l4_port(buf+cur_offset, size_left, *tmp_u16,
                                     false);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_L4_DST_PORT];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_ICMP_SRC_ID)) {
        tmp_u16 = offset_ptr;
        written = snprintf_icmp_id(buf + cur_offset, size_left, *tmp_u16);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_ICMP_SRC_ID];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_ICMP_DST_TYPE)) {
        tmp_u8 = offset_ptr;
        written = snprintf_icmp_type(buf + cur_offset, size_left, *tmp_u8);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_ICMP_DST_TYPE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_ICMP_DST_CODE)) {
        tmp_u8 = offset_ptr;
        written = snprintf_icmp_code(buf + cur_offset, size_left, *tmp_u8);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_ICMP_DST_CODE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TCP_STATE)) {
        tmp_u8 = offset_ptr;
        written = snprintf_tcp_state(buf + cur_offset, size_left, *tmp_u8);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TCP_STATE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TCP_ORIG_FLAGS_VALUE)) {
        tmp_u8 = offset_ptr;
        written = snprintf_tcp_flags(buf + cur_offset, size_left, *tmp_u8,
                                       true);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TCP_ORIG_FLAGS_VALUE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TCP_ORIG_FLAGS_MASK)) {
        tmp_u8 = offset_ptr;
        written = snprintf_tcp_flags_mask(buf + cur_offset, size_left,
                                            *tmp_u8, true);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TCP_ORIG_FLAGS_MASK];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TCP_ORIG_WSCALE)) {
        tmp_u8 = offset_ptr;
        written = snprintf_tcp_wscale(buf + cur_offset, size_left, *tmp_u8,
                                        true);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TCP_ORIG_WSCALE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TCP_REPL_FLAGS_VALUE)) {
        tmp_u8 = offset_ptr;
        written = snprintf_tcp_flags(buf + cur_offset, size_left, *tmp_u8,
                                       false);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TCP_ORIG_FLAGS_VALUE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TCP_REPL_FLAGS_MASK)) {
        tmp_u8 = offset_ptr;
        written = snprintf_tcp_flags_mask(buf + cur_offset, size_left,
                                            *tmp_u8, false);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TCP_REPL_FLAGS_MASK];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TCP_REPL_WSCALE)) {
        tmp_u8 = offset_ptr;
        written = snprintf_tcp_wscale(buf + cur_offset, size_left, *tmp_u8,
                                        false);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TCP_REPL_WSCALE];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_TIMEOUT)) {
        tmp_u32 = offset_ptr;
        written = snprintf_timeout(buf + cur_offset, size_left, *tmp_u32);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_TIMEOUT];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_MARK)) {
        tmp_u32 = offset_ptr;
        written = snprintf_mark(buf + cur_offset, size_left, *tmp_u32);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_MARK];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_STATUS)) {
        tmp_u32 = offset_ptr;
        written = snprintf_status(buf + cur_offset, size_left, *tmp_u32);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_STATUS];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    if (is_set_in_bitmap(ct_entry->bitmap, CT_ATTR_LABEL)) {
        tmp_u32 = offset_ptr;
        written = snprintf_label(buf + cur_offset, size_left, tmp_u32);
        offset_ptr += ct_entry_attr_to_size[CT_ATTR_LABEL];
        UPDATE_OFFSET(size_left, cur_offset, written);
    }

    return buf;
}

/**
 * Write the conntrack entry to log file.
 *
 * Args:
 *   @level logging level for the message.
 *   @ct_entry pointer to conntrack_entry to be printed.
 */
void
log_conntrack_entry(enum log_level level, struct conntrack_entry *ct_entry)
{
    char *buf;

    if (!is_log_level_configured(level)) {
        return;
    }

    buf = conntrack_entry_to_string(ct_entry);

    LOG(level, "%s: %s", __func__, buf);
    free(buf);
}

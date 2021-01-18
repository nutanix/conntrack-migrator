/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the declarations of functions and structs
 * implemented in conntrack_entry.c
 */

#ifndef CONNTRACK_ENTRY_H
#define CONNTRACK_ENTRY_H

#include <stdint.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "log.h"

// Size of unsigned 32-bit integer
#define WORD_SIZE sizeof(uint32_t)

// Size of unsigned 32-bit integer
#define UINT32_T_SIZE sizeof(uint32_t)

// Size of unsigned 16-bit integer
#define UINT16_T_SIZE sizeof(uint16_t)

// Size of unsigned 8-bit integer.
#define UINT8_T_SIZE sizeof(uint8_t)

// Number of words in a bitmap
#define BITMAP_NUM_WORDS 2

// Number of words in CT Label
#define CT_LABEL_NUM_WORDS 4

// Total num of attributes we are using from nf_conntrack
#define CT_ENTRY_NUM_ATTRIBUTES 21

// Number of bits per byte
#define BITS_PER_BYTE 8

/**
 * Represents the list of attributes that are of use from nf_conntrack in
 * context of LMCT. To add new attributes, append them to the list before
 * CT_ATTR_MAX.
 */
enum conntrack_entry_attribute {
    CT_ATTR_MIN = 0,                 // Attributes list start
    CT_ATTR_L3_SRC_V4 = CT_ATTR_MIN, // [uint32_t] source ip address
    CT_ATTR_L3_DST_V4,               // [uint32_t] destination ip address
    CT_ATTR_L3_PROTONUM,             // [uint8_t] L3 protocol number (ipv4/6)
    CT_ATTR_PROTONUM,                // [uint8_t] L4 protocol number
    CT_ATTR_ZONE,                    // [uint16_t] CT zone
    CT_ATTR_L4_SRC_PORT,             // [uint16_t] source port
    CT_ATTR_L4_DST_PORT,             // [uint16_t] destination port
    CT_ATTR_ICMP_SRC_ID,             // [uint16_t] icmp id
    CT_ATTR_ICMP_DST_TYPE,           // [uint8_t]  icmp type
    CT_ATTR_ICMP_DST_CODE,           // [uint8_t]  icmp code
    CT_ATTR_TCP_STATE,               // [uint8_t]  tcp state
    CT_ATTR_TCP_ORIG_FLAGS_VALUE,    // [uint8_t] tcp flags in original direction
    CT_ATTR_TCP_ORIG_FLAGS_MASK,     // [uint8_t] tcp flags mask for orignal direction
    CT_ATTR_TCP_ORIG_WSCALE,         // [uint8_t] tcp window scaling for original direction
    CT_ATTR_TCP_REPL_FLAGS_VALUE,    // [uint8_t] tcp flags in reply direction
    CT_ATTR_TCP_REPL_FLAGS_MASK,     // [uint8_t] tcp flags mask in reply direction
    CT_ATTR_TCP_REPL_WSCALE,         // [uint8_t] tcp window scaling for reply direction
    CT_ATTR_TIMEOUT,                 // [uint32_t] entry timeout value
    CT_ATTR_MARK,                    // [uint32_t] CT mark metadata
    CT_ATTR_STATUS,                  // [uint32_t] CT status.(REPLIED/CONFIRMED/ASSURED..)
    CT_ATTR_LABEL,                   // [uint32_t[4]] CT label. 128 bits
    CT_ATTR_MAX                      // Attributes list end
};

// Mapping from CT entry attribute to its size.
// Useful when converting the nf_conntrack entry
// to wire format. (void *)
extern int ct_entry_attr_to_size[CT_ATTR_MAX];

// Mapping of NF attributes to the local attributes.
extern enum nf_conntrack_attr ct_entry_attr_to_nf_attr[CT_ATTR_MAX];

/**
 * Represents the conntrack entry as a byte array created from nf_conntrack.
 * This is used to send the data over the dbus-daemon.
 */
struct conntrack_entry {
    uint32_t *bitmap;   // 64 bits map for indicating what all entries are set
    uint32_t data_size; // Payload size
    void *data;         // Wire format for the data
};

struct conntrack_entry *
conntrack_entry_new(void);

void
conntrack_entry_destroy(struct conntrack_entry *);

void
conntrack_entry_destroy_g_wrapper(void *);

struct conntrack_entry *
conntrack_entry_from_nf_conntrack(struct nf_conntrack *);

struct conntrack_entry *
get_conntrack_entry_from_update(struct conntrack_entry *,
                                struct nf_conntrack *);

bool
is_set_in_bitmap(uint32_t *, uint8_t);

void
log_conntrack_entry(enum log_level, struct conntrack_entry *);

#endif /* CONNTRACK_ENTRY_H */

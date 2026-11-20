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

#include <assert.h>
#include <stdint.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "common.h"
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

/* v1.0 wire schema size (slots 0..20). IP mode emits only this prefix. */
#define CT_ATTR_LEGACY_NUM_BITS 21

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
    CT_ATTR_L3_SRC_V4_REPL,          // [uint32_t] reply source ip address
    CT_ATTR_L3_DST_V4_REPL,          // [uint32_t] reply destination ip address
    CT_ATTR_L4_SRC_PORT_REPL,        // [uint16_t] reply source port
    CT_ATTR_L4_DST_PORT_REPL,        // [uint16_t] reply destination port
    CT_ATTR_MAX                      // Attributes list end
};

/**
 * Wire-protocol compatibility lock for v1.0/v1.1 migrations.
 *
 * These values are bit positions in the serialized payload. Reordering
 * them corrupts a migration between different daemon versions.
 *
 * Slots 0-20 are the v1.0 schema and must not change.
 * Slots 21-24 are the v1.1 zone-mode NAT reply fields.
 *
 * Append new attributes after slot 24 and bump CT_ATTR_MAX on purpose.
 */

/* Legacy v1.0 wire slots. */
static_assert(CT_ATTR_L3_SRC_V4            ==  0, "v1.0 wire slot 0 pinned");
static_assert(CT_ATTR_L3_DST_V4            ==  1, "v1.0 wire slot 1 pinned");
static_assert(CT_ATTR_L3_PROTONUM          ==  2, "v1.0 wire slot 2 pinned");
static_assert(CT_ATTR_PROTONUM             ==  3, "v1.0 wire slot 3 pinned");
static_assert(CT_ATTR_ZONE                 ==  4, "v1.0 wire slot 4 pinned");
static_assert(CT_ATTR_L4_SRC_PORT          ==  5, "v1.0 wire slot 5 pinned");
static_assert(CT_ATTR_L4_DST_PORT          ==  6, "v1.0 wire slot 6 pinned");
static_assert(CT_ATTR_ICMP_SRC_ID          ==  7, "v1.0 wire slot 7 pinned");
static_assert(CT_ATTR_ICMP_DST_TYPE        ==  8, "v1.0 wire slot 8 pinned");
static_assert(CT_ATTR_ICMP_DST_CODE        ==  9, "v1.0 wire slot 9 pinned");
static_assert(CT_ATTR_TCP_STATE            == 10, "v1.0 wire slot 10 pinned");
static_assert(CT_ATTR_TCP_ORIG_FLAGS_VALUE == 11, "v1.0 wire slot 11 pinned");
static_assert(CT_ATTR_TCP_ORIG_FLAGS_MASK  == 12, "v1.0 wire slot 12 pinned");
static_assert(CT_ATTR_TCP_ORIG_WSCALE      == 13, "v1.0 wire slot 13 pinned");
static_assert(CT_ATTR_TCP_REPL_FLAGS_VALUE == 14, "v1.0 wire slot 14 pinned");
static_assert(CT_ATTR_TCP_REPL_FLAGS_MASK  == 15, "v1.0 wire slot 15 pinned");
static_assert(CT_ATTR_TCP_REPL_WSCALE      == 16, "v1.0 wire slot 16 pinned");
static_assert(CT_ATTR_TIMEOUT              == 17, "v1.0 wire slot 17 pinned");
static_assert(CT_ATTR_MARK                 == 18, "v1.0 wire slot 18 pinned");
static_assert(CT_ATTR_STATUS               == 19, "v1.0 wire slot 19 pinned");
static_assert(CT_ATTR_LABEL                == 20, "v1.0 wire slot 20 pinned");

/* Zone-mode NAT'd-reply slots. */
static_assert(CT_ATTR_L3_SRC_V4_REPL       == 21, "zone wire slot 21 pinned");
static_assert(CT_ATTR_L3_DST_V4_REPL       == 22, "zone wire slot 22 pinned");
static_assert(CT_ATTR_L4_SRC_PORT_REPL     == 23, "zone wire slot 23 pinned");
static_assert(CT_ATTR_L4_DST_PORT_REPL     == 24, "zone wire slot 24 pinned");

/* Macro pins -- catch the cases the per-slot pins can't: drifting
 * the macro value, or appending a new attribute past slot 24. */
static_assert(CT_ATTR_LEGACY_NUM_BITS == 21,
               "v1.0 wire schema is locked at 21 attrs");
static_assert(CT_ATTR_MAX == 25,
               "current schema rev pinned; bump intentionally");

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
conntrack_entry_from_nf_conntrack(const struct nf_conntrack *, enum save_mode_op_type);

struct conntrack_entry *
get_conntrack_entry_from_update(struct conntrack_entry *,
                                const struct nf_conntrack *,
                                enum save_mode_op_type);

bool
is_set_in_bitmap(uint32_t *, uint8_t);

void
log_conntrack_entry(enum log_level, struct conntrack_entry *);

#endif /* CONNTRACK_ENTRY_H */

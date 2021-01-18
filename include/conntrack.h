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
 * implemented in conntrack.c
 */

#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <stdbool.h>

#include <glib.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <pthread.h>

#include "ct_delete_args.h"

/**
 * Represents the arguments to be passed to the threads listening for
 * the conntrack events.
 */
struct ct_events_targs {
    pthread_t tid;              // thread ID
    GHashTable *ips_to_migrate; // IPs for which CT events needs to be listened
    bool *stop_flag; // Flag when True, stop listening for CT events
    bool is_src; // Flag indicating whether the args are for src based events
};

int
get_conntrack_dump(struct nfct_handle *, GHashTable *);

int
listen_for_conntrack_events(struct mnl_socket *, GHashTable *, bool, bool *);

void
append_ct_to_batch(char *, struct nf_conntrack *, uint32_t *, int);

int
create_batch_conntrack(struct mnl_socket *, struct mnl_nlmsg_batch *);

void *
delete_ct_entries(void *);

#endif /* CONNTRACK_H */

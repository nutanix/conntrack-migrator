/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

/**
 * Provides the implementation for the common util functions.
 */

#include <arpa/inet.h> // For struct in_addr.
#include <stdlib.h>

#include "common.h"
#include "log.h"

/**
 * Creates hashtable from IP addresses list.
 *
 * This function allocates a hashtable which converts the string
 * based ipv4 address into uint32_t format and store them into hashtable
 * for fast lookup operations. They key for the hashtable is the uint32_t
 * ip address. and value is ignored (kept as 1). Since GLib does not have
 * any HashSet, hashtable is used and the values corresponding to the key
 * are ignored.
 *
 * NOTE: As of now we do not have support for ipv6 addresses thus all ipv6
 * addresses will be ignored.
 *
 * Args:
 *   @ip_list list of string IP addresses
 *   @num_ips number of IP addresses in the list
 *
 * Returns:
 *   Resulting hashtable containing IP addresses as key
 *   In case memory allocation fails, the process is terminated.
 *   NULL, in case an invalid IP address is present in the ip_list.
 */
GHashTable *
create_hashtable_from_ip_list(const char *ip_list[], int num_ips)
{
    int i;
    GHashTable *ht;

    ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    for (i = 0; i < num_ips; i++) {
        struct in_addr ip = {0};
        int success;

        success = inet_aton(ip_list[i], &ip);
        if (success == 0) {
            unsigned char buf[sizeof(struct in6_addr)];

            if (inet_pton(AF_INET6, ip_list[i], buf) == 1) {
                LOG(WARNING, "%s: No CT migration support for ipv6 address: "
                    "%s.", __func__, ip_list[i]);
            } else {
                LOG(ERROR, "%s: Invalid IP address %s", __func__, ip_list[i]);
                g_hash_table_destroy(ht);
                return NULL;
            }
        } else {
            g_hash_table_insert(ht, GUINT_TO_POINTER(ip.s_addr),
                                GINT_TO_POINTER(1));
        }
    }

    return ht;
}

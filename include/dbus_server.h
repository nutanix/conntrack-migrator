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
 * implemented in dbus_server.c
 */

#ifndef DBUS_SERVER_H
#define DBUS_SERVER_H

#include <stdbool.h>

#include <glib.h>
#include <gio/gio.h>
#include <pthread.h>

#include "common.h"

/**
 * Represents the mode of operation for the lmct_qemu_helper
 */
enum op_mode {
    LOAD_MODE = 1, // Read from dbus and program entries into kernel
    SAVE_MODE = 2  // Read from kernel and send to dbus
};

/**
 * Represents the arguments to be passed to the dbus_server thread.
 */
struct dbus_targs {
    pthread_t tid;           // represents the thread id
    const char *helper_id;   // helper_id used to export the object
    bool *stop_flag;         // flag to stop the thread listening for events
    enum op_mode mode;       // mode of operation LOAD/SAVE
};

void *
dbus_server_init(void *);

#endif /* DBUS_SERVER_H */

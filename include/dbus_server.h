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
 *
 * The loop_mu / loop / should_quit fields are used by
 * dbus_server_request_quit() to ask the dbus thread to exit its main
 * loop from another thread (typically dmain's error-cleanup path).
 * should_quit is latched if the loop does not exist yet. Once the loop
 * pointer is published, quit is delivered as an idle on the loop's
 * GMainContext so g_main_loop_run cannot miss it.
 * Callers MUST pthread_mutex_init(&loop_mu, NULL) before pthread_create
 * and pthread_mutex_destroy() after pthread_join.
 */
struct dbus_targs {
    pthread_t tid;           // represents the thread id
    const char *helper_id;   // helper_id used to export the object
    bool *stop_flag;         // flag to stop the thread listening for events
    enum op_mode mode;       // mode of operation LOAD/SAVE
    enum save_mode_op_type save_op_type; // SAVE-only; consumed by on_save
                                         // to size the outgoing data_template.
                                         // Undefined in LOAD mode (on_save
                                         // never fires there).
    struct load_mode_config *load_config; // LOAD-only mode config. NULL in SAVE.

    /* Loop shutdown coordination. See dbus_server_request_quit. */
    pthread_mutex_t loop_mu;
    GMainLoop *loop;         // NULL until dbus_server_init creates it
    bool should_quit;        // set by dbus_server_request_quit
};

void *
dbus_server_init(void *);

/**
 * Ask the dbus thread to leave its main loop.
 * - Safe from any thread.
 * - Safe before the loop exists: should_quit is latched and applied when
 *   the loop is published.
 * - Safe after the loop is published but before g_main_loop_run: an idle
 *   on the loop's GMainContext quits from inside run.
 * - NULL is a no-op.
 *
 * @targs dbus thread args.
 */
void
dbus_server_request_quit(struct dbus_targs *);

#endif /* DBUS_SERVER_H */

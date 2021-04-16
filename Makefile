#
# Copyright (c) 2021, Nutanix, Inc.
#
# Author: priyankar.jain@nutanix.com
#
# Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
# the GNU General Public License version 2.

CC := gcc
LDLIBS := -lmnl \
					-lnetfilter_conntrack \
					-lpthread \
					-lglib-2.0 \
					-lgio-2.0 \
					-lgobject-2.0

INCLUDE_DIRS := include/ \
								gen/ \
								/usr/include/glib-2.0 \
								/usr/lib64/glib-2.0/include \
								/usr/include/gio-unix-2.0/

INCLUDE_FLAGS := $(addprefix -I, $(INCLUDE_DIRS))
CFLAGS := $(INCLUDE_FLAGS) -O2 -ggdb -Wall -Wextra -Wno-unused-parameter -Wunused -fstack-protector -Wl,-z,relro -Wformat -Wformat-security -Werror=format-security

SRC_DIR := src
GEN_DIR := gen

BUILD_DIR := build
BUILD_DIR_GEN := $(BUILD_DIR)/gen
BUILD_DIR_SRC := $(BUILD_DIR)/src

MAIN_SRCS := common.c \
							conntrack.c \
							conntrack_entry.c \
							conntrack_entry_print.c \
							conntrack_store.c \
							data_template.c \
							marshal.c \
							unmarshal.c \
							dbus_server.c \
							log.c \
							lmct_config.c \
							main.c

DBUS_GENERATED := dbus_vmstate1.c

SRCS := $(addprefix $(SRC_DIR)/, $(MAIN_SRCS))
GEN_SRCS := $(addprefix $(GEN_DIR)/, $(DBUS_GENERATED))


OBJS := $(addprefix $(BUILD_DIR)/,$(SRCS:.c=.o))
GEN_OBJS := $(addprefix $(BUILD_DIR)/,$(GEN_SRCS:.c=.o))
CONNTRACK_MIGRATOR := $(BUILD_DIR)/conntrack_migrator

TEST_DIR := tests

MAIN_MOCK_SRCS := mock_log.c \
									mock_conntrack_entry_print.c

MAIN_TEST_SRCS := test_common.c \
							test_conntrack_entry.c \
							test_conntrack_store.c \
							test_data_template.c \
							test_marshal.c \
							test_unmarshal.c \
							test_lmct_config.c \
							test_conntrack.c \
							test_dbus_server.c

MOCK_SRCS := $(addprefix $(TEST_DIR)/, $(MAIN_MOCK_SRCS))
TEST_SRCS := $(addprefix $(TEST_DIR)/, $(MAIN_TEST_SRCS))

TEST_BUILD_DIR := $(BUILD_DIR)/$(TEST_DIR)
TEST_RUNNER_DIR := $(BUILD_DIR)/$(TEST_DIR)/runner
TEST_OBJS := $(addprefix $(TEST_BUILD_DIR)/,$(MAIN_TEST_SRCS:.c=.o))
MOCK_OBJS := $(addprefix $(TEST_BUILD_DIR)/,$(MAIN_MOCK_SRCS:.c=.o))
TEST_RUNNERS := $(addprefix $(TEST_RUNNER_DIR)/,$(MAIN_TEST_SRCS:.c=.out))

.PHONY: all check clean clean_secondary setup_test_dbus

all: $(GEN_SRCS) $(CONNTRACK_MIGRATOR) ;

$(TEST_BUILD_DIR):
	mkdir -p $@

$(TEST_RUNNER_DIR):
	mkdir -p $@

$(BUILD_DIR_GEN):
	mkdir -p $@

$(BUILD_DIR_SRC):
	mkdir -p $@

$(GEN_DIR):
	mkdir -p $@

$(GEN_SRCS): dbus-vmstate1.xml | $(GEN_DIR)
	gdbus-codegen --interface-prefix org.qemu. --output-directory $(GEN_DIR) --generate-c-code dbus_vmstate1 --c-generate-object-manager $<

$(BUILD_DIR_GEN)/%.o: $(GEN_DIR)/%.c $(GEN_SRCS)| $(BUILD_DIR_GEN)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR_SRC)/%.o: $(SRC_DIR)/%.c $(GEN_SRCS)| $(BUILD_DIR_SRC)
	$(CC) $(CFLAGS) -c -o $@ $<

$(CONNTRACK_MIGRATOR): $(GEN_OBJS) $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(TEST_BUILD_DIR)/test_%.o: $(TEST_DIR)/test_%.c | $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $^

$(TEST_BUILD_DIR)/mock_%.o: $(TEST_DIR)/mock_%.c | $(TEST_BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $^

$(TEST_RUNNER_DIR)/test_%.out: $(GEN_OBJS) $(BUILD_DIR_SRC)/%.o $(MOCK_OBJS) $(TEST_BUILD_DIR)/test_%.o | $(TEST_RUNNER_DIR)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS) -lcheck
	@echo "======================= Running Test ========================="
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/tmp/dbus/system_bus_socket ./$@
	@echo "=============================================================="

.SECONDARY: $(TEST_OBJS) $(MOCK_OBJS)

setup_test_dbus:
	mkdir -p /tmp/dbus
	dbus-daemon --config-file ./tests/dbus-test.conf --print-address 1 --print-pid 1

check: clean_secondary setup_test_dbus $(TEST_RUNNERS)
	pkill -9 -f "dbus-daemon --config-file ./tests/dbus-test.conf"

clean_secondary:
	rm -rf $(TEST_BUILD_DIR)
	rm -rf /tmp/dbus

clean: clean_secondary
	rm -rf $(BUILD_DIR) $(GEN_DIR)


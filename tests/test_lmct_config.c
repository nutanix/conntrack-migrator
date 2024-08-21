/**
 * Copyright (c) 2021, Nutanix, Inc.
 *
 * Author(s): priyankar.jain@nutanix.com
 *
 * Conntrack-Migrator v.1.0 is dual licensed under the BSD 3 Clause License or
 * the GNU General Public License version 2.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <check.h>

#include "lmct_config.h"
#include "log.h"

const char conf_path[] = "/tmp/lmct_test_conf";

static void
prepare_config_file(char conf_str[])
{
    FILE *fp;
    fp = fopen(conf_path, "w");
    ck_assert(fp != NULL);
    fprintf(fp, "%s", conf_str);
    fclose(fp);
}

static void
cleanup()
{
    remove(conf_path);
}

static void
init_config_for_test()
{
    lmct_conf.log_lvl = 0;
    lmct_conf.max_entries_to_migrate = 1;
}

START_TEST(test_lmct_config_present)
{
    init_config_for_test();
    char conf_str[] = "[CONNTRACK]\n"
                      "max_entries_to_migrate=100\n"
                      "[LOG]\n"
                      "level=ERROR\n";

    prepare_config_file(conf_str);
    init_lmct_config(conf_path);
    cleanup();

    ck_assert(lmct_conf.max_entries_to_migrate == 100);
    ck_assert(lmct_conf.log_lvl == ERROR);

}
END_TEST

START_TEST(test_lmct_config_log_level_not_present)
{
    init_config_for_test();
    char conf_str[] = "[CONNTRACK]\n"
                      "max_entries_to_migrate=100\n";

    prepare_config_file(conf_str);
    init_lmct_config(conf_path);
    cleanup();

    ck_assert(lmct_conf.max_entries_to_migrate == 100);
    ck_assert(lmct_conf.log_lvl == INFO);

}
END_TEST

START_TEST(test_lmct_config_max_entries_not_present)
{
    init_config_for_test();
    char conf_str[] = "[LOG]\n"
                      "level=WARNING\n";

    prepare_config_file(conf_str);
    init_lmct_config(conf_path);
    cleanup();

    ck_assert(lmct_conf.max_entries_to_migrate == 10000);
    ck_assert(lmct_conf.log_lvl == WARNING);

}
END_TEST

START_TEST(test_lmct_config_invalid_log_level)
{
    init_config_for_test();
    char conf_str[] = "[CONNTRACK]\n"
                      "max_entries_to_migrate=100\n"
                      "[LOG]\n"
                      "level=abcdef\n";
    prepare_config_file(conf_str);
    init_lmct_config(conf_path);
    cleanup();

    ck_assert(lmct_conf.max_entries_to_migrate == 100);
    ck_assert(lmct_conf.log_lvl == INFO);
}
END_TEST

START_TEST(test_lmct_config_invalid_max_entries_to_migrate)
{
    int pid = fork();
    int status;
    ck_assert(pid >= 0);

    if (pid == 0) {
        char conf_str[] = "[CONNTRACK]\n"
                          "max_entries_to_migrate=abc\n"
                          "[LOG]\n"
                          "level=INFO\n";

        prepare_config_file(conf_str);
        init_lmct_config(conf_path);
        exit(EXIT_SUCCESS);
    } else {
        waitpid(pid, &status, 0);
        cleanup();
        ck_assert(WEXITSTATUS(status) == EXIT_FAILURE);
    }

    pid = fork();
    status = 0;
    ck_assert(pid >= 0);

    if (pid == 0) {
        char conf_str2[] = "[CONNTRACK]\n"
                           "max_entries_to_migrate=-1\n"
                           "[LOG]\n"
                           "level=INFO\n";

        prepare_config_file(conf_str2);
        (void)init_lmct_config(conf_path);
        exit(EXIT_SUCCESS);
    } else {
        waitpid(pid, &status, 0);
        cleanup();
        ck_assert(WEXITSTATUS(status) == EXIT_FAILURE);
    }
}
END_TEST

START_TEST(test_lmct_config_empty)
{
    init_config_for_test();
    char conf_str[] = "";

    prepare_config_file(conf_str);
    init_lmct_config(conf_path);

    cleanup();
    ck_assert(lmct_conf.max_entries_to_migrate == 10000);
    ck_assert(lmct_conf.log_lvl == INFO);

}
END_TEST

START_TEST(test_lmct_config_not_present)
{
    lmct_conf.log_lvl = INFO;
    lmct_conf.max_entries_to_migrate = 10000;

    cleanup();

    init_lmct_config(conf_path);

    ck_assert(lmct_conf.max_entries_to_migrate == 10000);
    ck_assert(lmct_conf.log_lvl == INFO);
}
END_TEST

Suite *
lmct_config_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("LmctConfig");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_lmct_config_present);
    tcase_add_test(tc_core, test_lmct_config_log_level_not_present);
    tcase_add_test(tc_core, test_lmct_config_max_entries_not_present);
    tcase_add_test(tc_core, test_lmct_config_invalid_log_level);
    tcase_add_test(tc_core, test_lmct_config_invalid_max_entries_to_migrate);
    tcase_add_test(tc_core, test_lmct_config_empty);
    tcase_add_test(tc_core, test_lmct_config_not_present);

    suite_add_tcase(s, tc_core);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = lmct_config_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

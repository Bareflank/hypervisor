//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef TEST_H
#define TEST_H

#include <unittest.h>

class bfm_ut : public unittest
{
public:

    bfm_ut();
    ~bfm_ut() {}

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_command_line_parser_with_no_args();
    void test_command_line_parser_with_empty_args();
    void test_command_line_parser_with_unknown_command();
    void test_command_line_parser_with_unknown_command_maintains_state();
    void test_command_line_parser_with_unknown_option_single_bar();
    void test_command_line_parser_with_unknown_option_dual_bar();
    void test_command_line_parser_with_single_bar_help();
    void test_command_line_parser_with_dual_bar_help();
    void test_command_line_parser_with_load_no_modules();
    void test_command_line_parser_with_load_no_modules_empty_arg();
    void test_command_line_parser_with_load_no_modules_maintains_state();
    void test_command_line_parser_with_valid_load();
    void test_command_line_parser_with_valid_load_unknown_option();
    void test_command_line_parser_with_single_bar_help_unknown_option();
    void test_command_line_parser_with_dual_bar_help_unknown_option();
    void test_command_line_parser_with_unknown_command_before_valid_load();
    void test_command_line_parser_with_unknown_command_after_valid_load();
    void test_command_line_parser_with_help_and_valid_load();
    void test_command_line_parser_with_valid_unload();
    void test_command_line_parser_with_valid_start();
    void test_command_line_parser_with_valid_stop();
    void test_command_line_parser_with_valid_dump();
    void test_command_line_parser_with_valid_status();
    void test_command_line_parser_no_vcpuid();
    void test_command_line_parser_invalid_vcpuid();
    void test_command_line_parser_valid_vcpuid();

    void test_file_read_with_bad_filename();
    void test_file_read_with_good_filename();

    void test_ioctl_driver_inaccessible();
    void test_ioctl_add_module_with_invalid_length();
    void test_ioctl_add_module_failed();
    void test_ioctl_load_vmm_failed();
    void test_ioctl_unload_vmm_failed();
    void test_ioctl_start_vmm_failed();
    void test_ioctl_stop_vmm_failed();
    void test_ioctl_dump_vmm_with_invalid_drr();
    void test_ioctl_dump_vmm_failed();
    void test_ioctl_vmm_status_with_invalid_drr();
    void test_ioctl_vmm_status_failed();

    void test_ioctl_driver_process_invalid_file();
    void test_ioctl_driver_process_invalid_ioctl();
    void test_ioctl_driver_process_invalid_command_line_parser();
    void test_ioctl_driver_process_help();
    void test_ioctl_driver_process_load_vmm_running();
    void test_ioctl_driver_process_load_vmm_loaded();
    void test_ioctl_driver_process_load_vmm_corrupt();
    void test_ioctl_driver_process_load_vmm_unknown_status();
    void test_ioctl_driver_process_load_bad_modules_filename();
    void test_ioctl_driver_process_load_bad_module_filename();
    void test_ioctl_driver_process_load_add_module_failed();
    void test_ioctl_driver_process_load_load_failed();
    void test_ioctl_driver_process_load_success();
    void test_ioctl_driver_process_unload_vmm_running();
    void test_ioctl_driver_process_unload_vmm_loaded();
    void test_ioctl_driver_process_unload_vmm_unloaded();
    void test_ioctl_driver_process_unload_vmm_corrupt();
    void test_ioctl_driver_process_unload_vmm_unknown_status();
    void test_ioctl_driver_process_unload_unload_failed();
    void test_ioctl_driver_process_unload_success();
    void test_ioctl_driver_process_start_vmm_running();
    void test_ioctl_driver_process_start_vmm_loaded();
    void test_ioctl_driver_process_start_vmm_unloaded();
    void test_ioctl_driver_process_start_vmm_corrupt();
    void test_ioctl_driver_process_start_vmm_unknown_status();
    void test_ioctl_driver_process_start_start_failed();
    void test_ioctl_driver_process_start_success();
    void test_ioctl_driver_process_stop_vmm_loaded();
    void test_ioctl_driver_process_stop_vmm_unloaded();
    void test_ioctl_driver_process_stop_vmm_corrupt();
    void test_ioctl_driver_process_stop_vmm_unknown_status();
    void test_ioctl_driver_process_stop_stop_failed();
    void test_ioctl_driver_process_stop_success();
    void test_ioctl_driver_process_dump_vmm_unloaded();
    void test_ioctl_driver_process_dump_vmm_corrupted();
    void test_ioctl_driver_process_dump_vmm_unknown_status();
    void test_ioctl_driver_process_dump_dump_failed();
    void test_ioctl_driver_process_dump_success_running();
    void test_ioctl_driver_process_dump_success_loaded();
    void test_ioctl_driver_process_vmm_status_running();
    void test_ioctl_driver_process_vmm_status_loaded();
    void test_ioctl_driver_process_vmm_status_unloaded();
    void test_ioctl_driver_process_vmm_status_corrupt();
    void test_ioctl_driver_process_vmm_status_unknown_status();

    void test_split_empty_string();
    void test_split_with_non_existing_delimiter();
    void test_split_with_delimiter();
};

#endif

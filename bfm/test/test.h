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
    void test_command_line_parser_with_unknown_command();
    void test_command_line_parser_with_unknown_option_single_bar();
    void test_command_line_parser_with_unknown_option_dual_bar();
    void test_command_line_parser_with_single_bar_help();
    void test_command_line_parser_with_dual_bar_help();
    void test_command_line_parser_with_start_no_modules();
    void test_command_line_parser_with_valid_start();
    void test_command_line_parser_with_valid_start_unknown_option();
    void test_command_line_parser_with_single_bar_help_unknown_option();
    void test_command_line_parser_with_dual_bar_help_unknown_option();
    void test_command_line_parser_with_unknown_command_before_valid_start();
    void test_command_line_parser_with_unknown_command_after_valid_start();
    void test_command_line_parser_with_help_and_valid_start();
    void test_command_line_parser_with_valid_stop();
    void test_command_line_parser_with_valid_dump();

    void test_file_exists_with_bad_filename();
    void test_file_exists_with_good_filename();
    void test_file_read_with_bad_filename();
    void test_file_read_with_good_filename();

    void test_ioctl_with_unknown_command();
    void test_ioctl_with_null_msg();
    void test_ioctl_with_zero_length();

    void test_ioctl_driver_with_null_fb();
    void test_ioctl_driver_null_ioctlb();
    void test_ioctl_driver_with_null_clp();
    void test_ioctl_driver_with_invalid_clp();
    void test_ioctl_driver_with_unknown_command();
    void test_ioctl_driver_with_help();
    void test_ioctl_driver_with_start_and_no_modules();
    void test_ioctl_driver_with_start_and_bad_module_filename();
    void test_ioctl_driver_with_start_and_empty_list_of_modules();
    void test_ioctl_driver_with_start_and_one_bad_module_filename();
    void test_ioctl_driver_with_start_and_more_than_one_bad_module_filename();
    void test_ioctl_driver_with_start_and_empty_module();
    void test_ioctl_driver_with_start_and_ioctl_add_module_failure();
    void test_ioctl_driver_with_start_and_ioctl_start_vmm_failure();
    void test_ioctl_driver_with_start_and_ioctl_start_vmm_success();
    void test_ioctl_driver_with_stop_and_ioctl_stop_vmm_failure();
    void test_ioctl_driver_with_stop_and_ioctl_stop_vmm_success();
    void test_ioctl_driver_with_stop_and_ioctl_dump_vmm_failure();
    void test_ioctl_driver_with_stop_and_ioctl_dump_vmm_success();

    void test_split_empty_string();
    void test_split_with_non_existing_delimiter();
    void test_split_with_delimiter();
};

#endif

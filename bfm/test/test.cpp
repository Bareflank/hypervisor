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

#include <test.h>

bfm_ut::bfm_ut()
{
}

bool
bfm_ut::init()
{
    return true;
}

bool
bfm_ut::fini()
{
    return true;
}

bool
bfm_ut::list()
{
    this->test_command_line_parser_with_no_args();
    this->test_command_line_parser_with_unknown_command();
    this->test_command_line_parser_with_unknown_command_maintains_state();
    this->test_command_line_parser_with_unknown_option_single_bar();
    this->test_command_line_parser_with_unknown_option_dual_bar();
    this->test_command_line_parser_with_single_bar_help();
    this->test_command_line_parser_with_dual_bar_help();
    this->test_command_line_parser_with_load_no_modules();
    this->test_command_line_parser_with_load_no_modules_maintains_state();
    this->test_command_line_parser_with_valid_load();
    this->test_command_line_parser_with_valid_load_unknown_option();
    this->test_command_line_parser_with_single_bar_help_unknown_option();
    this->test_command_line_parser_with_dual_bar_help_unknown_option();
    this->test_command_line_parser_with_unknown_command_before_valid_load();
    this->test_command_line_parser_with_unknown_command_after_valid_load();
    this->test_command_line_parser_with_help_and_valid_load();
    this->test_command_line_parser_with_valid_unload();
    this->test_command_line_parser_with_valid_start();
    this->test_command_line_parser_with_valid_stop();
    this->test_command_line_parser_with_valid_dump();
    this->test_command_line_parser_with_valid_status();

    this->test_file_read_with_bad_filename();
    this->test_file_read_with_good_filename();

    this->test_ioctl_driver_inaccessible();
    this->test_ioctl_add_module_with_invalid_length();
    this->test_ioctl_add_module_failed();
    this->test_ioctl_load_vmm_failed();
    this->test_ioctl_unload_vmm_failed();
    this->test_ioctl_start_vmm_failed();
    this->test_ioctl_stop_vmm_failed();
    this->test_ioctl_dump_vmm_with_invalid_drr();
    this->test_ioctl_dump_vmm_failed();
    this->test_ioctl_vmm_status_with_invalid_drr();
    this->test_ioctl_vmm_status_failed();

    this->test_ioctl_driver_process_invalid_file();
    this->test_ioctl_driver_process_invalid_ioctl();
    this->test_ioctl_driver_process_invalid_command_line_parser();
    this->test_ioctl_driver_process_help();
    this->test_ioctl_driver_process_load_vmm_running();
    this->test_ioctl_driver_process_load_vmm_loaded();
    this->test_ioctl_driver_process_load_vmm_corrupt();
    this->test_ioctl_driver_process_load_vmm_unknown_status();
    this->test_ioctl_driver_process_load_bad_modules_filename();
    this->test_ioctl_driver_process_load_bad_module_filename();
    this->test_ioctl_driver_process_load_add_module_failed();
    this->test_ioctl_driver_process_load_load_failed();
    this->test_ioctl_driver_process_load_success();
    this->test_ioctl_driver_process_unload_vmm_running();
    this->test_ioctl_driver_process_unload_vmm_loaded();
    this->test_ioctl_driver_process_unload_vmm_unloaded();
    this->test_ioctl_driver_process_unload_vmm_corrupt();
    this->test_ioctl_driver_process_unload_vmm_unknown_status();
    this->test_ioctl_driver_process_unload_unload_failed();
    this->test_ioctl_driver_process_unload_success();
    this->test_ioctl_driver_process_start_vmm_running();
    this->test_ioctl_driver_process_start_vmm_loaded();
    this->test_ioctl_driver_process_start_vmm_unloaded();
    this->test_ioctl_driver_process_start_vmm_corrupt();
    this->test_ioctl_driver_process_start_vmm_unknown_status();
    this->test_ioctl_driver_process_start_start_failed();
    this->test_ioctl_driver_process_start_success();
    this->test_ioctl_driver_process_stop_vmm_loaded();
    this->test_ioctl_driver_process_stop_vmm_unloaded();
    this->test_ioctl_driver_process_stop_vmm_corrupt();
    this->test_ioctl_driver_process_stop_vmm_unknown_status();
    this->test_ioctl_driver_process_stop_stop_failed();
    this->test_ioctl_driver_process_stop_success();
    this->test_ioctl_driver_process_dump_vmm_unloaded();
    this->test_ioctl_driver_process_dump_vmm_unknown_status();
    this->test_ioctl_driver_process_dump_dump_failed();
    this->test_ioctl_driver_process_dump_success();
    this->test_ioctl_driver_process_vmm_status_running();
    this->test_ioctl_driver_process_vmm_status_loaded();
    this->test_ioctl_driver_process_vmm_status_unloaded();
    this->test_ioctl_driver_process_vmm_status_corrupt();
    this->test_ioctl_driver_process_vmm_status_unknown_status();

    this->test_split_empty_string();
    this->test_split_with_non_existing_delimiter();
    this->test_split_with_delimiter();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(bfm_ut);
}

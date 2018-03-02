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

exit_handler_intel_x64_ut::exit_handler_intel_x64_ut()
{
}

bool
exit_handler_intel_x64_ut::init()
{
    return true;
}

bool
exit_handler_intel_x64_ut::fini()
{
    return true;
}

bool
exit_handler_intel_x64_ut::list()
{
    this->test_entry_valid();
    this->test_entry_throws_general_exception();
    this->test_entry_throws_standard_exception();
    this->test_entry_throws_any_exception();

    this->test_vm_exit_reason_unknown();
    this->test_vm_exit_reason_cpuid();
    this->test_vm_exit_reason_invd();
    this->test_vm_exit_reason_vmcall_invalid_opcode();
    this->test_vm_exit_reason_vmcall_invalid_magic();
    this->test_vm_exit_reason_vmcall_protocol_version();
    this->test_vm_exit_reason_vmcall_bareflank_version();
    this->test_vm_exit_reason_vmcall_user_version();
    this->test_vm_exit_reason_vmcall_unknown_version();
    this->test_vm_exit_reason_vmcall_registers();
    this->test_vm_exit_reason_vmcall_unittest();
    this->test_vm_exit_reason_vmcall_event();
    this->test_vm_exit_reason_vmcall_start();
    this->test_vm_exit_reason_vmcall_stop();
    this->test_vm_exit_reason_vmcall_data_unknown();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_input_nullptr();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_output_nullptr();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_input_size_0();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_output_size_0();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_small();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_input_size_too_big();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_big();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_map_fails();
    this->test_vm_exit_reason_vmcall_data_string_unformatted_success();
    this->test_vm_exit_reason_vmcall_data_string_json_input_nullptr();
    this->test_vm_exit_reason_vmcall_data_string_json_output_nullptr();
    this->test_vm_exit_reason_vmcall_data_string_json_input_size_0();
    this->test_vm_exit_reason_vmcall_data_string_json_output_size_0();
    this->test_vm_exit_reason_vmcall_data_string_json_output_size_too_small();
    this->test_vm_exit_reason_vmcall_data_string_json_input_size_too_big();
    this->test_vm_exit_reason_vmcall_data_string_json_output_size_too_big();
    this->test_vm_exit_reason_vmcall_data_string_json_map_fails();
    this->test_vm_exit_reason_vmcall_data_string_json_invalid();
    this->test_vm_exit_reason_vmcall_data_string_json_success();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_input_nullptr();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_output_nullptr();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_input_size_0();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_output_size_0();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_small();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_input_size_too_big();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_big();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_map_fails();
    this->test_vm_exit_reason_vmcall_data_data_unformatted_success();
    this->test_vm_exit_reason_vmxoff();
    this->test_vm_exit_reason_rdmsr_debug_ctl();
    this->test_vm_exit_reason_rdmsr_pat();
    this->test_vm_exit_reason_rdmsr_efer();
    this->test_vm_exit_reason_rdmsr_perf();
    this->test_vm_exit_reason_rdmsr_cs();
    this->test_vm_exit_reason_rdmsr_esp();
    this->test_vm_exit_reason_rdmsr_eip();
    this->test_vm_exit_reason_rdmsr_fs_base();
    this->test_vm_exit_reason_rdmsr_gs_base();
    this->test_vm_exit_reason_rdmsr_default();
    this->test_vm_exit_reason_rdmsr_ignore();
    this->test_vm_exit_reason_wrmsr_debug_ctrl();
    this->test_vm_exit_reason_wrmsr_pat();
    this->test_vm_exit_reason_wrmsr_efer();
    this->test_vm_exit_reason_wrmsr_perf();
    this->test_vm_exit_reason_wrmsr_cs();
    this->test_vm_exit_reason_wrmsr_esp();
    this->test_vm_exit_reason_wrmsr_eip();
    this->test_vm_exit_reason_wrmsr_fs_base();
    this->test_vm_exit_reason_wrmsr_gs_base();
    this->test_vm_exit_reason_wrmsr_default();
    this->test_vm_exit_failure_check();
    this->test_halt();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(exit_handler_intel_x64_ut);
}

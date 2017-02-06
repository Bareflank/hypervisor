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

class exit_handler_intel_x64_ut : public unittest
{
public:

    exit_handler_intel_x64_ut();
    ~exit_handler_intel_x64_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

private:

    void test_entry_valid();
    void test_entry_throws_general_exception();
    void test_entry_throws_standard_exception();
    void test_entry_throws_any_exception();

    void test_vm_exit_reason_unknown();
    void test_vm_exit_reason_cpuid();
    void test_vm_exit_reason_invd();
    void test_vm_exit_reason_vmcall_invalid_opcode();
    void test_vm_exit_reason_vmcall_invalid_magic();
    void test_vm_exit_reason_vmcall_protocol_version();
    void test_vm_exit_reason_vmcall_bareflank_version();
    void test_vm_exit_reason_vmcall_user_version();
    void test_vm_exit_reason_vmcall_unknown_version();
    void test_vm_exit_reason_vmcall_registers();
    void test_vm_exit_reason_vmcall_unittest();
    void test_vm_exit_reason_vmcall_event();
    void test_vm_exit_reason_vmcall_start();
    void test_vm_exit_reason_vmcall_stop();
    void test_vm_exit_reason_vmcall_data_unknown();
    void test_vm_exit_reason_vmcall_data_string_unformatted_input_nullptr();
    void test_vm_exit_reason_vmcall_data_string_unformatted_output_nullptr();
    void test_vm_exit_reason_vmcall_data_string_unformatted_input_size_0();
    void test_vm_exit_reason_vmcall_data_string_unformatted_output_size_0();
    void test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_small();
    void test_vm_exit_reason_vmcall_data_string_unformatted_input_size_too_big();
    void test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_big();
    void test_vm_exit_reason_vmcall_data_string_unformatted_map_fails();
    void test_vm_exit_reason_vmcall_data_string_unformatted_success();
    void test_vm_exit_reason_vmcall_data_string_json_input_nullptr();
    void test_vm_exit_reason_vmcall_data_string_json_output_nullptr();
    void test_vm_exit_reason_vmcall_data_string_json_input_size_0();
    void test_vm_exit_reason_vmcall_data_string_json_output_size_0();
    void test_vm_exit_reason_vmcall_data_string_json_output_size_too_small();
    void test_vm_exit_reason_vmcall_data_string_json_input_size_too_big();
    void test_vm_exit_reason_vmcall_data_string_json_output_size_too_big();
    void test_vm_exit_reason_vmcall_data_string_json_map_fails();
    void test_vm_exit_reason_vmcall_data_string_json_invalid();
    void test_vm_exit_reason_vmcall_data_string_json_success();
    void test_vm_exit_reason_vmcall_data_data_unformatted_input_nullptr();
    void test_vm_exit_reason_vmcall_data_data_unformatted_output_nullptr();
    void test_vm_exit_reason_vmcall_data_data_unformatted_input_size_0();
    void test_vm_exit_reason_vmcall_data_data_unformatted_output_size_0();
    void test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_small();
    void test_vm_exit_reason_vmcall_data_data_unformatted_input_size_too_big();
    void test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_big();
    void test_vm_exit_reason_vmcall_data_data_unformatted_map_fails();
    void test_vm_exit_reason_vmcall_data_data_unformatted_success();
    void test_vm_exit_reason_vmxoff();
    void test_vm_exit_reason_rdmsr_debug_ctl();
    void test_vm_exit_reason_rdmsr_pat();
    void test_vm_exit_reason_rdmsr_efer();
    void test_vm_exit_reason_rdmsr_perf();
    void test_vm_exit_reason_rdmsr_cs();
    void test_vm_exit_reason_rdmsr_esp();
    void test_vm_exit_reason_rdmsr_eip();
    void test_vm_exit_reason_rdmsr_fs_base();
    void test_vm_exit_reason_rdmsr_gs_base();
    void test_vm_exit_reason_rdmsr_default();
    void test_vm_exit_reason_rdmsr_ignore();
    void test_vm_exit_reason_wrmsr_debug_ctrl();
    void test_vm_exit_reason_wrmsr_pat();
    void test_vm_exit_reason_wrmsr_efer();
    void test_vm_exit_reason_wrmsr_perf();
    void test_vm_exit_reason_wrmsr_cs();
    void test_vm_exit_reason_wrmsr_esp();
    void test_vm_exit_reason_wrmsr_eip();
    void test_vm_exit_reason_wrmsr_fs_base();
    void test_vm_exit_reason_wrmsr_gs_base();
    void test_vm_exit_reason_wrmsr_default();
    void test_vm_exit_failure_check();
    void test_halt();
};

#endif

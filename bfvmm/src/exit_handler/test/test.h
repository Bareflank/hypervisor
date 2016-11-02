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
    void test_vm_exit_reason_exception_or_non_maskable_interrupt();
    void test_vm_exit_reason_external_interrupt();
    void test_vm_exit_reason_triple_fault();
    void test_vm_exit_reason_init_signal();
    void test_vm_exit_reason_sipi();
    void test_vm_exit_reason_smi();
    void test_vm_exit_reason_other_smi();
    void test_vm_exit_reason_interrupt_window();
    void test_vm_exit_reason_nmi_window();
    void test_vm_exit_reason_task_switch();
    void test_vm_exit_reason_cpuid();
    void test_vm_exit_reason_getsec();
    void test_vm_exit_reason_hlt();
    void test_vm_exit_reason_invd();
    void test_vm_exit_reason_invlpg();
    void test_vm_exit_reason_rdpmc();
    void test_vm_exit_reason_rdtsc();
    void test_vm_exit_reason_rsm();

    void test_vm_exit_reason_vmcall_invalid_opcode();
    void test_vm_exit_reason_vmcall_invalid_magic();
    void test_vm_exit_reason_vmcall_protocol_version();
    void test_vm_exit_reason_vmcall_bareflank_version();
    void test_vm_exit_reason_vmcall_user_version();
    void test_vm_exit_reason_vmcall_unknown_version();
    void test_vm_exit_reason_vmcall_registers();
    void test_vm_exit_reason_vmcall_unittest();
    void test_vm_exit_reason_vmcall_event();
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
    void test_vm_exit_reason_vmclear();
    void test_vm_exit_reason_vmlaunch();
    void test_vm_exit_reason_vmptrld();
    void test_vm_exit_reason_vmptrst();
    void test_vm_exit_reason_vmread();
    void test_vm_exit_reason_vmresume();
    void test_vm_exit_reason_vmwrite();
    void test_vm_exit_reason_vmxoff();
    void test_vm_exit_reason_vmxon();
    void test_vm_exit_reason_control_register_accesses();
    void test_vm_exit_reason_mov_dr();
    void test_vm_exit_reason_io_instruction();
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
    void test_vm_exit_reason_vm_entry_failure_invalid_guest_state();
    void test_vm_exit_reason_vm_entry_failure_msr_loading();
    void test_vm_exit_reason_mwait();
    void test_vm_exit_reason_monitor_trap_flag();
    void test_vm_exit_reason_monitor();
    void test_vm_exit_reason_pause();
    void test_vm_exit_reason_vm_entry_failure_machine_check_event();
    void test_vm_exit_reason_tpr_below_threshold();
    void test_vm_exit_reason_apic_access();
    void test_vm_exit_reason_virtualized_eoi();
    void test_vm_exit_reason_access_to_gdtr_or_idtr();
    void test_vm_exit_reason_access_to_ldtr_or_tr();
    void test_vm_exit_reason_ept_violation();
    void test_vm_exit_reason_ept_misconfiguration();
    void test_vm_exit_reason_invept();
    void test_vm_exit_reason_rdtscp();
    void test_vm_exit_reason_vmx_preemption_timer_expired();
    void test_vm_exit_reason_invvpid();
    void test_vm_exit_reason_wbinvd();
    void test_vm_exit_reason_xsetbv();
    void test_vm_exit_reason_apic_write();
    void test_vm_exit_reason_rdrand();
    void test_vm_exit_reason_invpcid();
    void test_vm_exit_reason_vmfunc();
    void test_vm_exit_reason_rdseed();
    void test_vm_exit_reason_xsaves();
    void test_vm_exit_reason_xrstors();
    void test_vm_exit_failure_check();
    void test_halt();
};

#endif

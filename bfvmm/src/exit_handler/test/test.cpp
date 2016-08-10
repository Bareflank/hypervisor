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

    this->test_invalid_intrinics();
    this->test_vm_exit_reason_unknown();
    this->test_vm_exit_reason_exception_or_non_maskable_interrupt();
    this->test_vm_exit_reason_external_interrupt();
    this->test_vm_exit_reason_triple_fault();
    this->test_vm_exit_reason_init_signal();
    this->test_vm_exit_reason_sipi();
    this->test_vm_exit_reason_smi();
    this->test_vm_exit_reason_other_smi();
    this->test_vm_exit_reason_interrupt_window();
    this->test_vm_exit_reason_nmi_window();
    this->test_vm_exit_reason_task_switch();
    this->test_vm_exit_reason_cpuid();
    this->test_vm_exit_reason_getsec();
    this->test_vm_exit_reason_hlt();
    this->test_vm_exit_reason_invd();
    this->test_vm_exit_reason_invlpg();
    this->test_vm_exit_reason_rdpmc();
    this->test_vm_exit_reason_rdtsc();
    this->test_vm_exit_reason_rsm();
    this->test_vm_exit_reason_vmcall();
    this->test_vm_exit_reason_vmclear();
    this->test_vm_exit_reason_vmlaunch();
    this->test_vm_exit_reason_vmptrld();
    this->test_vm_exit_reason_vmptrst();
    this->test_vm_exit_reason_vmread();
    this->test_vm_exit_reason_vmresume();
    this->test_vm_exit_reason_vmwrite();
    this->test_vm_exit_reason_vmxoff();
    this->test_vm_exit_reason_vmxon();
    this->test_vm_exit_reason_control_register_accesses();
    this->test_vm_exit_reason_mov_dr();
    this->test_vm_exit_reason_io_instruction();
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
    this->test_vm_exit_reason_vm_entry_failure_invalid_guest_state();
    this->test_vm_exit_reason_vm_entry_failure_msr_loading();
    this->test_vm_exit_reason_mwait();
    this->test_vm_exit_reason_monitor_trap_flag();
    this->test_vm_exit_reason_monitor();
    this->test_vm_exit_reason_pause();
    this->test_vm_exit_reason_vm_entry_failure_machine_check_event();
    this->test_vm_exit_reason_tpr_below_threshold();
    this->test_vm_exit_reason_apic_access();
    this->test_vm_exit_reason_virtualized_eoi();
    this->test_vm_exit_reason_access_to_gdtr_or_idtr();
    this->test_vm_exit_reason_access_to_ldtr_or_tr();
    this->test_vm_exit_reason_ept_violation();
    this->test_vm_exit_reason_ept_misconfiguration();
    this->test_vm_exit_reason_invept();
    this->test_vm_exit_reason_rdtscp();
    this->test_vm_exit_reason_vmx_preemption_timer_expired();
    this->test_vm_exit_reason_invvpid();
    this->test_vm_exit_reason_wbinvd();
    this->test_vm_exit_reason_xsetbv();
    this->test_vm_exit_reason_apic_write();
    this->test_vm_exit_reason_rdrand();
    this->test_vm_exit_reason_invpcid();
    this->test_vm_exit_reason_vmfunc();
    this->test_vm_exit_reason_rdseed();
    this->test_vm_exit_reason_xsaves();
    this->test_vm_exit_reason_xrstors();
    this->test_vm_exit_reason_to_string();
    this->test_halt();
    this->test_vmread_failure();
    this->test_vmwrite_failure();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(exit_handler_intel_x64_ut);
}

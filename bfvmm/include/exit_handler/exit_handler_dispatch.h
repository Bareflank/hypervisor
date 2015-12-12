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

#ifndef EXIT_HANDLER_DISPATCH_H
#define EXIT_HANDLER_DISPATCH_H

#include <entry/entry_factory.h>

class exit_handler_dispatch
{
public:

    exit_handler_dispatch();
    virtual ~exit_handler_dispatch();

    virtual void dispatch();

protected:

    virtual void handle_exception_or_non_maskable_interrupt();
    virtual void handle_external_interrupt();
    virtual void handle_triple_fault();
    virtual void handle_init_signal();
    virtual void handle_sipi();
    virtual void handle_smi();
    virtual void handle_other_smi();
    virtual void handle_interrupt_window();
    virtual void handle_nmi_window();
    virtual void handle_task_switch();
    virtual void handle_cpuid();
    virtual void handle_getsec();
    virtual void handle_hlt();
    virtual void handle_invd();
    virtual void handle_invlpg();
    virtual void handle_rdpmc();
    virtual void handle_rdtsc();
    virtual void handle_rsm();
    virtual void handle_vmcall();
    virtual void handle_vmclear();
    virtual void handle_vmlaunch();
    virtual void handle_vmptrld();
    virtual void handle_vmptrst();
    virtual void handle_vmread();
    virtual void handle_vmresume();
    virtual void handle_vmwrite();
    virtual void handle_vmxoff();
    virtual void handle_vmxon();
    virtual void handle_control_register_accesses();
    virtual void handle_mov_dr();
    virtual void handle_io_instruction();
    virtual void handle_rdmsr();
    virtual void handle_wrmsr();
    virtual void handle_vm_entry_failure_invalid_guest_state();
    virtual void handle_vm_entry_failure_msr_loading();
    virtual void handle_mwait();
    virtual void handle_monitor_trap_flag();
    virtual void handle_monitor();
    virtual void handle_pause();
    virtual void handle_vm_entry_failure_machine_check_event();
    virtual void handle_tpr_below_threshold();
    virtual void handle_apic_access();
    virtual void handle_virtualized_eoi();
    virtual void handle_access_to_gdtr_or_idtr();
    virtual void handle_access_to_ldtr_or_tr();
    virtual void handle_ept_violation();
    virtual void handle_ept_misconfiguration();
    virtual void handle_invept();
    virtual void handle_rdtscp();
    virtual void handle_vmx_preemption_timer_expired();
    virtual void handle_invvpid();
    virtual void handle_wbinvd();
    virtual void handle_xsetbv();
    virtual void handle_apic_write();
    virtual void handle_rdrand();
    virtual void handle_invpcid();
    virtual void handle_vmfunc();
    virtual void handle_rdseed();
    virtual void handle_xsaves();
    virtual void handle_xrstors();

    virtual void advance_rip();

private:

    void spin_wait();
    void unimplemented_handler();

    const char *exit_reason_to_str(uint64_t exit_reason);

private:

    vcpu *m_vcpu;
    vmcs_intel_x64 *m_vmcs_intel_x64;
    intrinsics_intel_x64 *m_intrinsics_intel_x64;

    uint64_t m_exit_reason;
    uint64_t m_exit_qualification;
    uint64_t m_exit_instruction_length;
    uint64_t m_exit_instruction_information;
};

#endif

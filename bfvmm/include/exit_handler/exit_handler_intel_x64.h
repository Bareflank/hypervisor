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

#ifndef EXIT_HANDLER_INTEL_X64_H
#define EXIT_HANDLER_INTEL_X64_H

#include <memory>
#include <vmcs/vmcs_intel_x64.h>
#include <intrinsics/intrinsics_intel_x64.h>

// -----------------------------------------------------------------------------
// Exit Handler
// -----------------------------------------------------------------------------

/// Exit Handler
///
/// This class is responsible for detecting why a guest exited (i.e. stopped
/// it's execution), and dispatches the appropriated handler to emulate the
/// instruction that could not execute. Note that this class could be executed
/// a lot, so performance is key here.
///
/// This class works with the VMCS class to provide the bare minimum exit
/// handler needed to execute a 64bit guest, with the TRUE controls being used.
/// In general, the only instruction that needs to be emulated is the CPUID
/// instruction. If more functionality is needed (which is likely), the user
/// can subclass this class, and overload the handlers that are needed. The
/// basics are provided with this class to ease development.
///
class exit_handler_intel_x64
{
public:

    /// Default Constructor
    ///
    /// @param intrinsics the intriniscs class to be used by this class
    /// @throws invalid argument if the intrinsics class is null.
    ///
    exit_handler_intel_x64(std::shared_ptr<intrinsics_intel_x64> intrinsics = nullptr);

    /// Destructor
    ///
    virtual ~exit_handler_intel_x64() = default;

    /// Dispatch
    ///
    /// Called when a VM exit needs to be handled. This function will decode
    /// the exit reason, and dispatch the correct handler.
    ///
    virtual void dispatch();

    /// Halt
    ///
    /// Called when the exit handler needs to halt the CPU. This would mainly
    /// be due to an error.
    ///
    virtual void halt() noexcept;

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
    void unimplemented_handler();

    const char *exit_reason_to_str(uint64_t exit_reason);

    virtual uint64_t vmread(uint64_t field) const;
    virtual void vmwrite(uint64_t field, uint64_t value);

protected:

    friend class vcpu_ut;
    friend class vcpu_intel_x64;
    friend class exit_handler_intel_x64_ut;

    std::shared_ptr<intrinsics_intel_x64> m_intrinsics;

    uint64_t m_exit_reason;
    uint64_t m_exit_qualification;
    uint64_t m_exit_instruction_length;
    uint64_t m_exit_instruction_information;

    std::shared_ptr<vmcs_intel_x64> m_vmcs;
    std::shared_ptr<state_save_intel_x64> m_state_save;

private:

    virtual void set_vmcs(const std::shared_ptr<vmcs_intel_x64> &vmcs)
    { m_vmcs = vmcs; }

    virtual void set_state_save(const std::shared_ptr<state_save_intel_x64> &state_save)
    { m_state_save = state_save; }
};

#endif

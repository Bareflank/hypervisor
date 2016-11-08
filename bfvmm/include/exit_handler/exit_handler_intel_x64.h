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
#include <vmcall_interface.h>
#include <vmcs/vmcs_intel_x64.h>

// -----------------------------------------------------------------------------
// Exit Handler
// -----------------------------------------------------------------------------

/// Exit Handler
///
/// This class is responsible for detecting why a guest exited (i.e. stopped
/// its execution), and dispatches the appropriated handler to emulate the
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
    /// @expects none
    /// @ensures none
    ///
    exit_handler_intel_x64();

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~exit_handler_intel_x64() = default;

    /// Dispatch
    ///
    /// Called when a VM exit needs to be handled. This function will decode
    /// the exit reason, and dispatch the correct handler.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void dispatch();

    /// Halt
    ///
    /// Called when the exit handler needs to halt the CPU. This would mainly
    /// be due to an error.
    ///
    /// @expects none
    /// @ensures none
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

    virtual void advance_rip() noexcept;
    virtual void unimplemented_handler() noexcept;

    virtual std::string exit_reason_to_str(uint64_t exit_reason);

    virtual void handle_vmcall_versions(vmcall_registers_t &regs);
    virtual void handle_vmcall_registers(vmcall_registers_t &regs);
    virtual void handle_vmcall_data(vmcall_registers_t &regs);
    virtual void handle_vmcall_event(vmcall_registers_t &regs);
    virtual void handle_vmcall_unittest(vmcall_registers_t &regs);

protected:

    friend class vcpu_ut;
    friend class vcpu_intel_x64;
    friend class exit_handler_intel_x64_ut;
    friend exit_handler_intel_x64 setup_ehlr(const std::shared_ptr<vmcs_intel_x64> &vmcs);

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

// -----------------------------------------------------------------------------
// Exit Handler Exit Reasons
// -----------------------------------------------------------------------------

// *INDENT-OFF*

namespace intel_x64
{
namespace exit_reason
{
    constexpr const auto exception_or_non_maskable_interrupt            = 0UL;
    constexpr const auto external_interrupt                             = 1UL;
    constexpr const auto triple_fault                                   = 2UL;
    constexpr const auto init_signal                                    = 3UL;
    constexpr const auto sipi                                           = 4UL;
    constexpr const auto smi                                            = 5UL;
    constexpr const auto other_smi                                      = 6UL;
    constexpr const auto interrupt_window                               = 7UL;
    constexpr const auto nmi_window                                     = 8UL;
    constexpr const auto task_switch                                    = 9UL;
    constexpr const auto cpuid                                          = 10UL;
    constexpr const auto getsec                                         = 11UL;
    constexpr const auto hlt                                            = 12UL;
    constexpr const auto invd                                           = 13UL;
    constexpr const auto invlpg                                         = 14UL;
    constexpr const auto rdpmc                                          = 15UL;
    constexpr const auto rdtsc                                          = 16UL;
    constexpr const auto rsm                                            = 17UL;
    constexpr const auto vmcall                                         = 18UL;
    constexpr const auto vmclear                                        = 19UL;
    constexpr const auto vmlaunch                                       = 20UL;
    constexpr const auto vmptrld                                        = 21UL;
    constexpr const auto vmptrst                                        = 22UL;
    constexpr const auto vmread                                         = 23UL;
    constexpr const auto vmresume                                       = 24UL;
    constexpr const auto vmwrite                                        = 25UL;
    constexpr const auto vmxoff                                         = 26UL;
    constexpr const auto vmxon                                          = 27UL;
    constexpr const auto control_register_accesses                      = 28UL;
    constexpr const auto mov_dr                                         = 29UL;
    constexpr const auto io_instruction                                 = 30UL;
    constexpr const auto rdmsr                                          = 31UL;
    constexpr const auto wrmsr                                          = 32UL;
    constexpr const auto vm_entry_failure_invalid_guest_state           = 33UL;
    constexpr const auto vm_entry_failure_msr_loading                   = 34UL;
    constexpr const auto mwait                                          = 36UL;
    constexpr const auto monitor_trap_flag                              = 37UL;
    constexpr const auto monitor                                        = 39UL;
    constexpr const auto pause                                          = 40UL;
    constexpr const auto vm_entry_failure_machine_check_event           = 41UL;
    constexpr const auto tpr_below_threshold                            = 43UL;
    constexpr const auto apic_access                                    = 44UL;
    constexpr const auto virtualized_eoi                                = 45UL;
    constexpr const auto access_to_gdtr_or_idtr                         = 46UL;
    constexpr const auto access_to_ldtr_or_tr                           = 47UL;
    constexpr const auto ept_violation                                  = 48UL;
    constexpr const auto ept_misconfiguration                           = 49UL;
    constexpr const auto invept                                         = 50UL;
    constexpr const auto rdtscp                                         = 51UL;
    constexpr const auto vmx_preemption_timer_expired                   = 52UL;
    constexpr const auto invvpid                                        = 53UL;
    constexpr const auto wbinvd                                         = 54UL;
    constexpr const auto xsetbv                                         = 55UL;
    constexpr const auto apic_write                                     = 56UL;
    constexpr const auto rdrand                                         = 57UL;
    constexpr const auto invpcid                                        = 58UL;
    constexpr const auto vmfunc                                         = 59UL;
    constexpr const auto rdseed                                         = 61UL;
    constexpr const auto xsaves                                         = 63UL;
    constexpr const auto xrstors                                        = 64UL;
}
}

// *INDENT-ON*

#endif

//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef VCPU_INTEL_X64_H
#define VCPU_INTEL_X64_H

#include "vmexit/control_register.h"
#include "vmexit/cpuid.h"
#include "vmexit/ept_violation.h"
#include "vmexit/external_interrupt.h"
#include "vmexit/init_signal.h"
#include "vmexit/interrupt_window.h"
#include "vmexit/io_instruction.h"
#include "vmexit/monitor_trap.h"
#include "vmexit/nmi_window.h"
#include "vmexit/nmi.h"
#include "vmexit/rdmsr.h"
#include "vmexit/sipi_signal.h"
#include "vmexit/preemption_timer.h"
#include "vmexit/wrmsr.h"
#include "vmexit/xsetbv.h"

#include "ept.h"
#include "exit_handler.h"
#include "interrupt_queue.h"
#include "microcode.h"
#include "vcpu_global_state.h"
#include "vcpu_state.h"
#include "vmcs.h"
#include "vmx.h"
#include "vpid.h"

#include "../x64/unmapper.h"

#include "../../../vcpu/vcpu.h"
#include "../../../memory_manager/arch/x64/cr3.h"

// -----------------------------------------------------------------------------
// Defintion
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

using vcpu_delegate_t = delegate<void(vcpu *)>;  ///< vCPU delegate type

/// Intel vCPU
///
/// This class provides the base implementation for an Intel based vCPU. For
/// more information on how a vCPU works, please @see bfvmm::vcpu
///
class vcpu : public bfvmm::vcpu
{

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the vcpu
    /// @param global_state a pointer to the vCPUs state
    ///
    explicit vcpu(
        vcpuid::type id,
        vcpu_global_state_t *global_state = nullptr);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~vcpu() override = default;

public:

    /// Run
    ///
    /// Executes the vCPU. This is executed before a launch/resume. This means
    /// that this is executed in the context of the kernel if this is a host
    /// vCPU and in the context of the parent vCPU if this is a guest vCPU.
    ///
    /// In addition, this is also executed as a means to resume back into the
    /// guest after an exit, so this can also be run from the vCPU's own point
    /// of view if an exit has occurred and you are simply resuming.
    ///
    /// @expects none
    /// @ensures none
    ///
    VIRTUAL void run();

    /// Add Launch Delegate
    ///
    /// Adds a launch delegate to the VCPU. The delegates are added to a queue and
    /// executed in FILO order. All delegates are executed unless an exception
    /// is thrown that is not handled.
    ///
    /// Note that this is executed during a vcpu->run() if the vCPU is being
    /// launched and not resumed.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d the delegate to add to the vcpu
    ///
    VIRTUAL void add_launch_delegate(const vcpu_delegate_t &d) noexcept
    { m_launch_delegates.push_front(std::move(d)); }

    /// Add Resume Delegate
    ///
    /// Adds a resume delegate to the VCPU. The delegates are added to a queue and
    /// executed in FILO order. All delegates are executed unless an exception
    /// is thrown that is not handled.
    ///
    /// Note that this is executed during a vcpu->run() if the vCPU is being
    /// resumed and not launched.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d the delegate to add to the vcpu
    ///
    VIRTUAL void add_resume_delegate(const vcpu_delegate_t &d) noexcept
    { m_resume_delegates.push_front(std::move(d)); }

    /// Add Clear Delegate
    ///
    /// Adds a clear delegate to the VCPU. The delegates are added to a queue and
    /// executed in FILO order. All delegates are executed unless an exception
    /// is thrown that is not handled.
    ///
    /// Note that this is executed during a vcpu->clear().
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d the delegate to add to the vcpu
    ///
    VIRTUAL void add_clear_delegate(const vcpu_delegate_t &d) noexcept
    { m_resume_delegates.push_front(std::move(d)); }

private:

    void write_host_state();
    void write_guest_state();
    void write_control_state();

public:

    //==========================================================================
    // VMCS Operations
    //==========================================================================

    /// Load vCPU
    ///
    /// Loads the vCPU into hardware.
    ///
    /// @expects none
    /// @ensures none
    ///
    VIRTUAL void load();

    /// Clear vCPU
    ///
    /// Clears the vCPU in hardware.
    ///
    /// @expects none
    /// @ensures none
    ///
    VIRTUAL void clear();

    /// Promote vCPU
    ///
    /// Promotes the vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    VIRTUAL void promote();

    /// Advance vCPU
    ///
    /// Advances the vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return always returns true
    ///
    VIRTUAL bool advance();

    //==========================================================================
    // Handler Operations
    //==========================================================================

    /// Add Exit Handler
    ///
    /// Adds an exit function to the exit list. Exit functions are executed
    /// right after a vCPU exits for any reason. Use this with care because
    /// this function will be executed a lot.
    ///
    /// Note the return value of the delegate is ignored
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d The delegate being registered
    ///
    VIRTUAL void add_exit_handler(const handler_delegate_t &d);

    /// Add Exit Handler (for specific reason)
    ///
    /// Adds an exit handler to the vCPU for a specific reason
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param reason The exit reason for the handler being registered
    /// @param d The delegate being registered
    ///
    VIRTUAL void add_exit_handler_for_reason(
        ::intel_x64::vmcs::value_type reason, const handler_delegate_t &d);

    //==========================================================================
    // Fault Handling
    //==========================================================================

    /// Dump State
    ///
    /// Outputs the state of the vCPU with a custom header
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param str a custom header to add to the dump output
    ///
    VIRTUAL void dump(const char *str);

    /// Halt the vCPU
    ///
    /// Halts the vCPU. The default action is to freeze the physical core
    /// resulting in a hang, but this function can be overrided to provide
    /// a safer action if possible.
    ///
    /// @param str the reason for the halt
    ///
    virtual void halt(const std::string &str = {});

    //==========================================================================
    // VMExit
    //==========================================================================

    //--------------------------------------------------------------------------
    // Control Register
    //--------------------------------------------------------------------------

    /// Add Write CR0 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the CR0 enable/disable mask
    /// @param d the delegate to call when a mov-to-cr0 exit occurs
    ///
    VIRTUAL void add_wrcr0_handler(
        vmcs_n::value_type mask, const handler_delegate_t &d);

    /// Add Read CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-from-cr3 exit occurs
    ///
    VIRTUAL void add_rdcr3_handler(
        const handler_delegate_t &d);

    /// Add Write CR3 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a mov-to-cr3 exit occurs
    ///
    VIRTUAL void add_wrcr3_handler(
        const handler_delegate_t &d);

    /// Add Write CR4 Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the CR0 enable/disable mask
    /// @param d the delegate to call when a mov-to-cr4 exit occurs
    ///
    VIRTUAL void add_wrcr4_handler(
        vmcs_n::value_type mask, const handler_delegate_t &d);

    /// Execute wrcr0
    ///
    /// Executes the wrcr0 instruction, and populates the vCPU's registers.
    /// For more information, please see the control register VM exit handler's
    /// documentation.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void execute_wrcr0();

    /// Execute rdcr3
    ///
    /// Executes the rdcr3 instruction, and populates the vCPU's registers.
    /// For more information, please see the control register VM exit handler's
    /// documentation.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void execute_rdcr3();

    /// Execute wrcr3
    ///
    /// Executes the wrcr3 instruction, and populates the vCPU's registers.
    /// For more information, please see the control register VM exit handler's
    /// documentation.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void execute_wrcr3();

    /// Execute wrcr3
    ///
    /// Executes the wrcr3 instruction, and populates the vCPU's registers.
    /// For more information, please see the control register VM exit handler's
    /// documentation.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void execute_wrcr4();

    //--------------------------------------------------------------------------
    // CPUID
    //--------------------------------------------------------------------------

    /// Add CPUID Handler
    ///
    /// Add a delegate to handle a CPUID VM exit. Your handler should always
    /// return false unless you need to override the default behavior of the
    /// base hypervisor. For more information, please see the CPUID VM exit
    /// handler for details.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call on the vm exit
    ///
    VIRTUAL void add_cpuid_handler(
        cpuid_handler::leaf_t leaf, const ::handler_delegate_t &d);

    /// Add Emulate
    ///
    /// Emulate the exeuction of the CPUID instruction. For more information
    /// please see the CPUID VM exit handler for details. Generally speaking,
    /// you should typically use add_handler() instead.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the leaf to call d on
    /// @param d the delegate to call on the vm exit
    ///
    VIRTUAL void add_cpuid_emulator(
        cpuid_handler::leaf_t leaf, const ::handler_delegate_t &d);

    /// Execute CPUID
    ///
    /// Executes the CPUID instruction, and populates the vCPU's registers.
    /// For more information, please see the CPUID VM exit handler's
    /// documentation.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void execute_cpuid();

    /// Enable Whitelisting
    ///
    /// Ensures that if a VM exit occurs, that an emulator must be registered
    /// for the exit. If an emulator is not registered, the VM exit is
    /// reported as unhandled.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_cpuid_whitelisting() noexcept;

    //--------------------------------------------------------------------------
    // EPT Violation
    //--------------------------------------------------------------------------

    /// Add EPT read violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_read_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    /// Add EPT write violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_write_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    /// Add EPT execute violation handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_ept_execute_violation_handler(
        const ept_violation_handler::handler_delegate_t &d);

    /// Add EPT Read Violation Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_default_ept_read_violation_handler(
        const ::handler_delegate_t &d);

    /// Add EPT Write Violation Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_default_ept_write_violation_handler(
        const ::handler_delegate_t &d);

    /// Add EPT Execute Violation Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_default_ept_execute_violation_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // External Interrupt
    //--------------------------------------------------------------------------

    /// Add External Interrupt Handler
    ///
    /// Turns on external interrupt handling and adds an external interrupt
    /// handler to handle external interrupts
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_external_interrupt_handler(
        const external_interrupt_handler::handler_delegate_t &d);

    /// Disable External Interrupt Support
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_external_interrupts();

    //--------------------------------------------------------------------------
    // Interrupt Window
    //--------------------------------------------------------------------------

    /// Queue External Interrupt
    ///
    /// Queues an external interrupt for injection.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to queue for injection
    ///
    VIRTUAL void queue_external_interrupt(uint64_t vector);

    /// Inject Exception
    ///
    /// Inject an exception on the next VM entry. Note that this will overwrite
    /// any interrupts that are already injected for the next VM entry so
    /// care should be taken when using this function
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the guest
    /// @param ec the error code associated with the exception if applicable
    ///
    VIRTUAL void inject_exception(uint64_t vector, uint64_t ec = 0);

    /// Inject External Interrupt
    ///
    /// Inject an external interrupt on the next VM entry. Note that this will
    /// overwrite any interrupts that are already injected for the next VM entry
    /// so care should be taken when using this function
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector to inject into the guest
    ///
    VIRTUAL void inject_external_interrupt(uint64_t vector);

    //--------------------------------------------------------------------------
    // IO Instruction
    //--------------------------------------------------------------------------

    /// Trap All IO Instruction Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_io_instruction_accesses();

    /// Pass Through All IO Instruction Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_io_instruction_accesses();

    /// Pass Through Accesses
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to pass through
    ///
    VIRTUAL void pass_through_io_accesses(vmcs_n::value_type port);

    /// Add IO Instruction Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to call
    /// @param in_d the delegate to call when the reads in from the given port
    /// @param out_d the delegate to call when the guest writes out to the
    ///        given port.
    ///
    VIRTUAL void add_io_instruction_handler(
        vmcs_n::value_type port,
        const io_instruction_handler::handler_delegate_t &in_d,
        const io_instruction_handler::handler_delegate_t &out_d);

    /// Emulate IO Instruction Handler
    ///
    /// Adds a handler, and tells the APIs that full emulation is desired.
    /// This will prevent the real hardware from being touched.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param port the port to call
    /// @param in_d the delegate to call when the reads in from the given port
    /// @param out_d the delegate to call when the guest writes out to the
    ///        given port.
    ///
    VIRTUAL void emulate_io_instruction(
        vmcs_n::value_type port,
        const io_instruction_handler::handler_delegate_t &in_d,
        const io_instruction_handler::handler_delegate_t &out_d);

    /// Add IO Instruction Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes an IO instruction
    ///
    VIRTUAL void add_default_io_instruction_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Monitor Trap
    //--------------------------------------------------------------------------

    /// Add Monitor Trap Flag Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a monitor-trap flag exit occurs
    ///
    VIRTUAL void add_monitor_trap_handler(
        const ::handler_delegate_t &d);

    /// Enable Monitor Trap Flag
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_monitor_trap_flag();

    //--------------------------------------------------------------------------
    // Non-Maskable Interrupt Window
    //--------------------------------------------------------------------------

    /// Queue NMI
    ///
    /// Queues an NMI for injection.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void queue_nmi();

    /// Inject NMI
    ///
    /// Inject an NMI on the next VM entry. Note that this will
    /// overwrite any interrupts that are already injected for the next VM entry
    /// so care should be taken when using this function
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void inject_nmi();

    //--------------------------------------------------------------------------
    // Non-Maskable Interrupts
    //--------------------------------------------------------------------------

    /// Add NMI Handler
    ///
    /// Turns on NMI handling and adds an NMI
    /// handler to handle NMIs
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when an exit occurs
    ///
    VIRTUAL void add_nmi_handler(
        const nmi_handler::handler_delegate_t &d);

    /// Enable NMI Support
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_nmis();

    /// Disable NMI Support
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_nmis();

    //--------------------------------------------------------------------------
    // Read MSR
    //--------------------------------------------------------------------------

    /// Trap On Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    VIRTUAL void trap_on_rdmsr_access(vmcs_n::value_type msr);

    /// Trap All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_rdmsr_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_rdmsr_access(vmcs_n::value_type msr);

    /// Pass Through All Read MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_rdmsr_accesses();

    /// Add Read MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a rdmsr_handler exit occurs
    ///
    VIRTUAL void add_rdmsr_handler(
        vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d);

    /// Emulate Read MSR
    ///
    /// Adds a handler, and tells the APIs that full emulation is desired.
    /// This will prevent the real hardware from being touched.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a rdmsr_handler exit occurs
    ///
    VIRTUAL void emulate_rdmsr(
        vmcs_n::value_type msr, const rdmsr_handler::handler_delegate_t &d);

    /// Add Read MSR Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes rdmsr
    ///
    VIRTUAL void add_default_rdmsr_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Write MSR
    //--------------------------------------------------------------------------

    /// Trap On Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will
    /// trap to hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap on
    ///
    VIRTUAL void trap_on_wrmsr_access(vmcs_n::value_type msr);

    /// Trap All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void trap_on_all_wrmsr_accesses();

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_wrmsr_access(vmcs_n::value_type msr);

    /// Pass Through All Write MSR Accesses
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void pass_through_all_wrmsr_accesses();

    /// Add Write MSR Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a wrmsr_handler exit occurs
    ///
    VIRTUAL void add_wrmsr_handler(
        vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d);

    /// Emulate Write MSR
    ///
    /// Adds a handler, and tells the APIs that full emulation is desired.
    /// This will prevent the real hardware from being touched.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the address at which to call the given handler
    /// @param d the delegate to call when a wrmsr_handler exit occurs
    ///
    VIRTUAL void emulate_wrmsr(
        vmcs_n::value_type msr, const wrmsr_handler::handler_delegate_t &d);

    /// Add Write MSR Default Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when the guest executes wrmsr
    ///
    VIRTUAL void add_default_wrmsr_handler(
        const ::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // XSetBV
    //--------------------------------------------------------------------------

    /// Add XSetBV Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a xsetbv exit occurs
    ///
    VIRTUAL void add_xsetbv_handler(
        const xsetbv_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // VMX preemption timer
    //--------------------------------------------------------------------------

    /// Add VMX preemption timer handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a VMX PET exit occurs
    ///
    VIRTUAL void add_preemption_timer_handler(
        const preemption_timer_handler::handler_delegate_t &d);

    /// Set VMX preemption timer
    ///
    /// @expects
    /// @ensures
    ///
    /// @param val the value to write to the preemption timer
    ///
    VIRTUAL void set_preemption_timer(
        const preemption_timer_handler::value_t val);

    /// Get VMX preemption timer
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the value of the VMX-preemption timer field
    ///
    VIRTUAL preemption_timer_handler::value_t get_preemption_timer();

    /// Enable VMX preemption timer exiting
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_preemption_timer();

    /// Disable VMX preemption timer exiting
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_preemption_timer();

    //==========================================================================
    // EPT
    //==========================================================================

    /// Set EPTP
    ///
    /// Enables EPT and sets the EPTP to point to the provided mmap.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param map The map to set EPTP to.
    ///
    VIRTUAL void set_eptp(ept::mmap &map);

    /// Disable EPT
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_ept();

    //==========================================================================
    // VPID
    //==========================================================================

    /// Enable VPID
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void enable_vpid();

    /// Disable VPID
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void disable_vpid();

    //==========================================================================
    // Helpers
    //==========================================================================

    /// Trap MSR Access
    ///
    /// Sets a '1' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read/write from the provided msr will be
    /// trapped by the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to trap
    ///
    VIRTUAL void trap_on_msr_access(vmcs_n::value_type msr);

    /// Pass Through Access
    ///
    /// Sets a '0' in the MSR bitmap corresponding with the provided msr. All
    /// attempts made by the guest to read/write from the provided msr will be
    /// executed by the guest and will not trap to the hypervisor.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param msr the msr to pass through
    ///
    VIRTUAL void pass_through_msr_access(vmcs_n::value_type msr);

    //==========================================================================
    // Resources
    //==========================================================================

    /// Global State
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the global state object associated with this vCPU.
    ///
    VIRTUAL gsl::not_null<vcpu_global_state_t *> global_state()
    { return m_global_state; }

    /// State
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the state object associated with this vCPU.
    ///
    VIRTUAL gsl::not_null<vcpu_state_t *> state()
    { return m_state.get(); }

    /// MSR bitmap
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vCPU's msr bitmap
    ///
    VIRTUAL gsl::not_null<uint8_t *> msr_bitmap() const
    { return m_msr_bitmap.get(); }

    /// IO bitmap a
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vCPU's io bitmap a
    ///
    VIRTUAL gsl::not_null<uint8_t *> io_bitmap_a() const
    { return m_io_bitmap_a.get(); }

    /// IO bitmap b
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the vCPU's io bitmap b
    ///
    VIRTUAL gsl::not_null<uint8_t *> io_bitmap_b() const
    { return m_io_bitmap_b.get(); }

    //==========================================================================
    // Memory Mapping
    //==========================================================================

    /// Convert GPA to HPA
    ///
    /// Converts a guest physical address to a host physical address
    /// using EPT. If EPT is not enabled, this function will return
    /// the GPA (as the HPA == the GPA), and "from" will be set to 0 as
    /// this information is not available.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return the resulting host physical address
    ///
    VIRTUAL std::pair<uintptr_t, uintptr_t> gpa_to_hpa(uint64_t gpa);

    /// Convert GPA to HPA
    ///
    /// Converts a guest physical address to a host physical address
    /// using EPT. If EPT is not enabled, this function will return
    /// the GPA (as the HPA == the GPA), and "from" will be set to 0 as
    /// this information is not available.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return the resulting host physical address
    ///
    VIRTUAL std::pair<uintptr_t, uintptr_t> gpa_to_hpa(void *gpa)
    { return gpa_to_hpa(reinterpret_cast<uintptr_t>(gpa)); }

    /// Convert GVA to GPA
    ///
    /// Converts a guest virtual address to a guest physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting guest physical address
    ///
    VIRTUAL std::pair<uintptr_t, uintptr_t> gva_to_gpa(uint64_t gva);

    /// Convert GVA to GPA
    ///
    /// Converts a guest virtual address to a guest physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting guest physical address
    ///
    VIRTUAL std::pair<uintptr_t, uintptr_t> gva_to_gpa(void *gva)
    { return gva_to_gpa(reinterpret_cast<uintptr_t>(gva)); }

    /// Convert GVA to HPA
    ///
    /// Converts a guest virtual address to a host physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting host physical address
    ///
    VIRTUAL std::pair<uintptr_t, uintptr_t> gva_to_hpa(uint64_t gva);

    /// Convert GVA to HPA
    ///
    /// Converts a guest virtual address to a host physical address
    /// using EPT.
    ///
    /// Note:
    ///
    /// The vCPU must be loaded before this operation can take place
    /// as this function will use VMCS functions.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting host physical address
    ///
    VIRTUAL std::pair<uintptr_t, uintptr_t> gva_to_hpa(void *gva)
    { return gva_to_hpa(reinterpret_cast<uintptr_t>(gva)); }

    /// Map 1g GPA to HPA (Read-Only)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_1g_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read-Only)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_2m_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read-Only)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_4k_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_1g_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_2m_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_4k_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_1g_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_2m_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    VIRTUAL void map_4k_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map HPA (1g)
    ///
    /// Map a 1g host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 1g page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_1g(uintptr_t hpa)
    {
        using namespace ::x64::pdpt;

        expects(bfn::lower(hpa, from) == 0);
        expects(bfn::upper(hpa, from) != 0);

        auto hva = g_mm->alloc_map(page_size);
        g_cr3->map_1g(hva, hpa);

        return x64::unique_map<T>(
                   static_cast<T *>(hva),
                   x64::unmapper(hva, page_size)
               );
    }

    /// Map HPA (1g)
    ///
    /// Map a 1g host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 1g page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_1g(void *hpa)
    { return map_hpa_1g<T>(reinterpret_cast<uintptr_t>(hpa)); }

    /// Map HPA (2m)
    ///
    /// Map a 2m host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 2m page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_2m(uintptr_t hpa)
    {
        using namespace ::x64::pd;

        expects(bfn::lower(hpa, from) == 0);
        expects(bfn::upper(hpa, from) != 0);

        auto hva = g_mm->alloc_map(page_size);
        g_cr3->map_2m(hva, hpa);

        return x64::unique_map<T>(
                   static_cast<T *>(hva),
                   x64::unmapper(hva, page_size)
               );
    }

    /// Map HPA (2m)
    ///
    /// Map a 2m host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 2m page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_2m(void *hpa)
    { return map_hpa_2m<T>(reinterpret_cast<uintptr_t>(hpa)); }

    /// Map HPA (4k)
    ///
    /// Map a 4k host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 4k page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_4k(uintptr_t hpa)
    {
        using namespace ::x64::pt;

        expects(bfn::lower(hpa, from) == 0);
        expects(bfn::upper(hpa, from) != 0);

        auto hva = g_mm->alloc_map(page_size);
        g_cr3->map_4k(hva, hpa);

        return x64::unique_map<T>(
                   static_cast<T *>(hva),
                   x64::unmapper(hva, page_size)
               );
    }

    /// Map HPA (4k)
    ///
    /// Map a 4k host physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the HPA using the provided HVA.
    ///
    /// @expects hpa is 4k page aligned
    /// @expects hpa != 0
    /// @ensures
    ///
    /// @param hpa the guest physical address
    /// @return a unique_map that can be used to access the hpa
    ///
    template<typename T>
    auto map_hpa_4k(void *hpa)
    { return map_hpa_4k<T>(reinterpret_cast<uintptr_t>(hpa)); }

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(uintptr_t gpa)
    {
        using namespace ::x64::pdpt;

        expects(bfn::lower(gpa, from) == 0);
        expects(bfn::upper(gpa, from) != 0);

        return map_hpa_1g<T>(this->gpa_to_hpa(gpa).first);
    }

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(void *gpa)
    { return map_gpa_1g<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(uintptr_t gpa)
    {
        using namespace ::x64::pd;

        expects(bfn::lower(gpa, from) == 0);
        expects(bfn::upper(gpa, from) != 0);

        return map_hpa_2m<T>(this->gpa_to_hpa(gpa).first);
    }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(void *gpa)
    { return map_gpa_2m<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(uintptr_t gpa)
    {
        using namespace ::x64::pt;

        expects(bfn::lower(gpa, from) == 0);
        expects(bfn::upper(gpa, from) != 0);

        return map_hpa_4k<T>(this->gpa_to_hpa(gpa).first);
    }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(void *gpa)
    { return map_gpa_4k<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GPA.
    ///
    /// @expects gpa != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(uintptr_t gpa, std::size_t len)
    {
        using namespace ::x64::pt;

        expects(gpa != 0);
        expects(len != 0);

        auto gpa_offset = bfn::lower(gpa);
        gpa = bfn::upper(gpa);

        len *= sizeof(T);
        len += gpa_offset;
        if (bfn::lower(len) != 0) {
            len += page_size - bfn::lower(len);
        }

        auto hva = g_mm->alloc_map(len);

        for (std::size_t bytes = 0; bytes < len; bytes += page_size) {
            auto gpa_addr = gpa + bytes;
            auto hva_addr = reinterpret_cast<uintptr_t>(hva) + bytes;

            g_cr3->map_4k(hva_addr, this->gpa_to_hpa(gpa_addr).first);
        }

        return x64::unique_map<T>(
                   reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(hva) + gpa_offset),
                   x64::unmapper(hva, len)
               );
    }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GPA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GPA.
    ///
    /// @expects gpa != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(void *gpa, std::size_t len)
    { return map_gpa_4k<T>(reinterpret_cast<uintptr_t>(gpa), len); }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(uintptr_t gva, std::size_t len)
    {
        using namespace ::x64::pt;

        if (vmcs_n::guest_cr0::paging::is_disabled()) {
            return map_gpa_4k<T>(gva, len);
        }

        expects(gva != 0);
        expects(len != 0);

        auto gva_offset = bfn::lower(gva);
        gva = bfn::upper(gva);

        len *= sizeof(T);
        len += gva_offset;
        if (bfn::lower(len) != 0) {
            len += page_size - bfn::lower(len);
        }

        auto hva = g_mm->alloc_map(len);

        for (auto bytes = 0ULL; bytes < len; bytes += page_size) {
            auto gva_addr = gva + bytes;
            auto hva_addr = reinterpret_cast<uintptr_t>(hva) + bytes;

            g_cr3->map_4k(hva_addr, this->gva_to_hpa(gva_addr).first);
        }

        return x64::unique_map<T>(
                   reinterpret_cast<T *>(reinterpret_cast<uintptr_t>(hva) + gva_offset),
                   x64::unmapper(hva, len)
               );
    }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @param len the number elements to map. This is not in bytes.
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(void *gva, std::size_t len)
    { return map_gva_4k<T>(reinterpret_cast<uintptr_t>(gva), len); }

    /// Map Argument (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_arg(uintptr_t gva)
    { return map_gva_4k<T>(gva, 1); }

    /// Map Argument (4k)
    ///
    /// Map a 4k guest virtual address into the VMM. The result of this
    /// function is a unique_map that will unmap when scope is lost, and
    /// provides the ability to access the GVA using the provided HVA.
    ///
    /// Note:
    ///
    /// This version of the map function will map a contiguous len number
    /// of bytes. The provided address does not have to be aligned, and the
    /// resulting HVA will have the same page offset as the provided GVA.
    ///
    /// @expects gva != 0
    /// @expects len != 0
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_arg(void *gva)
    { return map_gva_4k<T>(gva, 1); }

private:

    uintptr_t get_entry(uintptr_t tble_gpa, std::ptrdiff_t index);

public:

    /// @cond

    /// vCPU Registers
    ///
    /// These functions read/write the register values of the vCPU. Some of
    /// these functions will touch the save state while others will read/write
    /// to the VMCS which means that the vCPU must be loaded prior to touching
    /// those registers. Care should be taken to ensure that loading the vCPU
    /// is kept at a minimum while at the same time ensuring that the right
    /// VMCS is being modified.
    ///

    VIRTUAL uint64_t rax() const noexcept;
    VIRTUAL void set_rax(uint64_t val) noexcept;
    VIRTUAL uint64_t rbx() const noexcept;
    VIRTUAL void set_rbx(uint64_t val) noexcept;
    VIRTUAL uint64_t rcx() const noexcept;
    VIRTUAL void set_rcx(uint64_t val) noexcept;
    VIRTUAL uint64_t rdx() const noexcept;
    VIRTUAL void set_rdx(uint64_t val) noexcept;
    VIRTUAL uint64_t rbp() const noexcept;
    VIRTUAL void set_rbp(uint64_t val) noexcept;
    VIRTUAL uint64_t rsi() const noexcept;
    VIRTUAL void set_rsi(uint64_t val) noexcept;
    VIRTUAL uint64_t rdi() const noexcept;
    VIRTUAL void set_rdi(uint64_t val) noexcept;
    VIRTUAL uint64_t r08() const noexcept;
    VIRTUAL void set_r08(uint64_t val) noexcept;
    VIRTUAL uint64_t r09() const noexcept;
    VIRTUAL void set_r09(uint64_t val) noexcept;
    VIRTUAL uint64_t r10() const noexcept;
    VIRTUAL void set_r10(uint64_t val) noexcept;
    VIRTUAL uint64_t r11() const noexcept;
    VIRTUAL void set_r11(uint64_t val) noexcept;
    VIRTUAL uint64_t r12() const noexcept;
    VIRTUAL void set_r12(uint64_t val) noexcept;
    VIRTUAL uint64_t r13() const noexcept;
    VIRTUAL void set_r13(uint64_t val) noexcept;
    VIRTUAL uint64_t r14() const noexcept;
    VIRTUAL void set_r14(uint64_t val) noexcept;
    VIRTUAL uint64_t r15() const noexcept;
    VIRTUAL void set_r15(uint64_t val) noexcept;
    VIRTUAL uint64_t rip() const noexcept;
    VIRTUAL void set_rip(uint64_t val) noexcept;
    VIRTUAL uint64_t rsp() const noexcept;
    VIRTUAL void set_rsp(uint64_t val) noexcept;
    VIRTUAL uint64_t gdt_base() const noexcept;
    VIRTUAL void set_gdt_base(uint64_t val) noexcept;
    VIRTUAL uint64_t gdt_limit() const noexcept;
    VIRTUAL void set_gdt_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t idt_base() const noexcept;
    VIRTUAL void set_idt_base(uint64_t val) noexcept;
    VIRTUAL uint64_t idt_limit() const noexcept;
    VIRTUAL void set_idt_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t cr0() const noexcept;
    VIRTUAL void set_cr0(uint64_t val) noexcept;
    VIRTUAL uint64_t cr3() const noexcept;
    VIRTUAL void set_cr3(uint64_t val) noexcept;
    VIRTUAL uint64_t cr4() const noexcept;
    VIRTUAL void set_cr4(uint64_t val) noexcept;
    VIRTUAL uint64_t ia32_efer() const noexcept;
    VIRTUAL void set_ia32_efer(uint64_t val) noexcept;
    VIRTUAL uint64_t ia32_pat() const noexcept;
    VIRTUAL void set_ia32_pat(uint64_t val) noexcept;

    VIRTUAL uint64_t es_selector() const noexcept;
    VIRTUAL void set_es_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t es_base() const noexcept;
    VIRTUAL void set_es_base(uint64_t val) noexcept;
    VIRTUAL uint64_t es_limit() const noexcept;
    VIRTUAL void set_es_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t es_access_rights() const noexcept;
    VIRTUAL void set_es_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_selector() const noexcept;
    VIRTUAL void set_cs_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_base() const noexcept;
    VIRTUAL void set_cs_base(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_limit() const noexcept;
    VIRTUAL void set_cs_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t cs_access_rights() const noexcept;
    VIRTUAL void set_cs_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_selector() const noexcept;
    VIRTUAL void set_ss_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_base() const noexcept;
    VIRTUAL void set_ss_base(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_limit() const noexcept;
    VIRTUAL void set_ss_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t ss_access_rights() const noexcept;
    VIRTUAL void set_ss_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_selector() const noexcept;
    VIRTUAL void set_ds_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_base() const noexcept;
    VIRTUAL void set_ds_base(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_limit() const noexcept;
    VIRTUAL void set_ds_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t ds_access_rights() const noexcept;
    VIRTUAL void set_ds_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_selector() const noexcept;
    VIRTUAL void set_fs_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_base() const noexcept;
    VIRTUAL void set_fs_base(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_limit() const noexcept;
    VIRTUAL void set_fs_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t fs_access_rights() const noexcept;
    VIRTUAL void set_fs_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_selector() const noexcept;
    VIRTUAL void set_gs_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_base() const noexcept;
    VIRTUAL void set_gs_base(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_limit() const noexcept;
    VIRTUAL void set_gs_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t gs_access_rights() const noexcept;
    VIRTUAL void set_gs_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_selector() const noexcept;
    VIRTUAL void set_tr_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_base() const noexcept;
    VIRTUAL void set_tr_base(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_limit() const noexcept;
    VIRTUAL void set_tr_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t tr_access_rights() const noexcept;
    VIRTUAL void set_tr_access_rights(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_selector() const noexcept;
    VIRTUAL void set_ldtr_selector(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_base() const noexcept;
    VIRTUAL void set_ldtr_base(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_limit() const noexcept;
    VIRTUAL void set_ldtr_limit(uint64_t val) noexcept;
    VIRTUAL uint64_t ldtr_access_rights() const noexcept;
    VIRTUAL void set_ldtr_access_rights(uint64_t val) noexcept;

    /// @endcond

public:

    /// General Register
    ///
    /// The GRs are registers used as input into the VM exit
    /// handlers. The meaning of each general register depends
    /// on the VM exit handler you are registering. See the execute
    /// functions for more details.
    ///

    /// @cond

    VIRTUAL uint64_t gr1() const noexcept;
    VIRTUAL void set_gr1(uint64_t val) noexcept;
    VIRTUAL uint64_t gr2() const noexcept;
    VIRTUAL void set_gr2(uint64_t val) noexcept;
    VIRTUAL uint64_t gr3() const noexcept;
    VIRTUAL void set_gr3(uint64_t val) noexcept;
    VIRTUAL uint64_t gr4() const noexcept;
    VIRTUAL void set_gr4(uint64_t val) noexcept;

    /// @endcond

private:

    uint64_t m_gr1{};
    uint64_t m_gr2{};
    uint64_t m_gr3{};
    uint64_t m_gr4{};

private:

    vcpu_global_state_t *m_global_state{};
    std::unique_ptr<vcpu_state_t> m_state;

    page_ptr<uint8_t> m_msr_bitmap;
    page_ptr<uint8_t> m_io_bitmap_a;
    page_ptr<uint8_t> m_io_bitmap_b;

    std::unique_ptr<gsl::byte[]> m_ist1;
    std::unique_ptr<gsl::byte[]> m_stack;

    x64::tss m_host_tss{};
    x64::gdt m_host_gdt{512};
    x64::idt m_host_idt{256};

private:

    std::unique_ptr<vmx> m_vmx;

    vmcs m_vmcs;
    exit_handler m_exit_handler;

    control_register_handler m_control_register_handler;
    cpuid_handler m_cpuid_handler;
    ept_violation_handler m_ept_violation_handler;
    external_interrupt_handler m_external_interrupt_handler;
    init_signal_handler m_init_signal_handler;
    interrupt_window_handler m_interrupt_window_handler;
    io_instruction_handler m_io_instruction_handler;
    monitor_trap_handler m_monitor_trap_handler;
    nmi_window_handler m_nmi_window_handler;
    nmi_handler m_nmi_handler;
    preemption_timer_handler m_preemption_timer_handler;
    rdmsr_handler m_rdmsr_handler;
    sipi_signal_handler m_sipi_signal_handler;
    wrmsr_handler m_wrmsr_handler;
    xsetbv_handler m_xsetbv_handler;

    ept_handler m_ept_handler;
    microcode_handler m_microcode_handler;
    vpid_handler m_vpid_handler;

private:

    bool m_launched{false};

    std::list<vcpu_delegate_t> m_launch_delegates{};
    std::list<vcpu_delegate_t> m_resume_delegates{};
    std::list<vcpu_delegate_t> m_clear_delegates{};

    ept::mmap *m_mmap{};
};
}

/// Base vcpu type
///
using vcpu_t = bfvmm::intel_x64::vcpu;

#endif

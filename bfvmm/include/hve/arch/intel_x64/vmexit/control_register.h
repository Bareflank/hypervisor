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

#ifndef VMEXIT_CONTROL_REGISTER_INTEL_X64_H
#define VMEXIT_CONTROL_REGISTER_INTEL_X64_H

#include <list>

#include <bfgsl.h>
#include <bfdelegate.h>

#include "../exit_handler.h"
#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// Control Register
///
/// Provides an interface for enabling/disabling exiting on control register
/// access. Users may supply handlers and specify shadow values (for CR0 and
/// CR4).
///
class control_register_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this control register handler
    ///
    control_register_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~control_register_handler() = default;

public:

    /// Add wrcr0 Handler
    ///
    /// Adds a VM exit handler. When a VM exit occurs, the registered
    /// handler will be called. More than one handler can be registered. If
    /// a handler returns true, the handler is stating that it is the last
    /// handler to be called, and no other handlers will be executed. If a
    /// handler returns false, the next registered handler will be called
    /// until all of the handlers are called, or another handler in the chain
    /// returns true. If a handler returns true, it must also execute
    /// vcpu->advance() when applicable to ensure the instruction pointer is
    /// advanced. If all of the handlers return false, the base implementation
    /// will return true for you and advance the instruction pointer.
    /// In general, handlers should always return false unless you
    /// explicitly wish to prevent any other handlers from executing (e.g. if
    /// you wish to override the default behavior). Do not call
    /// vcpu->advance() unless you return true, otherwise you will advance and
    /// instruction pointer twice.
    ///
    /// Prior to the handlers being called, the execute() function is called
    /// which places the hardware state into the vCPU registers. Please see
    /// this function for how the registers are set.
    ///
    /// To handle the VM exit, modify the cr0 register using the following two
    /// functions as needed:
    /// - vcpu->cr0()
    /// - vcpu->set_cr0()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr0_handler(const handler_delegate_t &d);

    /// Add rdcr3 Handler
    ///
    /// Adds a VM exit handler. When a VM exit occurs, the registered
    /// handler will be called. More than one handler can be registered. If
    /// a handler returns true, the handler is stating that it is the last
    /// handler to be called, and no other handlers will be executed. If a
    /// handler returns false, the next registered handler will be called
    /// until all of the handlers are called, or another handler in the chain
    /// returns true. If a handler returns true, it must also execute
    /// vcpu->advance() when applicable to ensure the instruction pointer is
    /// advanced. If all of the handlers return false, the base implementation
    /// will return true for you and advance the instruction pointer.
    /// In general, handlers should always return false unless you
    /// explicitly wish to prevent any other handlers from executing (e.g. if
    /// you wish to override the default behavior). Do not call
    /// vcpu->advance() unless you return true, otherwise you will advance and
    /// instruction pointer twice.
    ///
    /// Prior to the handlers being called, gr2 is populated with the old value
    /// of cr3 (the value that was in the VMCS just prior to the VM exit).
    /// Once all of the handlers have completed, the result of the vcpu->cr3()
    /// will be written to the proper output register defined by the Intel
    /// specification for you, including handlers that return true and advance
    /// the instruction pointer manually. If this functionality is not desired,
    /// register a custom control register handler with the base hypervisor
    /// and return true to indicate you are manually handling the exit.
    ///
    /// To handle the VM exit, modify the cr3 register using the following two
    /// functions as needed:
    /// - vcpu->cr3()
    /// - vcpu->set_cr3()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_rdcr3_handler(const handler_delegate_t &d);

    /// Add wrcr3 Handler
    ///
    /// Adds a VM exit handler. When a VM exit occurs, the registered
    /// handler will be called. More than one handler can be registered. If
    /// a handler returns true, the handler is stating that it is the last
    /// handler to be called, and no other handlers will be executed. If a
    /// handler returns false, the next registered handler will be called
    /// until all of the handlers are called, or another handler in the chain
    /// returns true. If a handler returns true, it must also execute
    /// vcpu->advance() when applicable to ensure the instruction pointer is
    /// advanced. If all of the handlers return false, the base implementation
    /// will return true for you and advance the instruction pointer.
    /// In general, handlers should always return false unless you
    /// explicitly wish to prevent any other handlers from executing (e.g. if
    /// you wish to override the default behavior). Do not call
    /// vcpu->advance() unless you return true, otherwise you will advance and
    /// instruction pointer twice.
    ///
    /// Prior to the handlers being called, the execute() function is called
    /// which places the hardware state into the vCPU registers. Please see
    /// this function for how the registers are set.
    ///
    /// To handle the VM exit, modify the cr3 register using the following two
    /// functions as needed:
    /// - vcpu->cr3()
    /// - vcpu->set_cr3()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr3_handler(const handler_delegate_t &d);

    /// Add wrcr4 Handler
    ///
    /// Adds a VM exit handler. When a VM exit occurs, the registered
    /// handler will be called. More than one handler can be registered. If
    /// a handler returns true, the handler is stating that it is the last
    /// handler to be called, and no other handlers will be executed. If a
    /// handler returns false, the next registered handler will be called
    /// until all of the handlers are called, or another handler in the chain
    /// returns true. If a handler returns true, it must also execute
    /// vcpu->advance() when applicable to ensure the instruction pointer is
    /// advanced. If all of the handlers return false, the base implementation
    /// will return true for you and advance the instruction pointer.
    /// In general, handlers should always return false unless you
    /// explicitly wish to prevent any other handlers from executing (e.g. if
    /// you wish to override the default behavior). Do not call
    /// vcpu->advance() unless you return true, otherwise you will advance and
    /// instruction pointer twice.
    ///
    /// Prior to the handlers being called, the execute() function is called
    /// which places the hardware state into the vCPU registers. Please see
    /// this function for how the registers are set.
    ///
    /// To handle the VM exit, modify the cr4 register using the following two
    /// functions as needed:
    /// - vcpu->cr4()
    /// - vcpu->set_cr4()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_wrcr4_handler(const handler_delegate_t &d);

public:

    /// Execute wrcr0
    ///
    /// Executes the mov to CR0 instruction and populates the vCPU's registers
    /// as follows:
    /// - vcpu->gr1() = new cr0
    /// - vcpu->gr2() = old cr0 (vcpu->cr0())
    /// - vcpu->cr0() = vcpu->gr1()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object to execute wrcr0 on
    ///
    void execute_wrcr0(gsl::not_null<vcpu *> vcpu);

    /// Execute rdcr3
    ///
    /// Executes the mov from CR3 instruction and populates the vCPU's registers
    /// as follows:
    /// - vcpu->gr1() = new cr3 (vcpu->cr3())
    /// - reg being read to = vcpu->gr1()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object to execute rdcr3 on
    ///
    void execute_rdcr3(gsl::not_null<vcpu *> vcpu);

    /// Execute wrcr3
    ///
    /// Executes the mov to CR3 instruction and populates the vCPU's registers
    /// as follows:
    /// - vcpu->gr1() = new cr3
    /// - vcpu->gr2() = old cr3 (vcpu->cr3())
    /// - vcpu->cr3() = vcpu->gr1()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object to execute wrcr3 on
    ///
    void execute_wrcr3(gsl::not_null<vcpu *> vcpu);

    /// Execute wrcr4
    ///
    /// Executes the mov to CR4 instruction and populates the vCPU's registers
    /// as follows:
    /// - vcpu->gr1() = new cr4
    /// - vcpu->gr2() = old cr4 (vcpu->cr4())
    /// - vcpu->cr4() = vcpu->gr1()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object to execute wrcr4 on
    ///
    void execute_wrcr4(gsl::not_null<vcpu *> vcpu);

public:

    /// Enable Write CR0 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr0_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the value of the cr0 guest/host mask to set in the vmcs
    ///
    void enable_wrcr0_exiting(vmcs_n::value_type mask);

    /// Enable Read CR3 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_rdcr3_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_rdcr3_exiting();

    /// Enable Write CR3 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr3_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void enable_wrcr3_exiting();

    /// Enable Write CR4 Exiting
    ///
    /// Example:
    /// @code
    /// this->enable_wrcr4_exiting();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    /// @param mask the value of the cr4 guest/host mask to set in the vmcs
    ///
    void enable_wrcr4_exiting(vmcs_n::value_type mask);

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    bool handle_cr0(vcpu *vcpu);
    bool handle_cr3(vcpu *vcpu);
    bool handle_cr4(vcpu *vcpu);

    bool handle_wrcr0(vcpu *vcpu);
    bool handle_rdcr3(vcpu *vcpu);
    bool handle_wrcr3(vcpu *vcpu);
    bool handle_wrcr4(vcpu *vcpu);

private:

    vcpu *m_vcpu;

    std::list<handler_delegate_t> m_wrcr0_handlers;
    std::list<handler_delegate_t> m_rdcr3_handlers;
    std::list<handler_delegate_t> m_wrcr3_handlers;
    std::list<handler_delegate_t> m_wrcr4_handlers;

public:

    /// @cond

    control_register_handler(control_register_handler &&) = default;
    control_register_handler &operator=(control_register_handler &&) = default;

    control_register_handler(const control_register_handler &) = delete;
    control_register_handler &operator=(const control_register_handler &) = delete;

    /// @endcond
};

}

#endif

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

#ifndef VMEXIT_CPUID_INTEL_X64_H
#define VMEXIT_CPUID_INTEL_X64_H

#include <unordered_map>

#include <bfgsl.h>
#include <bfdelegate.h>

#include "../exit_handler.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

class vcpu;

/// CPUID
///
/// Provides an interface for registering handlers for cpuid exits
/// at a given (leaf, subleaf).
///
class cpuid_handler
{
public:

    /// Leaf type
    ///
    ///
    using leaf_t = uint64_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this handler
    ///
    cpuid_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~cpuid_handler() = default;

public:

    /// Add Handler
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
    /// - vcpu->rax()
    /// - vcpu->set_rax()
    /// - vcpu->rbx()
    /// - vcpu->set_rbx()
    /// - vcpu->rcx()
    /// - vcpu->set_rcx()
    /// - vcpu->rdx()
    /// - vcpu->set_rdx()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the cpuid leaf to call d
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(leaf_t leaf, const handler_delegate_t &d);

    /// Add Emulator
    ///
    /// Emulate the VM exit instead of handling it. An emulator is different
    /// from a regular handler in two different ways:
    /// - The execute() function is not called before the emulators, which means
    ///   that the vCPU's registers do not have the hardware's values in them,
    ///   nor will the hardware's values be written to hardware for you. This
    ///   ensures that you do not accidentally write the hardware state to the
    ///   vCPU, leaking information that might be sensitive. If the hardware
    ///   state needs to be accessed, you can always call execute() yourself,
    ///   just be careful.
    /// - At least one emulator must return true. The base implementation will
    ///   not return true for an emulator. If at least one emulator doesn't
    ///   return true, an unhandled vm exit exception will occur. The emulator
    ///   that returns true must also call vcpu->advance() when applicable. As
    ///   as result, the last emulator to be called will typically return
    ///   by calling "return vcpu->advance();"
    ///
    /// In general, emulators are used to create fake versions of hardware.
    /// This is mostly useful for guest vCPUs, where hardware is being faked,
    /// or for hardware that is added to host vCPUs (like Bareflank specific
    /// regsiters). Unless you need to fake hardware, likely you should be
    /// using add_handler() and not add_emulator().
    ///
    /// Note: Once an emulator is added, regular handlers will no longer be
    /// called including the handlers provided by the base hypervisor. Adding
    /// an emulator handler tells the APIs that you are taking on the
    /// responsibility of properly handling the hardware, including ensuring
    /// that the hardware (or fake hardware) is consistent with what the base
    /// hypervisor provides, including any assumptions it is making. Use wisely.
    ///
    /// To handle the VM exit, modify the cr4 register using the following two
    /// functions as needed:
    /// - vcpu->rax()
    /// - vcpu->set_rax()
    /// - vcpu->rbx()
    /// - vcpu->set_rbx()
    /// - vcpu->rcx()
    /// - vcpu->set_rcx()
    /// - vcpu->rdx()
    /// - vcpu->set_rdx()
    ///
    /// @expects
    /// @ensures
    ///
    /// @param leaf the address to emulate
    /// @param d the handler to call when an exit occurs
    ///
    void add_emulator(leaf_t leaf, const handler_delegate_t &d);

    /// Execute
    ///
    /// Executes the CPUID instruction and populates the vCPU's registers as
    /// follows:
    /// - gr1 = vcpu->rax() (leaf input)
    /// - gr2 = vcpu->rcx() (subleaf input)
    /// - [rax, rbx, rcx, rdx] = cpuid
    /// - vcpu->rax() = rax (output)
    /// - vcpu->rbx() = rbx (output)
    /// - vcpu->rcx() = rcx (output)
    /// - vcpu->rdx() = rdx (output)
    ///
    /// Note: This function can be used inside of an emulator to
    /// access hardware similar to a regular handler. This is useful when you
    /// want to use an emulator, but still need to access hardware. Just be
    /// aware that the safety protections that an emulator provides are
    /// removed.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object to execute CPUID on
    ///
    void execute(gsl::not_null<vcpu *> vcpu);

    /// Enable Whitelisting
    ///
    /// By default, if an emulator is not registered, the base implementation
    /// will handle the VM exit for you automatically. If whitelisting is
    /// enabled, this behavior is disabled, and the base implementation will
    /// report the vm exit as unhandled, generating an exception. This is
    /// mostly useful for guest vCPUs that wish to halt() the vCPU if a
    /// register is accessed that is not explicitly being emulated.
    ///
    /// @expects
    /// @ensures
    ///
    void enable_whitelisting() noexcept
    { m_whitelist = true; }

public:

    /// @cond

    bool handle(vcpu *vcpu);

    /// @endcond

private:

    bool m_whitelist{false};
    std::unordered_map<leaf_t, std::list<handler_delegate_t>> m_handlers;
    std::unordered_map<leaf_t, std::list<handler_delegate_t>> m_emulators;

public:

    /// @cond

    cpuid_handler(cpuid_handler &&) = default;
    cpuid_handler &operator=(cpuid_handler &&) = default;

    cpuid_handler(const cpuid_handler &) = delete;
    cpuid_handler &operator=(const cpuid_handler &) = delete;

    /// @endcond
};

}

#endif

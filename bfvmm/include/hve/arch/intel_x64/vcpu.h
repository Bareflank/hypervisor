//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VCPU_INTEL_X64_H
#define VCPU_INTEL_X64_H

#include "exit_handler.h"
#include "vmx.h"
#include "vmcs.h"

#include "../../../vcpu/vcpu.h"
#include "../../../memory_manager/arch/x64/cr3.h"

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HVE
#ifdef SHARED_HVE
#define EXPORT_HVE EXPORT_SYM
#else
#define EXPORT_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HVE
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Defintion
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

/// Intel vCPU
///
/// This class provides the base implementation for an Intel based vCPU. For
/// more information on how a vCPU works, please @see bfvmm::vcpu
///
class EXPORT_HVE vcpu : public bfvmm::vcpu
{

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param id the id of the vcpu
    ///
    vcpu(vcpuid::type id);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~vcpu() override = default;

    /// Run Delegate
    ///
    /// Provides the base implementation for starting the vCPU. This delegate
    /// does not "resume" a vCPU as the base implementation does not support
    /// guest VMs.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj ignored
    ///
    VIRTUAL void run_delegate(bfobject *obj);

    /// Halt Delegate
    ///
    /// Provides the base implementation for stopping the vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param obj ignored
    ///
    VIRTUAL void hlt_delegate(bfobject *obj);

public:

    /// Load vCPU
    ///
    /// Loads the vCPU into hardware.
    ///
    /// @expects none
    /// @ensures none
    ///
    VIRTUAL void load();

    /// Promote vCPU
    ///
    /// Promotes the vCPU.
    ///
    /// @expects none
    /// @ensures none
    ///
    VIRTUAL void promote();

    /// Add Handler vCPU
    ///
    /// Adds an exit handler to the vCPU
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param reason The exit reason for the handler being registered
    /// @param d The delegate being registered
    ///
    VIRTUAL void add_handler(
        ::intel_x64::vmcs::value_type reason,
        const handler_delegate_t &d);

    /// Add Exit Delegate
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
    VIRTUAL void add_exit_handler(
        const handler_delegate_t &d);

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

public:

    /// @cond

    VIRTUAL uint64_t rax() const;
    VIRTUAL void set_rax(uint64_t val);

    VIRTUAL uint64_t rbx() const;
    VIRTUAL void set_rbx(uint64_t val);

    VIRTUAL uint64_t rcx() const;
    VIRTUAL void set_rcx(uint64_t val);

    VIRTUAL uint64_t rdx() const;
    VIRTUAL void set_rdx(uint64_t val);

    VIRTUAL uint64_t rbp() const;
    VIRTUAL void set_rbp(uint64_t val);

    VIRTUAL uint64_t rsi() const;
    VIRTUAL void set_rsi(uint64_t val);

    VIRTUAL uint64_t rdi() const;
    VIRTUAL void set_rdi(uint64_t val);

    VIRTUAL uint64_t r08() const;
    VIRTUAL void set_r08(uint64_t val);

    VIRTUAL uint64_t r09() const;
    VIRTUAL void set_r09(uint64_t val);

    VIRTUAL uint64_t r10() const;
    VIRTUAL void set_r10(uint64_t val);

    VIRTUAL uint64_t r11() const;
    VIRTUAL void set_r11(uint64_t val);

    VIRTUAL uint64_t r12() const;
    VIRTUAL void set_r12(uint64_t val);

    VIRTUAL uint64_t r13() const;
    VIRTUAL void set_r13(uint64_t val);

    VIRTUAL uint64_t r14() const;
    VIRTUAL void set_r14(uint64_t val);

    VIRTUAL uint64_t r15() const;
    VIRTUAL void set_r15(uint64_t val);

    VIRTUAL uint64_t rip() const;
    VIRTUAL void set_rip(uint64_t val);

    VIRTUAL uint64_t rsp() const;
    VIRTUAL void set_rsp(uint64_t val);

    VIRTUAL gsl::not_null<save_state_t *> save_state() const;

    /// @endcond

private:

    bool m_launched{false};

    std::unique_ptr<exit_handler> m_exit_handler;
    std::unique_ptr<vmcs> m_vmcs;
    std::unique_ptr<vmx> m_vmx;
};

}

using vcpu_t = bfvmm::intel_x64::vcpu;

/// Get Guest vCPU
///
/// Gets a guest vCPU from the vCPU manager given a vcpuid
///
/// @expects
/// @ensures
///
/// @return returns a pointer to the vCPU being queried or throws
///     and exception.
///
#define get_vcpu(a) \
    g_vcm->get<bfvmm::intel_x64::vcpu *>(a, __FILE__ ": invalid vcpuid")

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif

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

#ifndef EXIT_HANDLER_INTEL_X64_H
#define EXIT_HANDLER_INTEL_X64_H

#include <bfdelegate.h>

#include <list>
#include <array>
#include <memory>

#include <intrinsics.h>

#include "../vmcs/vmcs.h"
#include "../../x64/gdt.h"
#include "../../x64/idt.h"
#include "../../x64/tss.h"

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
// Dispatch Type
// -----------------------------------------------------------------------------

using dispatch_delegate_t = delegate<bool(gsl::not_null<bfvmm::intel_x64::vmcs *>)>;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void halt(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) noexcept;
bool advance(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) noexcept;

// -----------------------------------------------------------------------------
// Exit Handler
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

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
class EXPORT_HVE exit_handler
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vmcs The VMCS associated with this exit handler
    ///
    exit_handler(
        gsl::not_null<vmcs *> vmcs
    );

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~exit_handler() = default;

    /// Add Dispatch Delegate
    ///
    /// Adds a handler to the dispatch function. When a VM exit occurs, the
    /// dispatch handler will call the delegate registered by this function as
    /// as needed. Note that the handlers are called in the reverse order they
    /// are registered (i.e. FIFO).
    ///
    /// @note If the delegate has serviced the VM exit, it should return true,
    ///     otherwise it should return false, and the next delegate registered
    ///     for this VM exit will execute, or an unimplemented exit reason
    ///     error will trigger
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param reason The exit reason for the handler being registered
    /// @param d The delegate being registered
    ///
    void add_dispatch_delegate(
        ::intel_x64::vmcs::value_type reason,
        dispatch_delegate_t &&d
    );

    /// Dispatch
    ///
    /// Handles a VM exit. This function should only be called by the exit
    /// handler entry function, which gets called when a VM exit occurs, and
    /// then calls this function to dispatch the VM exit to the proper
    /// handler.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param exit_handler The exit handler to dispatch the VM exit to
    ///
    static void dispatch(
        bfvmm::intel_x64::exit_handler *exit_handler) noexcept;

private:

    void write_host_state();
    void write_guest_state();
    void write_control_state();

protected:

    /// @cond

    x64::tss m_host_tss{};
    x64::gdt m_host_gdt{512};
    x64::idt m_host_idt{256};

    /// @endcond

private:

    vmcs *m_vmcs;
    std::unique_ptr<gsl::byte[]> m_stack;

    static ::intel_x64::cr0::value_type s_cr0;
    static ::intel_x64::cr3::value_type s_cr3;
    static ::intel_x64::cr4::value_type s_cr4;
    static ::intel_x64::msrs::value_type s_ia32_pat_msr;
    static ::intel_x64::msrs::value_type s_ia32_efer_msr;

    std::array<std::list<dispatch_delegate_t>, 128> m_handlers;

public:

    /// @cond

    exit_handler(exit_handler &&) noexcept = default;
    exit_handler &operator=(exit_handler &&) noexcept = default;

    exit_handler(const exit_handler &) = delete;
    exit_handler &operator=(const exit_handler &) = delete;

    /// @endcond
};

}
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif

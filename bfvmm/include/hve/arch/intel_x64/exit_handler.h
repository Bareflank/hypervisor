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
#include <mutex>
#include <memory>

#include <intrinsics.h>

#include "vmcs.h"
#include "../x64/gdt.h"
#include "../x64/idt.h"
#include "../x64/tss.h"

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
// Handler Types
// -----------------------------------------------------------------------------

using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
using handler_delegate_t = delegate<handler_t>;
using init_handler_delegate_t = delegate<handler_t>;
using fini_handler_delegate_t = delegate<handler_t>;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void halt(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) noexcept;
bool advance(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs) noexcept;

::x64::msrs::value_type emulate_rdmsr(::x64::msrs::field_type msr);
void emulate_wrmsr(::x64::msrs::field_type msr, ::x64::msrs::value_type val);

uintptr_t emulate_rdgpr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);
void emulate_wrgpr(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs, uintptr_t val);

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
/// its execution), and handleres the appropriated handler to emulate the
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
    VIRTUAL ~exit_handler() = default;

    /// Add Handler Delegate
    ///
    /// Adds a handler to the handler function. When a VM exit occurs, the
    /// handler handler will call the delegate registered by this function as
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
    VIRTUAL void add_handler(
        ::intel_x64::vmcs::value_type reason,
        const handler_delegate_t &d
    );

    /// Add Init Delegate
    ///
    /// Adds an init function to the init list. Init functions are executed
    /// right after a vCPU is started.
    ///
    /// @note The init function is the first VMexit that Bareflank causes
    ///     intentionally. It might not be the first VMexit to occur.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d The delegate being registered
    ///
    VIRTUAL void add_init_handler(
        const handler_delegate_t &d
    );

    /// Add Fini Delegate
    ///
    /// Adds an fini function to the fini list. Fini functions are executed
    /// right before the vCPU is about to stop.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param d The delegate being registered
    ///
    VIRTUAL void add_fini_handler(
        const handler_delegate_t &d
    );

    /// Handle
    ///
    /// Handles a VM exit. This function should only be called by the exit
    /// handler entry function, which gets called when a VM exit occurs, and
    /// then calls this function to handler the VM exit to the proper
    /// handler.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param exit_handler The exit handler to handler the VM exit to
    ///
    static void handle(
        bfvmm::intel_x64::exit_handler *exit_handler) noexcept;

    /// Get Host TSS
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return Returns a pointer to the host_tss
    ///
    auto host_tss() noexcept
    { return &m_host_tss; }

    /// Get Host IDT
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return Returns a pointer to the host_idt
    ///
    auto host_idt() noexcept
    { return &m_host_idt; }

    /// Get Host GDT
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return Returns a pointer to the host_gdt
    ///
    auto host_gdt() noexcept
    { return &m_host_gdt; }

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

    bool handle_cpuid(gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs);

private:

    vmcs *m_vmcs;
    std::unique_ptr<gsl::byte[]> m_stack;
    std::unique_ptr<gsl::byte[]> m_ist1;

    std::list<init_handler_delegate_t> m_init_handlers;
    std::list<fini_handler_delegate_t> m_fini_handlers;
    std::array<std::list<handler_delegate_t>, 128> m_exit_handlers;

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

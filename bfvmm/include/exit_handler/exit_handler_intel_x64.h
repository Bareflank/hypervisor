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
#include <memory_manager/map_ptr_x64.h>
#include <intrinsics/x86/intel_x64.h>

#include <bfjson.h>
#include <bfvmcallinterface.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_EXIT_HANDLER
#ifdef SHARED_EXIT_HANDLER
#define EXPORT_EXIT_HANDLER EXPORT_SYM
#else
#define EXPORT_EXIT_HANDLER IMPORT_SYM
#endif
#else
#define EXPORT_EXIT_HANDLER
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

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
class EXPORT_EXIT_HANDLER exit_handler_intel_x64
{
public:

    using ret_type = int64_t;

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    exit_handler_intel_x64() = default;

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

    /// Stop
    ///
    /// The only difference between halt and stop is halt first prints some
    /// debug information and then halts. Stop simply halts the vCPU. Note
    /// that users can override the stop program to continue execution if it
    /// is possible (for example, running a different vcpu).
    ///
    virtual void stop() noexcept;

#ifndef ENABLE_UNITTESTING
protected:
#endif

    virtual void promote(gsl::not_null<const void *> guest_gdt);

    virtual void resume();
    virtual void advance_and_resume();

    virtual void handle_exit(
        intel_x64::vmcs::value_type reason);

    void handle_cpuid();
    void handle_invd();
    void handle_vmcall();
    void handle_vmxoff();
    void handle_rdmsr();
    void handle_wrmsr();

    void advance_rip() noexcept;
    void unimplemented_handler() noexcept;

    virtual void complete_vmcall(
        ret_type ret, vmcall_registers_t &regs) noexcept;

    virtual void handle_vmcall_versions(
        vmcall_registers_t &regs);
    virtual void handle_vmcall_registers(
        vmcall_registers_t &regs);
    virtual void handle_vmcall_data(
        vmcall_registers_t &regs);
    virtual void handle_vmcall_event(
        vmcall_registers_t &regs);
    virtual void handle_vmcall_start(
        vmcall_registers_t &regs);
    virtual void handle_vmcall_stop(
        vmcall_registers_t &regs);
    virtual void handle_vmcall_unittest(
        vmcall_registers_t &regs);

    virtual void handle_vmcall_data_string_unformatted(
        const std::string &istr, std::string &ostr);

    virtual void handle_vmcall_data_string_json(
        const json &ijson, json &ojson);

    virtual void handle_vmcall_data_binary_unformatted(
        const bfn::unique_map_ptr_x64<char> &imap,
        const bfn::unique_map_ptr_x64<char> &omap);

    void reply_with_string(
        vmcall_registers_t &regs, const std::string &str,
        const bfn::unique_map_ptr_x64<char> &omap);

    void reply_with_json(
        vmcall_registers_t &regs, const json &str,
        const bfn::unique_map_ptr_x64<char> &omap);

public:

    // The following are only marked public for unit testing. Do not use
    // these APIs directly as they may change at any time, and their direct
    // use may be unstable. You have been warned.

    vmcs_intel_x64 *m_vmcs{nullptr};
    state_save_intel_x64 *m_state_save{nullptr};

    virtual void set_vmcs(
        gsl::not_null<vmcs_intel_x64 *> vmcs)
    { m_vmcs = vmcs; }

    virtual void set_state_save(
        gsl::not_null<state_save_intel_x64 *> state_save)
    { m_state_save = state_save; }

public:

    exit_handler_intel_x64(exit_handler_intel_x64 &&) noexcept = default;
    exit_handler_intel_x64 &operator=(exit_handler_intel_x64 &&) noexcept = default;

    exit_handler_intel_x64(const exit_handler_intel_x64 &) = delete;
    exit_handler_intel_x64 &operator=(const exit_handler_intel_x64 &) = delete;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif

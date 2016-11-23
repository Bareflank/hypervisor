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

#include <json.h>
#include <vmcall_interface.h>
#include <vmcs/vmcs_intel_x64.h>
#include <memory_manager/map_ptr_x64.h>

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

protected:

    virtual void handle_exit(intel_x64::vmcs::value_type reason);

    void handle_cpuid();
    void handle_invd();
    void handle_vmcall();
    void handle_vmxoff();
    void handle_rdmsr();
    void handle_wrmsr();

    void advance_rip() noexcept;
    void unimplemented_handler() noexcept;

    void handle_vmcall_versions(vmcall_registers_t &regs);
    void handle_vmcall_registers(vmcall_registers_t &regs);
    void handle_vmcall_data(vmcall_registers_t &regs);
    void handle_vmcall_event(vmcall_registers_t &regs);
    void handle_vmcall_unittest(vmcall_registers_t &regs);

    void handle_vmcall_data_string_unformatted(
        vmcall_registers_t &regs, const std::string &str,
        const bfn::unique_map_ptr_x64<char> &omap);

    void handle_vmcall_data_string_json(
        vmcall_registers_t &regs, const json &str,
        const bfn::unique_map_ptr_x64<char> &omap);

    void handle_vmcall_data_binary_unformatted(
        vmcall_registers_t &regs,
        const bfn::unique_map_ptr_x64<char> &imap,
        const bfn::unique_map_ptr_x64<char> &omap);

protected:

    friend class vcpu_ut;
    friend class vcpu_intel_x64;
    friend class exit_handler_intel_x64_ut;
    friend exit_handler_intel_x64 setup_ehlr(const std::shared_ptr<vmcs_intel_x64> &vmcs);

    std::shared_ptr<vmcs_intel_x64> m_vmcs;
    std::shared_ptr<state_save_intel_x64> m_state_save;

private:

#ifdef INCLUDE_LIBCXX_UNITTESTS

    void unittest_1001_containers_array() const;
    void unittest_1002_containers_vector() const;
    void unittest_1003_containers_deque() const;
    void unittest_1004_containers_forward_list() const;
    void unittest_1005_containers_list() const;
    void unittest_1006_containers_stack() const;
    void unittest_1007_containers_queue() const;
    void unittest_1008_containers_priority_queue() const;
    void unittest_1009_containers_set() const;
    void unittest_100A_containers_map() const;

#endif

private:

    virtual void set_vmcs(const std::shared_ptr<vmcs_intel_x64> &vmcs)
    { m_vmcs = vmcs; }

    virtual void set_state_save(const std::shared_ptr<state_save_intel_x64> &state_save)
    { m_state_save = state_save; }
};

#endif

//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <vmcs/vmcs_intel_x64_state.h>
#include <vmcs/vmcs_intel_x64_helpers.h>
#include <exit_handler/state_save_intel_x64.h>

/// Intel x86_64 VMCS
///
/// The following provides the basic VMCS implementation as defined by the
/// Intel Software Developer's Manual (chapters 24-33). To best understand
/// this code, the manual should first be read.
///
/// This class provides the bare minimum to get a virtual machine to execute.
/// It assumes a 64bit VMM, and a 64bit guest. It does not trap on anything
/// by default, and thus the guest is allowed to execute unfettered. If
/// an error should occur, it contains the logic needed to help identify the
/// issue, including a complete implementation of chapter 26 in the Intel
/// manual, that describes all of the checks the CPU will perform prior to
/// a VM launch. We also provide a considerable amount of pre-defined
/// constants for working with the VMCS fields. Please see the VMCS headers
/// for more details. Pro tip: auto-complete works great with the VMCS
/// namespace logic.
///
/// To use this class, subclass vmcs_intel_x64, and overload the virtual
/// functions for setting up the guest / host state to provide the desired
/// functionality. Don't forget to call the base class function when complete
/// unless you intend to provide the same functionality. For an example of
/// how to do this, please see:
///
/// <a href="https://github.com/Bareflank/hypervisor_example_vpid">Bareflank Hypervisor VPID Example</a>
///
class vmcs_intel_x64
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    vmcs_intel_x64();

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual ~vmcs_intel_x64() = default;

    /// Launch
    ///
    /// Launches the VMCS. Note that this will create a new guest VM when
    /// it is complete. If this function is run more than once, it will clear
    /// the VMCS and its state, starting the VM over again. For this reason
    /// it should only be called once, unless you intend to clear the VM.
    ///
    /// @expects host_state != nullptr
    /// @expects guest_state != nullptr
    /// @ensures none
    ///
    virtual void launch(gsl::not_null<vmcs_intel_x64_state *> host_state,
                        gsl::not_null<vmcs_intel_x64_state *> guest_state);

    /// Resume
    ///
    /// Resumes the VMCS. Note that this should only be called after a launch,
    /// otherwise the system will crash. This function should be called
    /// whenever the exit handler needs to execute a VM. Note that there are
    /// two different times that this might happen: when the exit handler is
    /// done emulating an instruction and needs to return back to the VM,
    /// or it's time to schedule a different VM to execute (that has
    /// obviously already been launched)
    ///
    /// @note if you are going to resume a VMCS, you must make sure that
    ///       VMCS has been loaded first. Otherwise, you will end up resuming
    ///       the currently loaded VMCS with a different state save area. We
    ///       don't check for this issue as it would require us to query
    ///       VMX for the currently loaded VMCS which is slow, and it's likely
    ///       this function will get executed a lot.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void resume();

    /// Promote
    ///
    /// Promotes this guest to VMX root. This is used to transition out of
    /// VMX operation as the guest that this VMCS defines is likely about to
    /// disable VMX operation, and needs to be in VMX root to do so. Note
    /// that this function doesn't actually return if it is successful.
    /// Instead, the CPU resumes execution on the last instruction executed
    /// by the guest.
    ///
    /// @note this function is mainly implemented in raw assembly. The reason
    ///       for this is, GCC was optimizing errors in its implementation
    ///       when "-O3" was enabled. The order of each instruction is very
    ///       important
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void promote();

    /// Load
    ///
    /// The main purpose of this function is to execute VMPTRLD. Specifically,
    /// this function loads the VMCS that this class contains into the CPU.
    /// There are two different times that this is mainly needed. When the
    /// VMCS is first created, a VM launch is needed to get this VMCS up and
    /// running. Before the launch can occur, the VMCS needs to be loaded so
    /// that vm reads / writes are successful (as the CPU needs to know which
    /// VMCS to read / write to). Once a launch has been done, the VMCS
    /// contains the VM's state. The next time it needs to be run, a VMRESUME
    /// must be executed. Once gain, the CPU needs to know which VMCS to use,
    /// and thus a load is needed.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void load();

    /// Clear
    ///
    /// Clears the VMCS. This should only be needed before a VM launch. But
    /// can be used to "reset" a guest prior to launching it again. If you
    /// run a clear, you must run load again as the clear will remove the
    /// valid bit in the VMCS, rendering future reads / writes to this VMCS
    /// invalid.
    ///
    /// @expects none
    /// @ensures none
    ///
    virtual void clear();

protected:

    virtual void write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                              gsl::not_null<vmcs_intel_x64_state *> guest_state);

    void create_vmcs_region();
    void release_vmcs_region() noexcept;

    void create_exit_handler_stack();
    void release_exit_handler_stack() noexcept;

    void write_16bit_control_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_64bit_control_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_32bit_control_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_natural_control_state(gsl::not_null<vmcs_intel_x64_state *> state);

    void write_16bit_guest_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_64bit_guest_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_32bit_guest_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_natural_guest_state(gsl::not_null<vmcs_intel_x64_state *> state);

    void write_16bit_host_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_64bit_host_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_32bit_host_state(gsl::not_null<vmcs_intel_x64_state *> state);
    void write_natural_host_state(gsl::not_null<vmcs_intel_x64_state *> state);

    void pin_based_vm_execution_controls();
    void primary_processor_based_vm_execution_controls();
    void secondary_processor_based_vm_execution_controls();
    void vm_exit_controls();
    void vm_entry_controls();

protected:

    uintptr_t m_vmcs_region_phys;
    std::unique_ptr<uint32_t[]> m_vmcs_region;

    state_save_intel_x64 *m_state_save;
    std::unique_ptr<char[]> m_exit_handler_stack;

private:

    friend class vcpu_ut;
    friend class vmcs_ut;
    friend class vcpu_intel_x64;
    friend class exit_handler_intel_x64;
    friend class exit_handler_intel_x64_ut;

    virtual void set_state_save(gsl::not_null<state_save_intel_x64 *> state_save)
    { m_state_save = state_save; }
};

#endif

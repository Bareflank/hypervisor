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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <bfdelegate.h>

#include <intrinsics.h>
#include <hve/arch/intel_x64/state_save.h>
#include <hve/arch/intel_x64/vmcs/vmcs_state.h>

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
// Definitions
// -----------------------------------------------------------------------------

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
class EXPORT_HVE vmcs_intel_x64
{
public:

    using gdt_t = gsl::not_null<const void *>;                                      ///< GDT pointer type
    using host_state_t = gsl::not_null<vmcs_intel_x64_state *>;                     ///< Host state pointer type
    using guest_state_t = gsl::not_null<vmcs_intel_x64_state *>;                    ///< Guest state pointer type
    using pre_launch_delegate_t = delegate<void(host_state_t, guest_state_t)>;      ///< Pre launch delegate type
    using post_launch_delegate_t = delegate<void(host_state_t, guest_state_t)>;     ///< Post launch delegate type

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
    /// @param host_state the host state for the VMCS
    /// @param guest_state the guest state for the VMCS
    ///
    VIRTUAL void launch(host_state_t host_state, guest_state_t guest_state);

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
    VIRTUAL void resume();

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
    /// @note gdt is the virtual address of the guest's GDT that
    ///       has been mapped into the VMM read/write.  It is marked const
    ///       in order to prevent static analysis from complaining, but
    ///       the memory will be written by the processor in
    ///       vmcs_intel_x64_promote.asm
    ///
    /// @expects gdt != nullptr
    /// @ensures none
    ///
    /// @param gdt a pointer to the guest's gdt
    ///
    VIRTUAL void promote(gdt_t gdt);

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
    VIRTUAL void load();

    /// Set Pre Launch Delegate
    ///
    /// Sets the pre launch delegate. This delegate function will be called
    /// right before the launch occurs, and can be used by extensions to
    /// make mods to the VMCS prior to launch
    ///
    /// @param d the delegate function to use. Ownership is taken.
    ///
    void set_pre_launch_delegate(const pre_launch_delegate_t &d) noexcept;

    /// Set Post Launch Delegate
    ///
    /// Sets the post launch delegate. This delegate function will be called
    /// right after the launch occurs, and can be used by extensions to
    /// make mods to the VMCS after the launch.
    ///
    /// @note This is only called on demotions.
    ///
    /// @param d the delegate function to use. Ownership is taken.
    ///
    void set_post_launch_delegate(const post_launch_delegate_t &d) noexcept;

#ifndef ENABLE_BUILD_TEST
protected:
#endif

    /// @cond

    VIRTUAL void clear();

    /// @endcond

public:

    /// @cond

    void *m_exit_handler_entry{nullptr};
    state_save_intel_x64 *m_state_save{nullptr};

    virtual void set_state_save(gsl::not_null<state_save_intel_x64 *> state_save)
    { m_state_save = state_save; }

    virtual void set_exit_handler_entry(void *entry)
    { m_exit_handler_entry = entry; }

    /// @endcond

private:

    void create_vmcs_region();
    void release_vmcs_region() noexcept;

    void create_exit_handler_stack();
    void release_exit_handler_stack() noexcept;

    void write_16bit_control_state();
    void write_64bit_control_state();
    void write_32bit_control_state();
    void write_natural_control_state();

    void write_16bit_host_state(host_state_t state);
    void write_64bit_host_state(host_state_t state);
    void write_32bit_host_state(host_state_t state);
    void write_natural_host_state(host_state_t state);

    void write_16bit_guest_state(guest_state_t state);
    void write_64bit_guest_state(guest_state_t state);
    void write_32bit_guest_state(guest_state_t state);
    void write_natural_guest_state(guest_state_t state);

    void pin_based_vm_execution_controls();
    void primary_processor_based_vm_execution_controls();
    void secondary_processor_based_vm_execution_controls();
    void vm_exit_controls();
    void vm_entry_controls();


private:

    /// @cond

    uintptr_t m_vmcs_region_phys{0};
    std::unique_ptr<uint32_t[]> m_vmcs_region;
    std::unique_ptr<gsl::byte[]> m_exit_handler_stack;

    pre_launch_delegate_t m_pre_launch_delegate;
    post_launch_delegate_t m_post_launch_delegate;

    /// @endcond

public:

    /// @cond

    vmcs_intel_x64(vmcs_intel_x64 &&) noexcept = default;
    vmcs_intel_x64 &operator=(vmcs_intel_x64 &&) noexcept = default;

    vmcs_intel_x64(const vmcs_intel_x64 &) = delete;
    vmcs_intel_x64 &operator=(const vmcs_intel_x64 &) = delete;

    /// @endcond
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif

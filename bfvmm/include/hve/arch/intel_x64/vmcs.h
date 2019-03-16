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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <bftypes.h>
#include <bfvcpuid.h>

#include "save_state.h"
#include "check.h"
#include "../x64/gdt.h"
#include "../x64/idt.h"
#include "../x64/tss.h"

#include "../../../memory_manager/memory_manager.h"
#include "../../../vmm_types.h"

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

namespace bfvmm::intel_x64
{

class vcpu;

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
class EXPORT_HVE vmcs
{
public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param vcpu The vCPU associated with this VMCS
    ///
    vmcs(vcpu_t vcpu);

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~vmcs() = default;

    /// Init
    ///
    /// Initizlizes the VMCS stucture to be used by hardware
    ///
    /// @expects VMX is enabled
    /// @ensures none
    ///
    void init();

    /// Launch
    ///
    /// Launches the VMCS. Note that this will create a new guest VM when
    /// it is complete. If this function is run more than once, it will clear
    /// the VMCS and its state, starting the VM over again. For this reason
    /// it should only be called once, unless you intend to clear the VM.
    ///
    /// @expects none
    /// @ensures none
    ///
    void launch();

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
    void resume();

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
    void promote();

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
    void load();

    /// Clear
    ///
    /// This function clears the VMCS. This is needed for two main reasons:
    /// - During a VMCS migration, the way to do this is to clear the VMCS
    ///   and then do a VMLanuch again.
    /// - During initialization, we need to clear the VMCS just in case the
    ///   VMCS is given the same physical address twice, which does actually
    ///   happen.
    ///
    /// @expects none
    /// @ensures none
    ///
    void clear();

    /// Check
    ///
    /// This function checks to see if the VMCS is configured improperly.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns true if the VMCS is configured properly, false
    ///     otherwise
    ///
    bool check() const noexcept;

    /// Save State
    ///
    /// Returns the VMCS's save state. This is state that is above and beyond
    /// what the VMCS stores, includng the CPU's registers, vcpuid and
    /// exit handler pointer.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the VMCS's save state.
    ///
    save_state_t *save_state() const
    { return m_save_state.get(); }

    /// MSR bitmap
    ///
    /// Returns the VMCS's msr bitmap
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the VMCS's msr bitmap
    ///
    gsl::not_null<uint8_t *> msr_bitmap() const
    { return m_msr_bitmap.get(); }

    /// IO bitmap a
    ///
    /// Returns the VMCS's io bitmap a
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the VMCS's io bitmap a
    ///
    gsl::not_null<uint8_t *> io_bitmap_a() const
    { return m_io_bitmap_a.get(); }

    /// IO bitmap b
    ///
    /// Returns the VMCS's io bitmap b
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the VMCS's io bitmap b
    ///
    gsl::not_null<uint8_t *> io_bitmap_b() const
    { return m_io_bitmap_b.get(); }

private:

    page_ptr<save_state_t> m_save_state;
    page_ptr<uint32_t> m_vmcs_region;
    uintptr_t m_vmcs_region_phys;
    page_ptr<uint8_t> m_msr_bitmap;
    page_ptr<uint8_t> m_io_bitmap_a;
    page_ptr<uint8_t> m_io_bitmap_b;
    std::unique_ptr<gsl::byte[]> m_ist1;
    std::unique_ptr<gsl::byte[]> m_stack;
    x64::tss m_host_tss{};
    x64::gdt m_host_gdt{512};
    x64::idt m_host_idt{256};

    void write_host_state(vcpuid::type vcpuid);
    void write_guest_state();
    void write_control_state();

public:

    /// @cond

    vmcs(vmcs &&) noexcept = default;
    vmcs &operator=(vmcs &&) noexcept = default;

    vmcs(const vmcs &) = delete;
    vmcs &operator=(const vmcs &) = delete;

    /// @endcond
};

}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif

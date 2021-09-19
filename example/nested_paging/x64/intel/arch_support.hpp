/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef ARCH_SUPPORT_HPP
#define ARCH_SUPPORT_HPP

#include <common_arch_support.hpp>
#include <extended_page_table_t.hpp>
#include <map_page_flags.hpp>
#include <mk_interface.hpp>
#include <mtrrs_t.hpp>
#include <page_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @brief stores the MSR bitmap used by this extension
    constinit inline void *g_msr_bitmaps{};
    /// @brief stores the physical address of the MSR bitmap
    constinit inline bsl::safe_umx g_msr_bitmaps_phys{};

    /// @brief stores the page pool to use for page allocation
    constinit inline page_pool_t g_page_pool{};
    /// @brief stores the mtrrs used to create EPT
    constinit inline mtrrs_t g_mtrrs{};
    /// @brief stores the extended page tables
    constinit inline extended_page_table_t g_ept{};

    /// <!-- description -->
    ///   @brief Handle NMIs. This is required by Intel.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle the handle to use
    ///   @param vsid the ID of the VS that caused the VMExit
    ///   @return Returns bsl::errc_success on success and bsl::errc_failure
    ///     on failure.
    ///
    [[nodiscard]] constexpr auto
    handle_vmexit_nmi(syscall::bf_handle_t &handle, bsl::safe_u16 const &vsid) noexcept
        -> bsl::errc_type
    {
        /// NOTE:
        /// - If we caught an NMI, we need to inject it into the VM. To do
        ///   this, all we do is enable the NMI window, which will tell us
        ///   when we can safely inject the NMI.
        /// - Note that the microkernel will do the same thing. If an NMI
        ///   fires while the hypevisor is running, it will enable the NMI
        ///   window, which the extension will see as a VMExit, and must
        ///   from there, inject the NMI into the appropriate VS.
        ///

        constexpr bsl::safe_umx vmcs_procbased_ctls_idx{bsl::to_umx(0x4002U)};
        constexpr bsl::safe_u32 vmcs_set_nmi_window_exiting{bsl::to_u32(0x400000U)};

        bsl::errc_type ret{};
        bsl::safe_u32 val{};

        ret = syscall::bf_vs_op_read32(handle, vsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        val |= vmcs_set_nmi_window_exiting;

        ret = syscall::bf_vs_op_write32(handle, vsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        return ret;
    }

    /// <!-- description -->
    ///   @brief Handle NMIs Windows
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle the handle to use
    ///   @param vsid the ID of the VS that caused the VMExit
    ///   @return Returns bsl::errc_success on success and bsl::errc_failure
    ///     on failure.
    ///
    [[nodiscard]] constexpr auto
    handle_vmexit_nmi_window(syscall::bf_handle_t &handle, bsl::safe_u16 const &vsid) noexcept
        -> bsl::errc_type
    {
        /// NOTE:
        /// - If we see this exit, it is because an NMI fired. There are two
        ///   situations where this could occur, either while the hypervisor
        ///   is running, or the VS is running. In either case, we need to
        ///   clear the NMI window and inject the NMI into the appropriate
        ///   VS so that it can be handled. Note that Intel requires that
        ///   we handle NMIs, and they actually happen a lot with Linux based
        ///   on what hardware you are using (e.g., a laptop).
        ///

        constexpr bsl::safe_umx vmcs_procbased_ctls_idx{bsl::to_umx(0x4002U)};
        constexpr bsl::safe_u32 vmcs_clear_nmi_window_exiting{bsl::to_u32(0xFFBFFFFFU)};

        bsl::errc_type ret{};
        bsl::safe_u32 val{};

        ret = syscall::bf_vs_op_read32(handle, vsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        val &= vmcs_clear_nmi_window_exiting;

        ret = syscall::bf_vs_op_write32(handle, vsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Inject an NMI. If the NMI window was enabled, it is because we
        ///   need to inject a NMI. Note that the NMI window can be enabled
        ///   both by this extension, as well as by the microkernel itself,
        ///   so we are required to implement it on Intel.
        ///

        constexpr bsl::safe_umx vmcs_entry_interrupt_info_idx{bsl::to_umx(0x4016U)};
        constexpr bsl::safe_u32 vmcs_entry_interrupt_info_val{bsl::to_u32(0x80000202U)};

        ret = syscall::bf_vs_op_write32(
            handle, vsid, vmcs_entry_interrupt_info_idx, vmcs_entry_interrupt_info_val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        return ret;
    }

    /// <!-- description -->
    ///   @brief Implements the architecture specific VMExit handler.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle the handle to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    constexpr void
    vmexit(
        syscall::bf_handle_t &handle,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &exit_reason) noexcept
    {
        bsl::errc_type ret{};
        constexpr bsl::safe_umx exit_reason_nmi{bsl::to_umx(0x0)};
        constexpr bsl::safe_umx exit_reason_nmi_window{bsl::to_umx(0x8)};
        constexpr bsl::safe_umx exit_reason_cpuid{bsl::to_umx(0xA)};

        /// NOTE:
        /// - At a minimum, we need to handle CPUID and NMIs on Intel. Note
        ///   that the "run" APIs all return an error code, but for the most
        ///   part we can ignore them. If the this function succeeds, it will
        ///   not return. If it fails, it will return, and the error code is
        ///   always UNKNOWN. We output the current line so that debugging
        ///   the issue is easier.
        ///

        switch (exit_reason.get()) {
            case exit_reason_nmi.get(): {
                ret = handle_vmexit_nmi(handle, vsid);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return;
                }

                bsl::discard(syscall::bf_vs_op_run_current(handle));
                bsl::print<bsl::V>() << bsl::here();
                return;
            }

            case exit_reason_nmi_window.get(): {
                ret = handle_vmexit_nmi_window(handle, vsid);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return;
                }

                bsl::discard(syscall::bf_vs_op_run_current(handle));
                bsl::print<bsl::V>() << bsl::here();
                return;
            }

            case exit_reason_cpuid.get(): {
                ret = handle_vmexit_cpuid(handle, vsid);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return;
                }

                bsl::discard(syscall::bf_vs_op_advance_ip_and_run_current(handle));
                bsl::print<bsl::V>() << bsl::here();
                return;
            }

            default: {
                break;
            }
        }

        syscall::bf_debug_op_dump_vs(vsid);

        bsl::error() << "unknown exit_reason: "    // --
                     << bsl::hex(exit_reason)      // --
                     << bsl::endl                  // --
                     << bsl::here();               // --
    }

    /// <!-- description -->
    ///   @brief Returns the controls as their masked versions using the
    ///     conversion rules defined in the Intel Manual for determining
    ///     which controls must be enabled, and which controls are not
    ///     allowed to be enabled.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the control to mask
    ///   @return Returns the masked version of the control
    ///
    [[nodiscard]] constexpr auto
    mask_enabled_and_disabled(bsl::safe_umx const &val) noexcept -> bsl::safe_u32
    {
        constexpr bsl::safe_umx ctls_mask{bsl::to_umx(0x00000000FFFFFFFFU)};
        constexpr bsl::safe_umx ctls_shift{bsl::to_umx(32)};
        return bsl::to_u32_unsafe((val & ctls_mask) & (val >> ctls_shift));
    };

    /// <!-- description -->
    ///   @brief Initializes a VS with architecture specific stuff.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle the handle to use
    ///   @param vsid the VS being intialized
    ///   @return Returns bsl::errc_success on success and bsl::errc_failure
    ///     on failure.
    ///
    [[nodiscard]] constexpr auto
    init_vs(syscall::bf_handle_t &handle, bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::errc_type ret{};

        /// NOTE:
        /// - Set up VPID
        ///

        constexpr bsl::safe_umx vmcs_vpid_idx{bsl::to_umx(0x0000U)};
        constexpr bsl::safe_u16 vmcs_vpid_val{bsl::to_u16(0x1)};

        ret = syscall::bf_vs_op_write16(handle, vsid, vmcs_vpid_idx, vmcs_vpid_val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Set up the VMCS link pointer
        ///

        constexpr bsl::safe_umx vmcs_link_ptr_idx{bsl::to_umx(0x2800U)};
        constexpr bsl::safe_umx vmcs_link_ptr_val{bsl::to_umx(0xFFFFFFFFFFFFFFFFU)};

        ret = syscall::bf_vs_op_write64(handle, vsid, vmcs_link_ptr_idx, vmcs_link_ptr_val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Set up the VMCS pin based, proc based, exit and entry controls
        /// - We turn on MSR bitmaps so that we do not trap on MSR reads and
        ///   writes. If you do not configure this, or you use the bitmap
        ///   to trap to specific MSR accesses, make sure you keep the VMCS
        ///   in sync with your MSR mods. Any MSR that is in the VMCS also
        ///   needs to be written to the VMCS, otherwise, VMEntry/VMExit will
        ///   replace any values you write.
        /// - We also turn on secondary controls so that we can turn on VPID,
        ///   and turn on instructions that the OS is relying on, like
        ///   RDTSCP. Failure to do this will cause the invalid opcodes to
        ///   occur.
        /// - The lambda below performs the MSR conversion of the CTLS
        ///   registers to determine the bits that must always be set to 1,
        ///   and the bits that must always be set to 0. This allows us to
        ///   turn on as much as possible, letting the MSRs decide what is
        ///   allowed and what is not.
        /// - Also note that we do not attempt to detect support for the
        ///   secondary controls. This is because the loader ensures that
        ///   this support is present as it is a minimum requirement for the
        ///   project.
        ///

        constexpr bsl::safe_umx vmcs_pinbased_ctls_idx{bsl::to_umx(0x4000U)};
        constexpr bsl::safe_umx vmcs_procbased_ctls_idx{bsl::to_umx(0x4002U)};
        constexpr bsl::safe_umx vmcs_exit_ctls_idx{bsl::to_umx(0x400CU)};
        constexpr bsl::safe_umx vmcs_entry_ctls_idx{bsl::to_umx(0x4012U)};
        constexpr bsl::safe_umx vmcs_procbased_ctls2_idx{bsl::to_umx(0x401EU)};

        constexpr bsl::safe_u32 vmx_true_pinbased_ctls{bsl::to_u32(0x48DU)};
        constexpr bsl::safe_u32 vmx_true_procbased_ctls{bsl::to_u32(0x48EU)};
        constexpr bsl::safe_u32 vmx_true_exit_ctls{bsl::to_u32(0x48FU)};
        constexpr bsl::safe_u32 vmx_true_entry_ctls{bsl::to_u32(0x490U)};
        constexpr bsl::safe_u32 vmx_true_procbased_ctls2{bsl::to_u32(0x48BU)};

        bsl::safe_umx ctls{};

        /// NOTE:
        /// - Configure the pin based controls
        ///

        ret = syscall::bf_intrinsic_op_rdmsr(handle, vmx_true_pinbased_ctls, ctls);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        ret = syscall::bf_vs_op_write32(
            handle, vsid, vmcs_pinbased_ctls_idx, mask_enabled_and_disabled(ctls));
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Configure the proc based controls
        ///

        constexpr bsl::safe_umx enable_msr_bitmaps{bsl::to_umx(0x10000000U)};
        constexpr bsl::safe_umx enable_procbased_ctls2{bsl::to_umx(0x80000000U)};

        ret = syscall::bf_intrinsic_op_rdmsr(handle, vmx_true_procbased_ctls, ctls);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        ctls |= enable_msr_bitmaps;
        ctls |= enable_procbased_ctls2;

        ret = syscall::bf_vs_op_write32(
            handle, vsid, vmcs_procbased_ctls_idx, mask_enabled_and_disabled(ctls));
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Configure the exit controls
        ///

        ret = syscall::bf_intrinsic_op_rdmsr(handle, vmx_true_exit_ctls, ctls);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        ret = syscall::bf_vs_op_write32(
            handle, vsid, vmcs_exit_ctls_idx, mask_enabled_and_disabled(ctls));
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Configure the entry controls
        ///

        ret = syscall::bf_intrinsic_op_rdmsr(handle, vmx_true_entry_ctls, ctls);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        ret = syscall::bf_vs_op_write32(
            handle, vsid, vmcs_entry_ctls_idx, mask_enabled_and_disabled(ctls));
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Configure the secondary proc controls.
        ///

        constexpr bsl::safe_umx enable_vpid{bsl::to_umx(0x00000020U)};
        constexpr bsl::safe_umx enable_rdtscp{bsl::to_umx(0x00000008U)};
        constexpr bsl::safe_umx enable_invpcid{bsl::to_umx(0x00001000U)};
        constexpr bsl::safe_umx enable_xsave{bsl::to_umx(0x00100000U)};
        constexpr bsl::safe_umx enable_uwait{bsl::to_umx(0x04000000U)};
        constexpr bsl::safe_umx enable_ept{bsl::to_umx(0x00000002U)};

        ret = syscall::bf_intrinsic_op_rdmsr(handle, vmx_true_procbased_ctls2, ctls);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        ctls |= enable_vpid;
        ctls |= enable_rdtscp;
        ctls |= enable_invpcid;
        ctls |= enable_xsave;
        ctls |= enable_uwait;
        ctls |= enable_ept;

        ret = syscall::bf_vs_op_write32(
            handle, vsid, vmcs_procbased_ctls2_idx, mask_enabled_and_disabled(ctls));
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Configure the MSR bitmaps. This ensures that we do not trap
        ///   on MSR reads and writes. Also note that in most applications,
        ///   you only need one of these, regardless of the total number of
        ///   CPUs you are running on.
        ///

        constexpr bsl::safe_umx vmcs_msr_bitmaps{bsl::to_umx(0x2004U)};

        if (nullptr == g_msr_bitmaps) {
            ret = syscall::bf_mem_op_alloc_page(handle, g_msr_bitmaps, g_msr_bitmaps_phys);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            bsl::touch();
        }
        else {
            bsl::touch();
        }

        ret = syscall::bf_vs_op_write64(handle, vsid, vmcs_msr_bitmaps, g_msr_bitmaps_phys);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - The first step in setting up EPT is to determine
        ///   if we have support for it. We do this on each physical processor
        ///   we are being started on, but likely you could just do this
        ///   check on the first physical processor and be done.
        /// - To determine if we have support for EPT, we need to check to see
        ///   if attempting to enable EPT above worked. This can be done by
        ///   checking to see if EPT was actually enabled.
        ///

        ret = syscall::bf_vs_op_read64(handle, vsid, vmcs_procbased_ctls2_idx, ctls);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        if ((ctls & (~enable_ept)).is_zero()) {
            bsl::error() << "EPT not supported\n" << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Before we can set up the extended page tables, we need to set up
        ///   a page pool. This is needed because not all microkernels will
        ///   support the free_page() ABI. If we want to change the extended
        ///   page tables, or make new ones and then release them when we are
        ///   done, etc, we will need the ability to free a page so that we
        ///   can use it again. To do this we create our own page pool.
        ///   Whenever we allocate a page, if the page pool is empty, it will
        ///   as the microkernel for a page. When memory is freed, it puts
        ///   the freed page into our page pool so that we can use it the next
        ///   time an allocation occurs.
        /// - Note that this approach is basically how malloc/free engines
        ///   work when you write your own application for Windows/Linux.
        ///   The allocation engine asks the kernel for memory (usually it
        ///   asks for heap memory, but that is not a requirement), and then
        ///   it provides this memory when you run malloc(). We are doing the
        ///   samething here, but with page granularity.
        /// - It should also be noted that the microkernel does provide a
        ///   heap if you want to use it, but in this case we really do want
        ///   page allocation as you cannot do virtual address to physical
        ///   address conversions for memory that was allocated on the heap.
        ///

        if (syscall::bf_tls_ppid(handle) == bsl::ZERO_U16) {
            ret = g_page_pool.initialize(handle);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            bsl::touch();
        }
        else {
            bsl::touch();
        }

        /// NOTE:
        /// - The next step is to initialize and set up the nested page
        ///   tables. One issue with this is you need to know how much
        ///   physical memory to map in. You could determine how much
        ///   physical address space you will need, or you could use on-demand
        ///   paging. You could also fill the entire physical address space
        ///   (up to the MAX value provided by CPUID), but how much memory
        ///   you need to allocate for the page tables to make that work is
        ///   up to what granularity you use. In this example, we only
        ///   provide 2M granularity, so this approach is likely a bad idea.
        /// - Also note that what we are creating here is what we call an
        ///   identify map. Basically, each guest physical address is mapped
        ///   to the same system physical address. This is needed (usually)
        ///   for the root OS. If you plan to create your own guest VMs,
        ///   you will need a different mapping scheme.
        /// - By default, we map in 512 GB of memory. Again, this is likely
        ///   not safe, but is good enough for an example. If the MTRRs report
        ///   that there is less physical memory than 512GB, we use the value
        ///   returned by the MTRRs instead.
        ///

        constexpr bsl::safe_u64 max_physical_mem{bsl::to_umx(0x8000000000U)};

        if (syscall::bf_tls_ppid(handle) == bsl::ZERO_U16) {
            ret = g_ept.initialize(&g_page_pool);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = g_mtrrs.parse(handle);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = g_mtrrs.identity_map_2m(
                g_ept, bsl::ZERO_UMAX, g_mtrrs.max_phys().min(max_physical_mem), MAP_PAGE_RWE);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            bsl::touch();
        }
        else {
            bsl::touch();
        }

        /// NOTE:
        /// - Finally, we need to set EPTP in the VMCS so that the CPU
        ///   knows where to find our extended page tables.
        /// - Similar to CR3, we also need to set some bits in the EPTP.
        ///   In this case we have told the CPU that it has 4 page levels
        ///   to walk and that the default memory type is WB.
        ///

        constexpr bsl::safe_umx eptp_fields{bsl::to_umx(0x1EU)};
        constexpr bsl::safe_umx vmcs_ept_pointer{bsl::to_umx(0x201AU)};

        bsl::safe_umx eptp{g_ept.phys() | eptp_fields};

        ret = syscall::bf_vs_op_write64(handle, vsid, vmcs_ept_pointer, eptp);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        return ret;
    }
}

#endif

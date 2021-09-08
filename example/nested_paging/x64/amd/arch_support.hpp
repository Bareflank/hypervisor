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
#include <mk_interface.hpp>
#include <nested_page_table_t.hpp>
#include <page_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @brief stores the page pool to use for page allocation
    constinit inline page_pool_t g_page_pool{};
    /// @brief stores the nested page tables
    constinit inline nested_page_table_t g_npt{};

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
        constexpr bsl::safe_umx exit_reason_cpuid{bsl::to_umx(0x72U)};

        /// NOTE:
        /// - At a minimum, we need to handle CPUID on AMD. Note that the
        ///   "run" APIs all return an error code, but for the most part we
        ///   can ignore them. If the this function succeeds, it will not
        ///   return. If it fails, it will return, and the error code is
        ///   always UNKNOWN. We output the current line so that debugging
        ///   the issue is easier.
        ///

        switch (exit_reason.get()) {
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

        bsl::safe_umx rax{};
        bsl::safe_umx rbx{};
        bsl::safe_umx rcx{};
        bsl::safe_umx rdx{};

        /// NOTE:
        /// - Set up ASID
        ///

        constexpr bsl::safe_u64 guest_asid_idx{bsl::to_u64(0x0058U)};
        constexpr bsl::safe_u32 guest_asid_val{bsl::to_u32(0x1U)};

        ret = syscall::bf_vs_op_write32(handle, vsid, guest_asid_idx, guest_asid_val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Set up intercept controls. On AMD, we need to intercept
        ///   VMRun, and CPUID if we plan to support reporting and stopping.
        ///

        constexpr bsl::safe_u64 intercept_instruction1_idx{bsl::to_u64(0x000CU)};
        constexpr bsl::safe_u32 intercept_instruction1_val{bsl::to_u32(0x00040000U)};
        constexpr bsl::safe_u64 intercept_instruction2_idx{bsl::to_u64(0x0010U)};
        constexpr bsl::safe_u32 intercept_instruction2_val{bsl::to_u32(0x00000001U)};

        ret = syscall::bf_vs_op_write32(
            handle, vsid, intercept_instruction1_idx, intercept_instruction1_val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        ret = syscall::bf_vs_op_write32(
            handle, vsid, intercept_instruction2_idx, intercept_instruction2_val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - The first step in setting up nested paging is to determine
        ///   if we have support for it. We do this on each physical processor
        ///   we are being started on, but likely you could just do this
        ///   check on the first physical processor and be done.
        ///

        constexpr bsl::safe_umx cpuid_svm_feature_identification{bsl::to_umx(0x8000000AU)};
        constexpr bsl::safe_umx cpuid_svm_feature_identification_np{bsl::to_umx(0x00000001U)};

        rax = cpuid_svm_feature_identification;
        rcx = {};
        intrinsic_cpuid(rax.data(), rbx.data(), rcx.data(), rdx.data());

        if (bsl::unlikely((rdx & cpuid_svm_feature_identification_np).is_zero())) {
            bsl::error() << "nested paging not supported\n" << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - The next step is to enable nested paging in the VMCB.
        ///

        constexpr bsl::safe_u64 guest_ctls1_idx{bsl::to_u64(0x0090U)};
        constexpr bsl::safe_u64 guest_ctls1_val{bsl::to_u64(0x1U)};

        ret = syscall::bf_vs_op_write64(handle, vsid, guest_ctls1_idx, guest_ctls1_val);
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        /// NOTE:
        /// - Before we can set up the nested page tables, we need to set up
        ///   a page pool. This is needed because not all microkernels will
        ///   support the free_page() ABI. If we want to change the nested
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
        ///   not safe, but is good enough for an example.
        ///

        constexpr bsl::safe_u64 page_size_2m{bsl::to_umx(0x200000U)};
        constexpr bsl::safe_u64 max_physical_mem{bsl::to_umx(0x8000000000U)};

        if (syscall::bf_tls_ppid(handle) == bsl::ZERO_U16) {
            ret = g_npt.initialize(&g_page_pool);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            for (bsl::safe_idx gpa{}; gpa < max_physical_mem; gpa += page_size_2m) {
                ret = g_npt.map_2m_page(gpa, gpa, MAP_PAGE_RWE, MEMORY_TYPE_WB);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
        }
        else {
            bsl::touch();
        }

        /// NOTE:
        /// - Finally, we need to set N_CR3 in the VMCB so that the CPU
        ///   knows where to find our nested page tables.
        ///

        constexpr bsl::safe_u64 guest_n_cr3_idx{bsl::to_u64(0x00B0U)};

        ret = syscall::bf_vs_op_write64(handle, vsid, guest_n_cr3_idx, g_npt.phys());
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        return ret;
    }
}

#endif

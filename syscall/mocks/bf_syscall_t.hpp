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

#ifndef MOCK_BF_SYSCALL_T_HPP
#define MOCK_BF_SYSCALL_T_HPP

#include <bf_constants.hpp>       // IWYU pragma: export
#include <bf_reg_t.hpp>           // IWYU pragma: export
#include <bf_syscall_impl.hpp>    // IWYU pragma: export
#include <bf_types.hpp>           // IWYU pragma: export

// IWYU pragma: no_include "bf_constants.hpp"
// IWYU pragma: no_include "bf_reg_t.hpp"
// IWYU pragma: no_include "bf_types.hpp"
// IWYU pragma: no_include "bf_syscall_impl.hpp"

#include <tuple>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unordered_map.hpp>

namespace syscall
{
    /// <!-- description -->
    ///   @brief Provides an API wrapper around all of the microkernel ABIs.
    ///     For more information about these APIs, please see the Microkernel
    ///     ABI Specification.
    ///
    ///
    class bf_syscall_t final
    {
        // clang-format off

        /// @brief stores the results for initialize
        bsl::errc_type m_initialize{};

        /// @brief stores TLS data
        bsl::unordered_map<bsl::safe_u64, bsl::safe_u64> m_tls{};

        /// @brief stores the results for bf_vm_op_create_vm
        bsl::safe_u16 m_bf_vm_op_create_vm{};
        /// @brief stores the results for bf_vm_op_destroy_vm
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vm_op_destroy_vm{};
        /// @brief stores the results for bf_vm_op_map_direct
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vm_op_map_direct{};
        /// @brief stores the results for bf_vm_op_unmap_direct
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vm_op_unmap_direct{};
        /// @brief stores the results for bf_vm_op_unmap_direct_broadcast
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vm_op_unmap_direct_broadcast{};
        /// @brief stores the results for bf_vm_op_tlb_flush
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vm_op_tlb_flush{};
        /// @brief stores the results for bf_vp_op_create_vp
        bsl::unordered_map<bsl::safe_u16, bsl::safe_u16> m_bf_vp_op_create_vp{};
        /// @brief stores the results for bf_vp_op_destroy_vp
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vp_op_destroy_vp{};
        /// @brief stores the results for bf_vs_op_create_vs
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16>, bsl::safe_u16> m_bf_vs_op_create_vs{};
        /// @brief stores the results for bf_vs_op_destroy_vs
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vs_op_destroy_vs{};
        /// @brief stores the results for bf_vs_op_init_as_root
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vs_op_init_as_root{};
        /// @brief stores the results for bf_vs_op_read
        bsl::unordered_map<std::tuple<bsl::safe_u16, bf_reg_t>, bsl::safe_u64> m_bf_vs_op_read{};
        /// @brief stores the results for bf_vs_op_write
        bsl::unordered_map<std::tuple<bsl::safe_u16, bf_reg_t, bsl::safe_u64>, bsl::errc_type> m_bf_vs_op_write{};
        /// @brief stores the results for bf_vs_op_run
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16, bsl::safe_u16>, bsl::errc_type> m_bf_vs_op_run{};
        /// @brief stores the results for bf_vs_op_run_current
        bsl::errc_type m_bf_vs_op_run_current{};
        /// @brief stores the results for bf_vs_op_advance_ip_and_run_impl
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16, bsl::safe_u16>, bsl::errc_type> m_bf_vs_op_advance_ip_and_run{};
        /// @brief stores the results for bf_vs_op_advance_ip_and_run_current
        bsl::errc_type m_bf_vs_op_advance_ip_and_run_current{};
        /// @brief stores the results for bf_vs_op_promote
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vs_op_promote{};
        /// @brief stores the results for bf_vs_op_clear
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vs_op_clear{};
        /// @brief stores the results for bf_vs_op_migrate
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16>, bsl::errc_type> m_bf_vs_op_migrate{};
        /// @brief stores the results for bf_vs_op_set_active
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16, bsl::safe_u16>, bsl::errc_type> m_bf_vs_op_set_active{};
        /// @brief stores the results for bf_vs_op_advance_ip_and_set_active
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16, bsl::safe_u16>, bsl::errc_type> m_bf_vs_op_advance_ip_and_set_active{};
        /// @brief stores the results for bf_vs_op_tlb_flush
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u64>, bsl::errc_type> m_bf_vs_op_tlb_flush{};
        /// @brief stores the results for bf_intrinsic_op_rdmsr
        bsl::unordered_map<bsl::safe_u32, bsl::safe_u64> m_bf_intrinsic_op_rdmsr{};
        /// @brief stores the results for bf_intrinsic_op_wrmsr
        bsl::unordered_map<std::tuple<bsl::safe_u32, bsl::safe_u64>, bsl::errc_type> m_bf_intrinsic_op_wrmsr{};
        /// @brief stores the results for bf_mem_op_alloc_page
        bsl::errc_type m_bf_mem_op_alloc_page{};
        /// @brief stores the results for bf_mem_op_alloc_huge
        bsl::errc_type m_bf_mem_op_alloc_huge{};

        /// @brief stores the call count for initialize
        bsl::safe_umx m_initialize_count{};
        /// @brief stores the call count for release
        bsl::safe_umx m_release_count{};
        /// @brief stores the call count for bf_tls_set_rax
        bsl::safe_umx m_bf_tls_set_rax_count{};
        /// @brief stores the call count for bf_tls_set_rbx
        bsl::safe_umx m_bf_tls_set_rbx_count{};
        /// @brief stores the call count for bf_tls_set_rcx
        bsl::safe_umx m_bf_tls_set_rcx_count{};
        /// @brief stores the call count for bf_tls_set_rdx
        bsl::safe_umx m_bf_tls_set_rdx_count{};
        /// @brief stores the call count for bf_tls_set_rbp
        bsl::safe_umx m_bf_tls_set_rbp_count{};
        /// @brief stores the call count for bf_tls_set_rsi
        bsl::safe_umx m_bf_tls_set_rsi_count{};
        /// @brief stores the call count for bf_tls_set_rdi
        bsl::safe_umx m_bf_tls_set_rdi_count{};
        /// @brief stores the call count for bf_tls_set_r8
        bsl::safe_umx m_bf_tls_set_r8_count{};
        /// @brief stores the call count for bf_tls_set_r9
        bsl::safe_umx m_bf_tls_set_r9_count{};
        /// @brief stores the call count for bf_tls_set_r10
        bsl::safe_umx m_bf_tls_set_r10_count{};
        /// @brief stores the call count for bf_tls_set_r11
        bsl::safe_umx m_bf_tls_set_r11_count{};
        /// @brief stores the call count for bf_tls_set_r12
        bsl::safe_umx m_bf_tls_set_r12_count{};
        /// @brief stores the call count for bf_tls_set_r13
        bsl::safe_umx m_bf_tls_set_r13_count{};
        /// @brief stores the call count for bf_tls_set_r14
        bsl::safe_umx m_bf_tls_set_r14_count{};
        /// @brief stores the call count for bf_tls_set_r15
        bsl::safe_umx m_bf_tls_set_r15_count{};
        /// @brief stores the call count for bf_vm_op_create_vm
        bsl::safe_umx m_bf_vm_op_create_vm_count{};
        /// @brief stores the call count for bf_vm_op_destroy_vm
        bsl::safe_umx m_bf_vm_op_destroy_vm_count{};
        /// @brief stores the call count for bf_vm_op_map_direct
        bsl::safe_umx m_bf_vm_op_map_direct_count{};
        /// @brief stores the call count for bf_vm_op_unmap_direct
        bsl::safe_umx m_bf_vm_op_unmap_direct_count{};
        /// @brief stores the call count for bf_vm_op_unmap_direct_broadcast
        bsl::safe_umx m_bf_vm_op_unmap_direct_broadcast_count{};
        /// @brief stores the call count for bf_vm_op_tlb_flush
        bsl::safe_umx m_bf_vm_op_tlb_flush_count{};
        /// @brief stores the call count for bf_vp_op_create_vp
        bsl::safe_umx m_bf_vp_op_create_vp_count{};
        /// @brief stores the call count for bf_vp_op_destroy_vp
        bsl::safe_umx m_bf_vp_op_destroy_vp_count{};
        /// @brief stores the call count for bf_vs_op_create_vs
        bsl::safe_umx m_bf_vs_op_create_vs_count{};
        /// @brief stores the call count for bf_vs_op_destroy_vs
        bsl::safe_umx m_bf_vs_op_destroy_vs_count{};
        /// @brief stores the call count for bf_vs_op_init_as_root
        bsl::safe_umx m_bf_vs_op_init_as_root_count{};
        /// @brief stores the call count for bf_vs_op_read
        bsl::safe_umx m_bf_vs_op_read_count{};
        /// @brief stores the call count for bf_vs_op_write
        bsl::safe_umx m_bf_vs_op_write_count{};
        /// @brief stores the call count for bf_vs_op_run
        bsl::safe_umx m_bf_vs_op_run_count{};
        /// @brief stores the call count for bf_vs_op_run_current
        bsl::safe_umx m_bf_vs_op_run_current_count{};
        /// @brief stores the call count for bf_vs_op_advance_ip_and_run
        bsl::safe_umx m_bf_vs_op_advance_ip_and_run_count{};
        /// @brief stores the call count for bf_vs_op_advance_ip_and_run_current
        bsl::safe_umx m_bf_vs_op_advance_ip_and_run_current_count{};
        /// @brief stores the call count for bf_vs_op_promote
        bsl::safe_umx m_bf_vs_op_promote_count{};
        /// @brief stores the call count for bf_vs_op_clear
        bsl::safe_umx m_bf_vs_op_clear_count{};
        /// @brief stores the call count for bf_vs_op_migrate
        bsl::safe_umx m_bf_vs_op_migrate_count{};
        /// @brief stores the call count for bf_vs_op_set_active
        bsl::safe_umx m_bf_vs_op_set_active_count{};
        /// @brief stores the call count for bf_vs_op_advance_ip_and_set_active
        bsl::safe_umx m_bf_vs_op_advance_ip_and_set_active_count{};
        /// @brief stores the call count for bf_vs_op_tlb_flush
        bsl::safe_umx m_bf_vs_op_tlb_flush_count{};
        /// @brief stores the call count for bf_intrinsic_op_rdmsr
        bsl::safe_umx m_bf_intrinsic_op_rdmsr_count{};
        /// @brief stores the call count for bf_intrinsic_op_wrmsr
        bsl::safe_umx m_bf_intrinsic_op_wrmsr_count{};
        /// @brief stores the call count for bf_mem_op_alloc_page
        bsl::safe_umx m_bf_mem_op_alloc_page_count{};
        /// @brief stores the call count for bf_mem_op_alloc_huge
        bsl::safe_umx m_bf_mem_op_alloc_huge_count{};


        /// @brief stores the direct map with a phys to virt relationship
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u64>, void *> m_direct_map_phys_to_virt{};
        /// @brief stores the direct map with a virt to phys relationship
        bsl::unordered_map<std::tuple<bsl::safe_u16, void *>, bsl::safe_u64> m_direct_map_virt_to_phys{};

        /// @brief stores the alloc page with a phys to virt relationship
        bsl::unordered_map<bsl::safe_u64, void *> m_alloc_page_phys_to_virt{};
        /// @brief stores the alloc page with a virt to phys relationship
        bsl::unordered_map<void *, bsl::safe_u64> m_alloc_page_virt_to_phys{};

        /// @brief stores the alloc huge with a phys to virt relationship
        bsl::unordered_map<bsl::safe_u64, void *> m_alloc_huge_phys_to_virt{};
        /// @brief stores the alloc huge with a virt to phys relationship
        bsl::unordered_map<void *, bsl::safe_u64> m_alloc_huge_virt_to_phys{};

        /// @brief stores the physical address given out to the next alloc
        bsl::safe_u64 m_alloc_page_phys{};
        /// @brief stores the physical address given out to the next alloc
        bsl::safe_u64 m_alloc_huge_phys{};

        // clang-format on

    public:
        /// <!-- description -->
        ///   @brief Initializes the bf_syscall_t by verifying version
        ///     compatibility, opening a handle and registering the provided
        ///     callbacks.
        ///
        /// <!-- inputs/outputs -->
        ///   @param version the version provided to the extension by the
        ///     microkernel. If this API does not support the ABI versions
        ///     that the microkernel supports, this function will fail.
        ///   @param pmut_bootstrap_handler the bootstrap handler to register
        ///   @param pmut_vmexit_handler the vmexit handler to register
        ///   @param pmut_fail_handler the fail handler to register
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            bsl::safe_u32 const &version,
            bf_callback_handler_bootstrap_t const pmut_bootstrap_handler,
            bf_callback_handler_vmexit_t const pmut_vmexit_handler,
            bf_callback_handler_fail_t const pmut_fail_handler) noexcept -> bsl::errc_type
        {
            bsl::expects(version.is_valid_and_checked());
            bsl::expects(version.is_pos());
            bsl::expects(nullptr != pmut_bootstrap_handler);
            bsl::expects(nullptr != pmut_vmexit_handler);
            bsl::expects(nullptr != pmut_fail_handler);

            ++m_initialize_count;
            return m_initialize;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of initialize.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     initialize
        ///
        constexpr void
        set_initialize(bsl::errc_type const &errc) noexcept
        {
            m_initialize = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times initialize
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times initialize
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        initialize_count() const noexcept -> bsl::safe_umx
        {
            return m_initialize_count.checked();
        }

        /// <!-- description -->
        ///   @brief Releases the bf_syscall_t by closing the handle.
        ///
        constexpr void
        release() noexcept
        {
            ++m_release_count;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times release
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times release
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        release_count() const noexcept -> bsl::safe_umx
        {
            return m_release_count.checked();
        }

        // ---------------------------------------------------------------------
        // TLS ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief Returns the value of tls.rax
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rax
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rax() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_RAX);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rax
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rax to
        ///
        constexpr void
        bf_tls_set_rax(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_rax_count;
            m_tls.at(TLS_OFFSET_RAX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_rax
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_rax
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_rax_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_rax_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rbx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rbx
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rbx() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_RBX);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rbx
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rbx to
        ///
        constexpr void
        bf_tls_set_rbx(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_rbx_count;
            m_tls.at(TLS_OFFSET_RBX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_rbx
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_rbx
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_rbx_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_rbx_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rcx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rcx
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rcx() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_RCX);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rcx
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rcx to
        ///
        constexpr void
        bf_tls_set_rcx(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_rcx_count;
            m_tls.at(TLS_OFFSET_RCX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_rcx
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_rcx
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_rcx_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_rcx_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rdx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rdx
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rdx() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_RDX);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rdx
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rdx to
        ///
        constexpr void
        bf_tls_set_rdx(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_rdx_count;
            m_tls.at(TLS_OFFSET_RDX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_rdx
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_rdx
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_rdx_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_rdx_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rbp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rbp
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rbp() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_RBP);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rbp
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rbp to
        ///
        constexpr void
        bf_tls_set_rbp(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_rbp_count;
            m_tls.at(TLS_OFFSET_RBP) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_rbp
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_rbp
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_rbp_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_rbp_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rsi
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rsi
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rsi() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_RSI);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rsi
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rsi to
        ///
        constexpr void
        bf_tls_set_rsi(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_rsi_count;
            m_tls.at(TLS_OFFSET_RSI) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_rsi
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_rsi
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_rsi_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_rsi_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rdi
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rdi
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rdi() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_RDI);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.rdi
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.rdi to
        ///
        constexpr void
        bf_tls_set_rdi(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_rdi_count;
            m_tls.at(TLS_OFFSET_RDI) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_rdi
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_rdi
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_rdi_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_rdi_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r8
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r8
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r8() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R8);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r8
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r8 to
        ///
        constexpr void
        bf_tls_set_r8(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r8_count;
            m_tls.at(TLS_OFFSET_R8) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r8
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r8
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r8_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r8_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r9
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r9
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r9() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R9);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r9
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r9 to
        ///
        constexpr void
        bf_tls_set_r9(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r9_count;
            m_tls.at(TLS_OFFSET_R9) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r9
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r9
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r9_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r9_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r10
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r10
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r10() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R10);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r10
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r10 to
        ///
        constexpr void
        bf_tls_set_r10(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r10_count;
            m_tls.at(TLS_OFFSET_R10) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r10
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r10
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r10_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r10_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r11
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r11
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r11() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R11);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r11
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r11 to
        ///
        constexpr void
        bf_tls_set_r11(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r11_count;
            m_tls.at(TLS_OFFSET_R11) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r11
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r11
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r11_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r11_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r12
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r12
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r12() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R12);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r12
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r12 to
        ///
        constexpr void
        bf_tls_set_r12(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r12_count;
            m_tls.at(TLS_OFFSET_R12) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r12
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r12
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r12_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r12_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r13
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r13
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r13() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R13);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r13
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r13 to
        ///
        constexpr void
        bf_tls_set_r13(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r13_count;
            m_tls.at(TLS_OFFSET_R13) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r13
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r13
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r13_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r13_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r14
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r14
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r14() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R14);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r14
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r14 to
        ///
        constexpr void
        bf_tls_set_r14(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r14_count;
            m_tls.at(TLS_OFFSET_R14) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r14
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r14
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r14_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r14_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r15
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r15
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r15() const noexcept -> bsl::safe_u64
        {
            return m_tls.at(TLS_OFFSET_R15);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.r15
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.r15 to
        ///
        constexpr void
        bf_tls_set_r15(bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(val.is_valid_and_checked());

            ++m_bf_tls_set_r15_count;
            m_tls.at(TLS_OFFSET_R15) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_tls_set_r15
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_tls_set_r15
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_tls_set_r15_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_tls_set_r15_count.checked();
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.extid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.extid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_extid() const noexcept -> bsl::safe_u16
        {
            return bsl::to_u16(m_tls.at(TLS_OFFSET_ACTIVE_EXTID));
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.extid (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.extid to
        ///
        constexpr void
        bf_tls_set_extid(bsl::safe_u16 const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ACTIVE_EXTID) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.vmid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.vmid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_vmid() const noexcept -> bsl::safe_u16
        {
            return bsl::to_u16(m_tls.at(TLS_OFFSET_ACTIVE_VMID));
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.vmid (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.vmid to
        ///
        constexpr void
        bf_tls_set_vmid(bsl::safe_u16 const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ACTIVE_VMID) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.vpid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.vpid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_vpid() const noexcept -> bsl::safe_u16
        {
            return bsl::to_u16(m_tls.at(TLS_OFFSET_ACTIVE_VPID));
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.vpid (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.vpid to
        ///
        constexpr void
        bf_tls_set_vpid(bsl::safe_u16 const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ACTIVE_VPID) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.vsid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.vsid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_vsid() const noexcept -> bsl::safe_u16
        {
            return bsl::to_u16(m_tls.at(TLS_OFFSET_ACTIVE_VSID));
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.vsid (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.vsid to
        ///
        constexpr void
        bf_tls_set_vsid(bsl::safe_u16 const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ACTIVE_VSID) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.ppid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.ppid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_ppid() const noexcept -> bsl::safe_u16
        {
            return bsl::to_u16(m_tls.at(TLS_OFFSET_ACTIVE_PPID));
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.ppid (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.ppid to
        ///
        constexpr void
        bf_tls_set_ppid(bsl::safe_u16 const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ACTIVE_PPID) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.online_pps
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.online_pps
        ///
        [[nodiscard]] constexpr auto
        bf_tls_online_pps() const noexcept -> bsl::safe_u16
        {
            return bsl::to_u16(m_tls.at(TLS_OFFSET_ONLINE_PPS));
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.online_pps (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.online_pps to
        ///
        constexpr void
        bf_tls_set_online_pps(bsl::safe_u16 const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ONLINE_PPS) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns true if the active VM is the
        ///     root VM. Returns false otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the active VM is the
        ///     root VM. Returns false otherwise.
        ///
        [[nodiscard]] constexpr auto
        is_the_active_vm_the_root_vm() const noexcept -> bool
        {
            return this->bf_tls_vmid() == BF_ROOT_VMID;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided VMID is the
        ///     ID of the root VM. Returns false otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID of the VM to query
        ///   @return Returns true if the provided VMID is the
        ///     ID of the root VM. Returns false otherwise.
        ///
        [[nodiscard]] static constexpr auto
        is_vm_the_root_vm(bsl::safe_u16 const &vmid) noexcept -> bool
        {
            return vmid == BF_ROOT_VMID;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided VPID is the
        ///     ID of a root VP. Returns false otherwise. This
        ///     is the same as vpid == sys.bf_tls_ppid().
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid the ID of the VP to query
        ///   @return Returns true if the provided VPID is the
        ///     ID of a root VP. Returns false otherwise. This
        ///     is the same as vpid == sys.bf_tls_ppid().
        ///
        [[nodiscard]] constexpr auto
        is_vp_a_root_vp(bsl::safe_u16 const &vpid) const noexcept -> bool
        {
            return vpid < bf_tls_online_pps();
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided VSID is the
        ///     ID of a root VS. Returns false otherwise. This
        ///     is the same as vsid == sys.bf_tls_ppid().
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid the ID of the VS to query
        ///   @return Returns true if the provided VSID is the
        ///     ID of a root VS. Returns false otherwise. This
        ///     is the same as vsid == sys.bf_tls_ppid().
        ///
        [[nodiscard]] constexpr auto
        is_vs_a_root_vs(bsl::safe_u16 const &vsid) const noexcept -> bool
        {
            return vsid < bf_tls_online_pps();
        }

        // ---------------------------------------------------------------------
        // bf_vm_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VM
        ///     and return it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_create_vm() noexcept -> bsl::safe_u16
        {
            ++m_bf_vm_op_create_vm_count;
            return m_bf_vm_op_create_vm;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_create_vm.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid the ID to return when executing bf_vm_op_create_vm
        ///
        constexpr void
        set_bf_vm_op_create_vm(bsl::safe_u16 const &vmid) noexcept
        {
            m_bf_vm_op_create_vm = vmid;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vm_op_create_vm
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vm_op_create_vm
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_create_vm_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vm_op_create_vm_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VM
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_destroy_vm(bsl::safe_u16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);

            ++m_bf_vm_op_destroy_vm_count;
            return m_bf_vm_op_destroy_vm.at(vmid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_destroy_vm.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to destroy
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vm_op_destroy_vm
        ///
        constexpr void
        set_bf_vm_op_destroy_vm(bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_destroy_vm.at(vmid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vm_op_destroy_vm
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vm_op_destroy_vm
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_destroy_vm_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vm_op_destroy_vm_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to map a physical
        ///     address into the VM's direct map. This is the same as directly
        ///     accessing the direct map with the difference being that
        ///     software can provide a physical address and receive the
        ///     precalculated virtual address.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param vmid The ID of the VM to map the physical address to
        ///   @param phys The physical address to map
        ///   @return Returns a pointer to the map on success, returns a
        ///     nullptr on failure.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_vm_op_map_direct(bsl::safe_u16 const &vmid, bsl::safe_u64 const &phys) noexcept -> T *
        {
            /// NOTE:
            /// - If we ever need to store T and return is so that a unit test
            ///   can mess around with it, we can use the same pattern used
            ///   by the page_pool_t, where a set of helper functions manage
            ///   what types T can be, and set/get a pointer to T in a union
            ///   for this class so that it just stores the union. This is
            ///   needed because we can only store a void * since we will do
            ///   know what T should be, and as a result we cannot return a
            ///   T *, because in a constexpr, you cannot do a static cast
            ///   from a void * to a T *.
            ///

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);
            bsl::expects(phys.is_valid_and_checked());
            bsl::expects(phys.is_pos());
            bsl::expects(phys < HYPERVISOR_EXT_DIRECT_MAP_SIZE);
            bsl::expects(bf_is_page_aligned(phys));
            bsl::expects(!m_direct_map_phys_to_virt.contains({vmid, phys}));

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            ++m_bf_vm_op_map_direct_count;
            if (!m_bf_vm_op_map_direct.at(vmid)) {
                return nullptr;
            }

            auto *const pmut_virt{new T()};
            m_direct_map_phys_to_virt.at({vmid, phys}) = pmut_virt;
            m_direct_map_virt_to_phys.at({vmid, pmut_virt}) = phys;

            return pmut_virt;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_map_direct.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to map the physical address to
        ///   @param errc if set to any "failure" error code,
        ///     bf_vm_op_map_direct will return a nullptr. Otherwise, the use
        ///     of this function is ignored.
        ///
        constexpr void
        set_bf_vm_op_map_direct(bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_map_direct.at(vmid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vm_op_map_direct
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vm_op_map_direct
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_map_direct_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vm_op_map_direct_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to unmap a previously
        ///     mapped virtual address in the direct map. Unlike
        ///     bf_vm_op_unmap_direct_broadcast, this syscall does not flush the
        ///     TLB on any other PP, meaning this unmap is local to the PP the
        ///     call is made on. Attempting to unmap a virtual address from the
        ///     direct map that has been accessed on any other PP other than
        ///     the PP this syscall is executed on will result in undefined
        ///     behavior. This syscall is designed to support mapping and then
        ///     immediately unmapping a physical address on a single PP during
        ///     a single VMExit. It can also be used to map on a PP and then
        ///     use unmap on the same PP during multiple VMExits, but special
        ///     care must be taken to ensure no other PP can access the map,
        ///     otherwise UB will occur.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param vmid The ID of the VM to unmap the virtual address from
        ///   @param pmut_virt The virtual address to unmap
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_vm_op_unmap_direct(bsl::safe_u16 const &vmid, T *const pmut_virt) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);
            bsl::expects(nullptr != pmut_virt);

            auto const phys{m_direct_map_virt_to_phys.at({vmid, pmut_virt})};
            bsl::expects(phys.is_valid_and_checked());
            bsl::expects(phys.is_pos());

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            ++m_bf_vm_op_unmap_direct_count;
            if (!m_bf_vm_op_unmap_direct.at(vmid)) {
                return m_bf_vm_op_unmap_direct.at(vmid);
            }

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete pmut_virt;    // GRCOV_EXCLUDE_BR
            bsl::discard(m_direct_map_phys_to_virt.erase({vmid, phys}));
            bsl::discard(m_direct_map_virt_to_phys.erase({vmid, pmut_virt}));

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_unmap_direct.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to unmap the virtual address from
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vm_op_unmap_direct
        ///
        constexpr void
        set_bf_vm_op_unmap_direct(bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_unmap_direct.at(vmid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vm_op_unmap_direct
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vm_op_unmap_direct
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_unmap_direct_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vm_op_unmap_direct_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to unmap a previously
        ///     mapped virtual address in the direct map. Unlike
        ///     bf_vm_op_unmap_direct, this syscall performs a broadcast TLB flush
        ///     which means it can be safely used on all direct mapped
        ///     addresses. The downside of using this function is that it can
        ///     be a lot slower than bf_vm_op_unmap_direct, especially on
        ///     systems with a lot of PPs.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param vmid The ID of the VM to unmap the virtual address from
        ///   @param pmut_virt The virtual address to unmap
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_vm_op_unmap_direct_broadcast(bsl::safe_u16 const &vmid, T *const pmut_virt) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);
            bsl::expects(nullptr != pmut_virt);

            auto const phys{m_direct_map_virt_to_phys.at({vmid, pmut_virt})};
            bsl::expects(phys.is_valid_and_checked());
            bsl::expects(phys.is_pos());

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            ++m_bf_vm_op_unmap_direct_broadcast_count;
            if (!m_bf_vm_op_unmap_direct_broadcast.at(vmid)) {
                return m_bf_vm_op_unmap_direct_broadcast.at(vmid);
            }

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete pmut_virt;    // GRCOV_EXCLUDE_BR
            bsl::discard(m_direct_map_phys_to_virt.erase({vmid, phys}));
            bsl::discard(m_direct_map_virt_to_phys.erase({vmid, pmut_virt}));

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_unmap_direct_broadcast.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to unmap the virtual address from
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vm_op_unmap_direct_broadcast
        ///
        constexpr void
        set_bf_vm_op_unmap_direct_broadcast(
            bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_unmap_direct_broadcast.at(vmid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vm_op_unmap_direct_broadcast
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vm_op_unmap_direct_broadcast
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_unmap_direct_broadcast_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vm_op_unmap_direct_broadcast_count.checked();
        }

        /// <!-- description -->
        ///   @brief Given the ID of a VM, invalidates a TLB entry for a given
        ///     GLA on the PP that this is executed on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to invalidate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_tlb_flush(bsl::safe_u16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);

            ++m_bf_vm_op_tlb_flush_count;
            return m_bf_vm_op_tlb_flush.at(vmid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_tlb_flush.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to invalidate
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vm_op_tlb_flush
        ///
        constexpr void
        set_bf_vm_op_tlb_flush(bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_tlb_flush.at(vmid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vm_op_tlb_flush
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vm_op_tlb_flush
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_tlb_flush_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vm_op_tlb_flush_count.checked();
        }

        // ---------------------------------------------------------------------
        // bf_vp_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VP given the
        ///     IDs of the VM and PP the VP will be assigned to. Upon success,
        ///     this syscall returns the ID of the newly created VP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to assign the newly created VP to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_create_vp(bsl::safe_u16 const &vmid) noexcept -> bsl::safe_u16
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);

            ++m_bf_vp_op_create_vp_count;
            return m_bf_vp_op_create_vp.at(vmid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vp_op_create_vp.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to assign the newly created VP to
        ///   @param vpid the ID to return when executing set_bf_vp_op_create_vp
        ///
        constexpr void
        set_bf_vp_op_create_vp(bsl::safe_u16 const &vmid, bsl::safe_u16 const &vpid) noexcept
        {
            m_bf_vp_op_create_vp.at(vmid) = vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vp_op_create_vp
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vp_op_create_vp
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_create_vp_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vp_op_create_vp_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VP
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_destroy_vp(bsl::safe_u16 const &vpid) noexcept -> bsl::errc_type
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);

            ++m_bf_vp_op_destroy_vp_count;
            return m_bf_vp_op_destroy_vp.at(vpid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vp_op_destroy_vp.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to destroy
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vp_op_destroy_vp
        ///
        constexpr void
        set_bf_vp_op_destroy_vp(bsl::safe_u16 const &vpid, bsl::errc_type const errc) noexcept
        {
            m_bf_vp_op_destroy_vp.at(vpid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vp_op_destroy_vp
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vp_op_destroy_vp
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_destroy_vp_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vp_op_destroy_vp_count.checked();
        }

        // ---------------------------------------------------------------------
        // bf_vs_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VS
        ///     and return it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to assign the newly created VS to
        ///   @param ppid The resulting VSID of the newly created VS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_create_vs(bsl::safe_u16 const &vpid, bsl::safe_u16 const &ppid) noexcept
            -> bsl::safe_u16
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(ppid) < HYPERVISOR_MAX_PPS);

            ++m_bf_vs_op_create_vs_count;
            return m_bf_vs_op_create_vs.at({vpid, ppid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_create_vs.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to assign the newly created VS to
        ///   @param ppid The resulting VSID of the newly created VS
        ///   @param vspid the ID to return when executing
        ///     set_bf_vs_op_create_vs
        ///
        constexpr void
        set_bf_vs_op_create_vs(
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid,
            bsl::safe_u16 const &vspid) noexcept
        {
            m_bf_vs_op_create_vs.at({vpid, ppid}) = vspid;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_create_vs
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_create_vs
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_create_vs_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_create_vs_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VS
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_destroy_vs(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_destroy_vs_count;
            return m_bf_vs_op_destroy_vs.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_destroy_vs.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to destroy
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_destroy_vs
        ///
        constexpr void
        set_bf_vs_op_destroy_vs(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_destroy_vs.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_destroy_vs
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_destroy_vs
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_destroy_vs_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_destroy_vs_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to initialize a VS using
        ///     the root VP state provided by the loader using the current PPID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to initialize
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_init_as_root(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_init_as_root_count;
            return m_bf_vs_op_init_as_root.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_init_as_root.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to initialize
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_init_as_root
        ///
        constexpr void
        set_bf_vs_op_init_as_root(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_init_as_root.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_init_as_root
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_init_as_root
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_init_as_root_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_init_as_root_count.checked();
        }

        /// <!-- description -->
        ///   @brief Reads a CPU register from the VS given a bf_reg_t. Note
        ///     that the bf_reg_t is architecture specific.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to read from
        ///   @param reg A bf_reg_t defining which register to read
        ///   @return Returns the value read, or bsl::safe_u64::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_read(bsl::safe_u16 const &vsid, bf_reg_t const reg) const noexcept -> bsl::safe_u64
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);
            bsl::expects(reg < syscall::bf_reg_t::bf_reg_t_invalid);
            bsl::expects(reg != syscall::bf_reg_t::bf_reg_t_unsupported);

            return m_bf_vs_op_read.at({vsid, reg});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_read.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to read from
        ///   @param reg A bf_reg_t defining which register to read
        ///   @param value the value to return when executing
        ///     bf_vs_op_read
        ///
        constexpr void
        set_bf_vs_op_read(
            bsl::safe_u16 const &vsid, bf_reg_t const reg, bsl::safe_u64 const &value) noexcept
        {
            m_bf_vs_op_read.at({vsid, reg}) = value;
        }

        /// <!-- description -->
        ///   @brief Writes to a CPU register in the VS given a bf_reg_t and the
        ///     value to write. Note that the bf_reg_t is architecture specific.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to write to
        ///   @param reg A bf_reg_t defining which register to write to
        ///   @param value The value to write to the requested register
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_write(
            bsl::safe_u16 const &vsid, bf_reg_t const reg, bsl::safe_u64 const &value) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(reg < syscall::bf_reg_t::bf_reg_t_invalid);
            bsl::expects(reg != syscall::bf_reg_t::bf_reg_t_unsupported);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);
            bsl::expects(value.is_valid_and_checked());

            if (m_bf_vs_op_write.at({vsid, reg, value})) {
                m_bf_vs_op_read.at({vsid, reg}) = value;
            }
            else {
                bsl::touch();
            }

            ++m_bf_vs_op_write_count;
            return m_bf_vs_op_write.at({vsid, reg, value});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_write.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to write to
        ///   @param reg A bf_reg_t defining which register to write to
        ///   @param value The value to write to the requested field
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_write
        ///
        constexpr void
        set_bf_vs_op_write(
            bsl::safe_u16 const &vsid,
            bf_reg_t const reg,
            bsl::safe_u64 const &value,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_write.at({vsid, reg, value}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_write
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_write
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_write_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_write_count.checked();
        }

        /// <!-- description -->
        ///   @brief TODO
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to run
        ///   @param vpid The ID of the VP to run
        ///   @param vsid The ID of the VS to run
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_run(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_run_count;
            return m_bf_vs_op_run.at({vmid, vpid, vsid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_run.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to run
        ///   @param vpid The ID of the VP to run
        ///   @param vsid The ID of the VS to run
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_run
        ///
        constexpr void
        set_bf_vs_op_run(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_run.at({vmid, vpid, vsid}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_run
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_run
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_run_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_run_count.checked();
        }

        /// <!-- description -->
        ///   @brief bf_vs_op_run_current tells the microkernel to execute the
        ///     currently active VS, VP and VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_run_current() noexcept -> bsl::errc_type
        {
            ++m_bf_vs_op_run_current_count;
            return m_bf_vs_op_run_current;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_run_current.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_run_current
        ///
        constexpr void
        set_bf_vs_op_run_current(bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_run_current = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_run_current
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_run_current
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_run_current_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_run_current_count.checked();
        }

        /// <!-- description -->
        ///   @brief TODO
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to advance the IP for
        ///   @param vpid The ID of the VP to advance the IP for
        ///   @param vsid The ID of the VS to advance the IP for
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip_and_run(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_advance_ip_and_run_count;
            return m_bf_vs_op_advance_ip_and_run.at({vmid, vpid, vsid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_advance_ip_and_run.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to advance the IP for
        ///   @param vpid The ID of the VP to advance the IP for
        ///   @param vsid The ID of the VS to advance the IP for
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_advance_ip_and_run
        ///
        constexpr void
        set_bf_vs_op_advance_ip_and_run(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_advance_ip_and_run.at({vmid, vpid, vsid}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_advance_ip_and_run
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_advance_ip_and_run
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip_and_run_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_advance_ip_and_run_count.checked();
        }

        /// <!-- description -->
        ///   @brief TODO
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip_and_run_current() noexcept -> bsl::errc_type
        {
            ++m_bf_vs_op_advance_ip_and_run_current_count;
            return m_bf_vs_op_advance_ip_and_run_current;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_advance_ip_and_run_current.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_advance_ip_and_run_current
        ///
        constexpr void
        set_bf_vs_op_advance_ip_and_run_current(bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_advance_ip_and_run_current = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_advance_ip_and_run_current
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_advance_ip_and_run_current
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip_and_run_current_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_advance_ip_and_run_current_count.checked();
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to promote the requested
        ///     VS. This will stop the hypervisor complete on the physical
        ///     processor that this syscall is executed on and replace it's state
        ///     with the state in the VS. Note that this syscall only returns
        ///     on error.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to promote
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_promote(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_promote_count;
            return m_bf_vs_op_promote.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_promote.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to promote
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_promote
        ///
        constexpr void
        set_bf_vs_op_promote(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_promote.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_promote
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_promote
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_promote_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_promote_count.checked();
        }

        /// <!-- description -->
        ///   @brief bf_vs_op_clear tells the microkernel to clear the VS's
        ///     hardware cache, if one exists. How this is used depends entirely
        ///     on the hardware and is associated with AMD's VMCB Clean Bits,
        ///     and Intel's VMClear instruction. See the associated documentation
        ///     for more details. On AMD, this ABI clears the entire VMCB. For more
        ///     fine grained control, use the write ABIs to manually modify the
        ///     VMCB.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to clear
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_clear(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_clear_count;
            return m_bf_vs_op_clear.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_clear.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to clear
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_clear
        ///
        constexpr void
        set_bf_vs_op_clear(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_clear.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_clear
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_clear
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_clear_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_clear_count.checked();
        }

        /// <!-- description -->
        ///   @brief TODO
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to migrate
        ///   @param ppid The ID of the PP to migrate the VS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_migrate(bsl::safe_u16 const &vsid, bsl::safe_u16 const &ppid) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(ppid) < HYPERVISOR_MAX_PPS);

            ++m_bf_vs_op_migrate_count;
            return m_bf_vs_op_migrate.at({vsid, ppid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_migrate.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to migrate
        ///   @param ppid The ID of the PP to migrate the VS to
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_migrate
        ///
        constexpr void
        set_bf_vs_op_migrate(
            bsl::safe_u16 const &vsid,
            bsl::safe_u16 const &ppid,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_migrate.at({vsid, ppid}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_migrate
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_migrate
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_migrate_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_migrate_count.checked();
        }

        /// <!-- description -->
        ///   @brief TODO
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to run
        ///   @param vpid The ID of the VP to run
        ///   @param vsid The ID of the VS to run
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_set_active(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_set_active_count;
            return m_bf_vs_op_set_active.at({vmid, vpid, vsid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_set_active.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to run
        ///   @param vpid The ID of the VP to run
        ///   @param vsid The ID of the VS to run
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_set_active
        ///
        constexpr void
        set_bf_vs_op_set_active(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_set_active.at({vmid, vpid, vsid}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_set_active
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_set_active
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_set_active_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_set_active_count.checked();
        }

        /// <!-- description -->
        ///   @brief TODO
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to run
        ///   @param vpid The ID of the VP to run
        ///   @param vsid The ID of the VS to run
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip_and_set_active(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            ++m_bf_vs_op_advance_ip_and_set_active_count;
            return m_bf_vs_op_advance_ip_and_set_active.at({vmid, vpid, vsid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_advance_ip_and_set_active.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to run
        ///   @param vpid The ID of the VP to run
        ///   @param vsid The ID of the VS to run
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_advance_ip_and_set_active
        ///
        constexpr void
        set_bf_vs_op_advance_ip_and_set_active(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &vsid,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_advance_ip_and_set_active.at({vmid, vpid, vsid}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_advance_ip_and_set_active
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_advance_ip_and_set_active
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip_and_set_active_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_advance_ip_and_set_active_count.checked();
        }

        /// <!-- description -->
        ///   @brief Given the ID of a VS, invalidates a TLB entry for a given
        ///     GLA on the PP that this is executed on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to invalidate
        ///   @param gla The GLA to invalidate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_tlb_flush(bsl::safe_u16 const &vsid, bsl::safe_u64 const &gla) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);
            bsl::expects(gla.is_valid_and_checked());
            bsl::expects(gla.is_pos());
            bsl::expects(bf_is_page_aligned(gla));

            ++m_bf_vs_op_tlb_flush_count;
            return m_bf_vs_op_tlb_flush.at({vsid, gla});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_tlb_flush.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The ID of the VS to invalidate
        ///   @param gla The GLA to invalidate
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_tlb_flush
        ///
        constexpr void
        set_bf_vs_op_tlb_flush(
            bsl::safe_u16 const &vsid, bsl::safe_u64 const &gla, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_tlb_flush.at({vsid, gla}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_vs_op_tlb_flush
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_vs_op_tlb_flush
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_tlb_flush_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_vs_op_tlb_flush_count.checked();
        }

        // ---------------------------------------------------------------------
        // bf_intrinsic_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief Reads an MSR directly from the CPU given the address of
        ///     the MSR to read. Note that this is specific to Intel/AMD only.
        ///     Also note that not all MSRs can be read, and which MSRs that
        ///     can be read is up to the microkernel's internal policy as well
        ///     as which architecture the hypervisor is running on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to read
        ///   @return Returns the value read, or bsl::safe_u64::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_rdmsr(bsl::safe_u32 const &msr) const noexcept -> bsl::safe_u64
        {
            bsl::expects(msr.is_valid_and_checked());
            bsl::expects(msr.is_pos());

            return m_bf_intrinsic_op_rdmsr.at(msr);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_intrinsic_op_rdmsr.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to read
        ///   @param val the value to return when executing
        ///     bf_intrinsic_op_rdmsr
        ///
        constexpr void
        set_bf_intrinsic_op_rdmsr(bsl::safe_u32 const &msr, bsl::safe_u64 const &val) noexcept
        {
            m_bf_intrinsic_op_rdmsr.at(msr) = val;
        }

        /// <!-- description -->
        ///   @brief Writes to an MSR directly from the CPU given the address of
        ///     the MSR to write as well as the value to write. Note that this is
        ///     specific to Intel/AMD only. Also note that not all MSRs can be
        ///     written to, and which MSRs that can be written to is up to the
        ///     microkernel's internal policy as well as which architecture the
        ///     hypervisor is running on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to write to
        ///   @param val The value to write to the requested MSR
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_wrmsr(bsl::safe_u32 const &msr, bsl::safe_u64 const &val) noexcept
            -> bsl::errc_type
        {
            bsl::expects(msr.is_valid_and_checked());
            bsl::expects(msr.is_pos());
            bsl::expects(val.is_valid_and_checked());

            if (m_bf_intrinsic_op_wrmsr.at({msr, val})) {
                m_bf_intrinsic_op_rdmsr.at(msr) = val;
            }
            else {
                bsl::touch();
            }

            ++m_bf_intrinsic_op_wrmsr_count;
            return m_bf_intrinsic_op_wrmsr.at({msr, val});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_intrinsic_op_wrmsr.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to write to
        ///   @param val The value to write to the requested MSR
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_intrinsic_op_wrmsr
        ///
        constexpr void
        set_bf_intrinsic_op_wrmsr(
            bsl::safe_u32 const &msr, bsl::safe_u64 const &val, bsl::errc_type const errc) noexcept
        {
            m_bf_intrinsic_op_wrmsr.at({msr, val}) = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_intrinsic_op_wrmsr
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_intrinsic_op_wrmsr
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_wrmsr_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_intrinsic_op_wrmsr_count.checked();
        }

        // ---------------------------------------------------------------------
        // bf_mem_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_page allocates a page, and maps this page
        ///     into the direct map of the VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param mut_phys The mut_physical address of the resulting page
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_page(bsl::safe_u64 &mut_phys) noexcept -> T *
        {
            bsl::expects(mut_phys.is_valid_and_checked());

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            ++m_bf_mem_op_alloc_page_count;
            if (!m_bf_mem_op_alloc_page) {
                return nullptr;
            }

            m_alloc_page_phys += HYPERVISOR_PAGE_SIZE;
            mut_phys = m_alloc_page_phys.checked();

            auto *const pmut_virt{new T()};
            m_alloc_page_phys_to_virt.at(mut_phys) = pmut_virt;
            m_alloc_page_virt_to_phys.at(pmut_virt) = mut_phys;

            return pmut_virt;
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_page allocates a page, and maps this page
        ///     into the direct map of the VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_page() noexcept -> T *
        {
            bsl::safe_u64 mut_ignored{};
            return this->bf_mem_op_alloc_page<T>(mut_ignored);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_mem_op_alloc_page.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_mem_op_alloc_page
        ///
        constexpr void
        set_bf_mem_op_alloc_page(bsl::errc_type const errc) noexcept
        {
            m_bf_mem_op_alloc_page = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_mem_op_alloc_page
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_mem_op_alloc_page
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_page_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_mem_op_alloc_page_count.checked();
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_huge allocates a physically contiguous block
        ///     of memory. When allocating a page, the extension should keep in
        ///     mind the following:
        ///       - The total memory available to allocate from this pool is
        ///         extremely limited. This should only be used when absolutely
        ///         needed, and extensions should not expect more than 1 MB (might
        ///         be less) of total memory available.
        ///       - Memory allocated from the huge pool might be allocated using
        ///         different schemes. For example, the microkernel might allocate
        ///         in increments of a page, or it might use a buddy allocator that
        ///         would allocate in multiples of 2. If the allocation size
        ///         doesn't match the algorithm, internal fragmentation could
        ///         occur, further limiting the total number of allocations this
        ///         pool can support.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param size The total number of bytes to allocate
        ///   @param mut_phys The physical address of the resulting memory
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_huge(bsl::safe_u64 const &size, bsl::safe_u64 &mut_phys) noexcept -> T *
        {
            bsl::expects(size.is_valid_and_checked());
            bsl::expects(size.is_pos());
            bsl::expects(bf_is_page_aligned(size));
            bsl::expects(mut_phys.is_valid_and_checked());

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            ++m_bf_mem_op_alloc_huge_count;
            if (!m_bf_mem_op_alloc_huge) {
                return nullptr;
            }

            /// BUG:
            /// - Clang 10 has a bug that does not allow us to allocate memory
            ///   of any size. If we attempt to do this, it will segfault the
            ///   the compiler. This is not an issue with Clang 11+, so the
            ///   bug has already been addressed. The problem is, we need to
            ///   be able to support Clang 10 as that is what comes default
            ///   with Ubuntu 20.04.
            /// - To fix this, we hardcode the allocation in this mock to 16k.
            ///   Most of the huge page allocations that will be needed are
            ///   limited to 4k (or at least should be as the huge page pool
            ///   is very limited in size and should not be used for much more
            ///   than that. Anything larger, and a different, extension
            ///   specific allocator should be used instead.
            /// - If this proves to be an issue, a CMake constant could be
            ///   added to configure this.
            ///

            constexpr auto bf_mem_op_alloc_huge_max{0x4000_umx};
            bsl::expects(size <= bf_mem_op_alloc_huge_max);

            m_alloc_huge_phys += size;
            mut_phys = m_alloc_huge_phys.checked();

            auto *const pmut_virt{new T[bf_mem_op_alloc_huge_max.get()]()};
            m_alloc_huge_phys_to_virt.at(mut_phys) = pmut_virt;
            m_alloc_huge_virt_to_phys.at(pmut_virt) = mut_phys;

            return pmut_virt;
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_huge allocates a physically contiguous block
        ///     of memory. When allocating a page, the extension should keep in
        ///     mind the following:
        ///       - The total memory available to allocate from this pool is
        ///         extremely limited. This should only be used when absolutely
        ///         needed, and extensions should not expect more than 1 MB (might
        ///         be less) of total memory available.
        ///       - Memory allocated from the huge pool might be allocated using
        ///         different schemes. For example, the microkernel might allocate
        ///         in increments of a page, or it might use a buddy allocator that
        ///         would allocate in multiples of 2. If the allocation size
        ///         doesn't match the algorithm, internal fragmentation could
        ///         occur, further limiting the total number of allocations this
        ///         pool can support.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param size The total number of bytes to allocate
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_huge(bsl::safe_u64 const &size) noexcept -> T *
        {
            bsl::safe_u64 mut_ignored{};
            return this->bf_mem_op_alloc_huge<T>(size, mut_ignored);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_mem_op_alloc_huge.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_mem_op_alloc_huge
        ///
        constexpr void
        set_bf_mem_op_alloc_huge(bsl::errc_type const errc) noexcept
        {
            m_bf_mem_op_alloc_huge = errc;
        }

        /// <!-- description -->
        ///   @brief Returns the total number of times bf_mem_op_alloc_huge
        ///     has been called (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the total number of times bf_mem_op_alloc_huge
        ///     has been called
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_huge_count() const noexcept -> bsl::safe_umx
        {
            return m_bf_mem_op_alloc_huge_count.checked();
        }
    };
}

#endif

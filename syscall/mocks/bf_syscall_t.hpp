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

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <bf_syscall_impl.hpp>
#include <bf_types.hpp>
#include <tuple>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/is_unsigned.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unordered_map.hpp>

namespace syscall
{
    /// @class syscall::bf_syscall_t
    ///
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
        /// @brief stores the results for bf_vp_op_create_vp
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16>, bsl::safe_u16> m_bf_vp_op_create_vp{};
        /// @brief stores the results for bf_vp_op_destroy_vp
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vp_op_destroy_vp{};
        /// @brief stores the results for bf_vp_op_migrate
        bsl::unordered_map<std::tuple<bsl::safe_u16, bsl::safe_u16>, bsl::errc_type> m_bf_vp_op_migrate{};
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
        /// @brief stores the results for bf_vs_op_advance_ip
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vs_op_advance_ip{};
        /// @brief stores the results for bf_vs_op_advance_ip_and_run_current
        bsl::errc_type m_bf_vs_op_advance_ip_and_run_current{};
        /// @brief stores the results for bf_vs_op_promote
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vs_op_promote{};
        /// @brief stores the results for bf_vs_op_clear_vs
        bsl::unordered_map<bsl::safe_u16, bsl::errc_type> m_bf_vs_op_clear_vs{};
        /// @brief stores the results for bf_intrinsic_op_rdmsr
        bsl::unordered_map<bsl::safe_u32, bsl::safe_u64> m_bf_intrinsic_op_rdmsr{};
        /// @brief stores the results for bf_intrinsic_op_wrmsr
        bsl::unordered_map<std::tuple<bsl::safe_u32, bsl::safe_u64>, bsl::errc_type> m_bf_intrinsic_op_wrmsr{};
        /// @brief stores the results for bf_mem_op_alloc_page
        bsl::errc_type m_bf_mem_op_alloc_page{};
        /// @brief stores the results for bf_mem_op_free_page
        bsl::errc_type m_bf_mem_op_free_page{};
        /// @brief stores the results for bf_mem_op_alloc_huge
        bsl::errc_type m_bf_mem_op_alloc_huge{};
        /// @brief stores the results for bf_mem_op_free_huge
        bsl::errc_type m_bf_mem_op_free_huge{};

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
        ///   @brief Releases the bf_syscall_t by closing the handle.
        ///
        constexpr void
        release() noexcept
        {}

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
            m_tls.at(TLS_OFFSET_RAX) = val;
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
            m_tls.at(TLS_OFFSET_RBX) = val;
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
            m_tls.at(TLS_OFFSET_RCX) = val;
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
            m_tls.at(TLS_OFFSET_RDX) = val;
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
            m_tls.at(TLS_OFFSET_RBP) = val;
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
            m_tls.at(TLS_OFFSET_RSI) = val;
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
            m_tls.at(TLS_OFFSET_RDI) = val;
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
            m_tls.at(TLS_OFFSET_R8) = val;
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
            m_tls.at(TLS_OFFSET_R9) = val;
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
            m_tls.at(TLS_OFFSET_R10) = val;
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
            m_tls.at(TLS_OFFSET_R11) = val;
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
            m_tls.at(TLS_OFFSET_R12) = val;
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
            m_tls.at(TLS_OFFSET_R13) = val;
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
            m_tls.at(TLS_OFFSET_R14) = val;
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
            m_tls.at(TLS_OFFSET_R15) = val;
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
        ///   @brief This syscall tells the microkernel to destroy a VM
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vm_op_destroy_vm(bsl::safe_u16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);

            return m_bf_vm_op_destroy_vm.at(vmid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_destroy_vm.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to destroy
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vm_op_destroy_vm
        ///
        constexpr void
        set_bf_vm_op_destroy_vm(bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_destroy_vm.at(vmid) = errc;
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
        ///   @param vmid The VMID of the VM to map the physical address to
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
        ///   @param vmid The VMID of the VM to map the physical address to
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
        ///   @param vmid The VMID of the VM to unmap the virtual address from
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

            if (!m_bf_vm_op_unmap_direct.at(vmid)) {
                return m_bf_vm_op_unmap_direct.at(vmid);
            }

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete pmut_virt;
            m_direct_map_phys_to_virt.erase({vmid, phys});
            m_direct_map_virt_to_phys.erase({vmid, pmut_virt});

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_unmap_direct.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to unmap the virtual address from
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vm_op_unmap_direct
        ///
        constexpr void
        set_bf_vm_op_unmap_direct(bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_unmap_direct.at(vmid) = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to unmap a previously
        ///     mapped virtual address in the direct map. Unlike
        ///     bf_vm_op_unmap_direct, this syscall performs a broadcast TLB flush
        ///     which means it can be safely used on all direct mapped
        ///     addresses. The downside of using this function is that it can
        ///     be a lot slower than bf_vm_op_unmap_direct, especially on
        ///     systems with a lot of cores.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param vmid The VMID of the VM to unmap the virtual address from
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

            if (!m_bf_vm_op_unmap_direct_broadcast.at(vmid)) {
                return m_bf_vm_op_unmap_direct_broadcast.at(vmid);
            }

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete pmut_virt;
            m_direct_map_phys_to_virt.erase({vmid, phys});
            m_direct_map_virt_to_phys.erase({vmid, pmut_virt});

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vm_op_unmap_direct_broadcast.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to unmap the virtual address from
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vm_op_unmap_direct_broadcast
        ///
        constexpr void
        set_bf_vm_op_unmap_direct_broadcast(
            bsl::safe_u16 const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_unmap_direct_broadcast.at(vmid) = errc;
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
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_create_vp(bsl::safe_u16 const &vmid, bsl::safe_u16 const &ppid) noexcept
            -> bsl::safe_u16
        {
            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vmid) < HYPERVISOR_MAX_VMS);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(ppid) < HYPERVISOR_MAX_PPS);

            return m_bf_vp_op_create_vp.at({vmid, ppid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vp_op_create_vp.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The ID of the VM to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @param vpid the ID to return when executing set_bf_vp_op_create_vp
        ///
        constexpr void
        set_bf_vp_op_create_vp(
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &ppid,
            bsl::safe_u16 const &vpid) noexcept
        {
            m_bf_vp_op_create_vp.at({vmid, ppid}) = vpid;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VP
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The VPID of the VP to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_destroy_vp(bsl::safe_u16 const &vpid) noexcept -> bsl::errc_type
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);

            return m_bf_vp_op_destroy_vp.at(vpid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vp_op_destroy_vp.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The VPID of the VP to destroy
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vp_op_destroy_vp
        ///
        constexpr void
        set_bf_vp_op_destroy_vp(bsl::safe_u16 const &vpid, bsl::errc_type const errc) noexcept
        {
            m_bf_vp_op_destroy_vp.at(vpid) = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to migrate a VP from one PP
        ///     to another PP. This function does not execute the VP (use
        ///     bf_vs_op_run for that), but instead allows bf_vs_op_run to
        ///     execute a VP on a PP that it was not originally assigned to.
        ///
        ///     When a VP is migrated, all of the VSs that are assigned to the
        ///     requested VP are also migrated to this new PP as well. From an
        ///     AMD/Intel point of view, this clears the VMCS/VMCB for each VS
        ///     assigned to the VP. On Intel, it also loads the newly cleared VS
        ///     and sets the launched state to false, ensuring the next
        ///     bf_vs_op_run will use VMLaunch instead of VMResume.
        ///
        ///     It should be noted that the migration of a VS from one PP to
        ///     another does not happen during the execution of this ABI. This
        ///     ABI simply tells the microkernel that the requested VP may now
        ///     execute on the requested PP. This will cause a mismatch between
        ///     the assigned PP for a VP and the assigned PP for a VS. The
        ///     microkernel will detect this mismatch when an extension attempts
        ///     to execute bf_vs_op_run. When this occurs, the microkernel will
        ///     ensure the VP is being run on the PP it was assigned to during
        ///     migration, and then it will check to see if the PP of the VS
        ///     matches. If it doesn't, it will then perform a migration of that
        ///     VS at that time. This ensures that the microkernel is only
        ///     migrations VSs when it needs to, and it ensures the VS is
        ///     cleared an loaded (in the case of Intel) on the PP it will be
        ///     executed on, which is a requirement for VMCS migration. An
        ///     extension can determine which VSs have been migrated by looking
        ///     at the assigned PP of a VS. If it doesn't match the VP it was
        ///     assigned to, it has not been migrated. Finally, an extension is
        ///     free to read/write to the VSs state, even if it has not been
        ///     migrated. The only requirement for migration is execution (meaning
        ///     VMRun/VMLaunch/VMResume).
        ///
        ///     Any additional migration responsibilities, like TSC
        ///     synchronization, must be performed by the extension.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The VPID of the VP to migrate
        ///   @param ppid The ID of the PP to assign the provided VP to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vp_op_migrate(bsl::safe_u16 const &vpid, bsl::safe_u16 const &ppid) noexcept
            -> bsl::errc_type
        {
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vpid) < HYPERVISOR_MAX_VPS);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(ppid) < HYPERVISOR_MAX_PPS);

            return m_bf_vp_op_migrate.at({vpid, ppid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vp_op_migrate.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The VPID of the VP to migrate
        ///   @param ppid The ID of the PP to assign the provided VP to
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vp_op_migrate
        ///
        constexpr void
        set_bf_vp_op_migrate(
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vp_op_migrate.at({vpid, ppid}) = errc;
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
        ///   @brief This syscall tells the microkernel to destroy a VS
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_destroy_vs(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            return m_bf_vs_op_destroy_vs.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_destroy_vs.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to destroy
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_destroy_vs
        ///
        constexpr void
        set_bf_vs_op_destroy_vs(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_destroy_vs.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to initialize a VS using
        ///     the root VP state provided by the loader using the current PPID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to initialize
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_init_as_root(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            return m_bf_vs_op_init_as_root.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_init_as_root.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to initialize
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_init_as_root
        ///
        constexpr void
        set_bf_vs_op_init_as_root(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_init_as_root.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief Reads a CPU register from the VS given a bf_reg_t. Note
        ///     that the bf_reg_t is architecture specific.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to read from
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
        ///   @param vsid The VSID of the VS to read from
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
        ///   @param vsid The VSID of the VS to write to
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

            return m_bf_vs_op_write.at({vsid, reg, value});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_write.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to write to
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
        ///   @brief bf_vs_op_run tells the microkernel to execute a given VS on
        ///     behalf of a given VP and VM. This system call only returns if an
        ///     error occurs. On success, this system call will physically execute
        ///     the requested VM and VP using the requested VS, and the extension
        ///     will only execute again on the next VMExit.
        ///
        ///     Unless an extension needs to change the active VM, VP or VS, the
        ///     extension should use bf_vs_op_run_current instead of
        ///     bf_vs_op_run. bf_vs_op_run is slow as it must perform a series of
        ///     checks to determine if it has any work to perform before execution
        ///     of a VM can occur.
        ///
        ///     Unlike bf_vs_op_run_current which is really just a return to
        ///     microkernel execution, bf_vs_op_run must perform the following
        ///     operations:
        ///     - It first verifies that the provided VM, VP and VS are all
        ///       created. Meaning, and extension must first use the create ABI
        ///       to properly create a VM, VP and VS before it may be used.
        ///     - Next, it must ensure VM, VP and VS assignment is correct. A
        ///       newly created VP and VS are unassigned. Once bf_vs_op_run is
        ///       executed, the VP is assigned to the provided VM and the VS is
        ///       assigned to the provided VP. The VP and VS are also both
        ///       assigned to the PP bf_vs_op_run is executed on. Once these
        ///       assignments take place, an extension cannot change them, and any
        ///       attempt to run a VP or VS on a VM, VP or PP they are not
        ///       assigned to will fail. It is impossible to change the assigned of
        ///       a VM or VP, but an extension can change the assignment of a VP
        ///       and VSs PP by using the bf_vp_op_migrate function.
        ///     - Next, bf_vs_op_run must determine if it needs to migrate a VS
        ///       to the PP the VS is being executed on by bf_vs_op_run. For more
        ///       information about how this works, please see bf_vp_op_migrate.
        ///     - Finally, bf_vs_op_run must ensure the active VM, VP and VS are
        ///       set to the VM, VP and VS provided to this ABI. Any changes in
        ///       the active state could cause additional operations to take place.
        ///       For example, the VS must transfer the TLS state of the general
        ///       purpose registers to its internal cache so that the VS that is
        ///       about to become active can use the TLS block instead.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to run
        ///   @param vpid The VPID of the VP to run
        ///   @param vsid The VSID of the VS to run
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

            return m_bf_vs_op_run.at({vmid, vpid, vsid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_run.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to run
        ///   @param vpid The VPID of the VP to run
        ///   @param vsid The VSID of the VS to run
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
        ///   @brief This syscall tells the microkernel to advance the instruction
        ///     pointer in the requested VS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS advance the IP in
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            return m_bf_vs_op_advance_ip.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_advance_ip.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS advance the IP in
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_advance_ip
        ///
        constexpr void
        set_bf_vs_op_advance_ip(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_advance_ip.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to advance the instruction
        ///     pointer in the currently active VS and run the currently active
        ///     VS, VP and VM (i.e., this combines bf_vs_op_advance_ip and
        ///     bf_vs_op_advance_ip).
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_advance_ip_and_run_current() noexcept -> bsl::errc_type
        {
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
        ///   @brief This syscall tells the microkernel to promote the requested
        ///     VS. This will stop the hypervisor complete on the physical
        ///     processor that this syscall is executed on and replace it's state
        ///     with the state in the VS. Note that this syscall only returns
        ///     on error.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to promote
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_promote(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            return m_bf_vs_op_promote.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_promote.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to promote
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_promote
        ///
        constexpr void
        set_bf_vs_op_promote(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_promote.at(vsid) = errc;
        }

        /// <!-- description -->
        ///   @brief bf_vs_op_clear_vs tells the microkernel to clear the VS's
        ///     hardware cache, if one exists. How this is used depends entirely
        ///     on the hardware and is associated with AMD's VMCB Clean Bits,
        ///     and Intel's VMClear instruction. See the associated documentation
        ///     for more details. On AMD, this ABI clears the entire VMCB. For more
        ///     fine grained control, use the write ABIs to manually modify the
        ///     VMCB.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to clear
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vs_op_clear_vs(bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
        {
            bsl::expects(vsid.is_valid_and_checked());
            bsl::expects(vsid != BF_INVALID_ID);
            bsl::expects(bsl::to_umx(vsid) < HYPERVISOR_MAX_VSS);

            return m_bf_vs_op_clear_vs.at(vsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vs_op_clear_vs.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vsid The VSID of the VS to clear
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vs_op_clear_vs
        ///
        constexpr void
        set_bf_vs_op_clear_vs(bsl::safe_u16 const &vsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vs_op_clear_vs.at(vsid) = errc;
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
        ///   @brief Frees a page previously allocated by bf_mem_op_alloc_page.
        ///     This operation is optional and not all microkernels may implement
        ///     it.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param pmut_virt The virtual address of the page to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_mem_op_free_page(T *const pmut_virt) noexcept -> bsl::errc_type
        {
            bsl::expects(nullptr != pmut_virt);

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            auto const phys{m_alloc_page_virt_to_phys.at(pmut_virt)};
            bsl::expects(phys.is_valid_and_checked());
            bsl::expects(phys.is_pos());

            if (!m_bf_mem_op_free_page) {
                return m_bf_mem_op_free_page;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete pmut_virt;
            bsl::discard(m_alloc_page_phys_to_virt.erase(phys));
            bsl::discard(m_alloc_page_virt_to_phys.erase(pmut_virt));

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_mem_op_free_page.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_mem_op_free_page
        ///
        constexpr void
        set_bf_mem_op_free_page(bsl::errc_type const errc) noexcept
        {
            m_bf_mem_op_free_page = errc;
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

            if (!m_bf_mem_op_alloc_huge) {
                return nullptr;
            }

            m_alloc_huge_phys += HYPERVISOR_PAGE_SIZE * size;
            mut_phys = m_alloc_huge_phys.checked();

            auto *const pmut_virt{new T[size.get()]()};
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
        ///   @brief Frees memory previously allocated by bf_mem_op_alloc_huge.
        ///     This operation is optional and not all microkernels may implement
        ///     it.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of pointer to return. Must be a POD type and
        ///     the size of a page.
        ///   @param pmut_virt The virtual address of the memory to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T>
        [[nodiscard]] constexpr auto
        bf_mem_op_free_huge(T *const pmut_virt) noexcept -> bsl::errc_type
        {
            bsl::expects(nullptr != pmut_virt);

            static_assert(bsl::is_pod<T>::value);
            static_assert(sizeof(T) <= HYPERVISOR_PAGE_SIZE);

            auto const phys{m_alloc_huge_virt_to_phys.at(pmut_virt)};
            bsl::expects(phys.is_valid_and_checked());
            bsl::expects(phys.is_pos());

            if (!m_bf_mem_op_free_huge) {
                return m_bf_mem_op_free_huge;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete[] pmut_virt;
            bsl::discard(m_alloc_huge_phys_to_virt.erase(phys));
            bsl::discard(m_alloc_huge_virt_to_phys.erase(pmut_virt));

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_mem_op_free_huge.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_mem_op_free_huge
        ///
        constexpr void
        set_bf_mem_op_free_huge(bsl::errc_type const errc) noexcept
        {
            m_bf_mem_op_free_huge = errc;
        }
    };
}

#endif

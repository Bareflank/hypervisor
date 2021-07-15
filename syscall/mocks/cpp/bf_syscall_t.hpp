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

#ifndef MOCKS_BF_SYSCALL_T_HPP
#define MOCKS_BF_SYSCALL_T_HPP

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
        bsl::errc_type m_initialize;

        /// @brief stores TLS data
        bsl::unordered_map<bf_uint64_t, bf_uint64_t> m_tls;

        /// @brief stores the results for bf_vm_op_create_vm
        bf_uint16_t m_bf_vm_op_create_vm;
        /// @brief stores the results for bf_vm_op_destroy_vm
        bsl::unordered_map<bf_uint16_t, bsl::errc_type> m_bf_vm_op_destroy_vm;
        /// @brief stores the results for bf_vp_op_create_vp
        bsl::unordered_map<std::tuple<bf_uint16_t, bf_uint16_t>, bf_uint16_t> m_bf_vp_op_create_vp;
        /// @brief stores the results for bf_vp_op_destroy_vp
        bsl::unordered_map<bf_uint16_t, bsl::errc_type> m_bf_vp_op_destroy_vp;
        /// @brief stores the results for bf_vp_op_migrate
        bsl::unordered_map<std::tuple<bf_uint16_t, bf_uint16_t>, bsl::errc_type> m_bf_vp_op_migrate;
        /// @brief stores the results for bf_vps_op_create_vps
        bsl::unordered_map<std::tuple<bf_uint16_t, bf_uint16_t>, bf_uint16_t> m_bf_vps_op_create_vps;
        /// @brief stores the results for bf_vps_op_destroy_vps
        bsl::unordered_map<bf_uint16_t, bsl::errc_type> m_bf_vps_op_destroy_vps;
        /// @brief stores the results for bf_vps_op_init_as_root
        bsl::unordered_map<bf_uint16_t, bsl::errc_type> m_bf_vps_op_init_as_root;
        /// @brief stores the results for bf_vps_op_read
        bsl::unordered_map<std::tuple<bf_uint16_t, bf_reg_t>, bf_uint64_t> m_bf_vps_op_read;
        /// @brief stores the results for bf_vps_op_write
        bsl::unordered_map<std::tuple<bf_uint16_t, bf_reg_t, bf_uint64_t>, bsl::errc_type> m_bf_vps_op_write;
        /// @brief stores the results for bf_vps_op_run
        bsl::unordered_map<std::tuple<bf_uint16_t, bf_uint16_t, bf_uint16_t>, bsl::errc_type> m_bf_vps_op_run;
        /// @brief stores the results for bf_vps_op_run_current
        bsl::errc_type m_bf_vps_op_run_current;
        /// @brief stores the results for bf_vps_op_advance_ip
        bsl::unordered_map<bf_uint16_t, bsl::errc_type> m_bf_vps_op_advance_ip;
        /// @brief stores the results for bf_vps_op_advance_ip_and_run_current
        bsl::errc_type m_bf_vps_op_advance_ip_and_run_current;
        /// @brief stores the results for bf_vps_op_promote
        bsl::unordered_map<bf_uint16_t, bsl::errc_type> m_bf_vps_op_promote;
        /// @brief stores the results for bf_vps_op_clear_vps
        bsl::unordered_map<bf_uint16_t, bsl::errc_type> m_bf_vps_op_clear_vps;
        /// @brief stores the results for bf_intrinsic_op_rdmsr
        bsl::unordered_map<bf_uint32_t, bf_uint64_t> m_bf_intrinsic_op_rdmsr;
        /// @brief stores the results for bf_intrinsic_op_wrmsr
        bsl::unordered_map<std::tuple<bf_uint32_t, bf_uint64_t>, bsl::errc_type> m_bf_intrinsic_op_wrmsr;
        /// @brief stores the results for bf_intrinsic_op_invlpga
        bsl::unordered_map<std::tuple<bf_uint64_t, bf_uint64_t>, bsl::errc_type> m_bf_intrinsic_op_invlpga;
        /// @brief stores the results for bf_intrinsic_op_invept
        bsl::unordered_map<std::tuple<bf_uint64_t, bf_uint64_t>, bsl::errc_type> m_bf_intrinsic_op_invept;
        /// @brief stores the results for bf_intrinsic_op_invvpid
        bsl::unordered_map<std::tuple<bf_uint64_t, bf_uint16_t, bf_uint64_t>, bsl::errc_type> m_bf_intrinsic_op_invvpid;
        /// @brief stores the results for bf_mem_op_alloc_page
        bsl::errc_type m_bf_mem_op_alloc_page;
        /// @brief stores the results for bf_mem_op_free_page
        bsl::errc_type m_bf_mem_op_free_page;
        /// @brief stores the results for bf_mem_op_alloc_huge
        bsl::errc_type m_bf_mem_op_alloc_huge;
        /// @brief stores the results for bf_mem_op_free_huge
        bsl::errc_type m_bf_mem_op_free_huge;

        /// @brief stores a map of allocations and their sizes
        bsl::unordered_map<void *, bf_uint64_t> m_alloc_free_map;
        /// @brief stores the results for bf_read_phys
        bsl::unordered_map<bf_uint64_t, bf_uint64_t> m_read_write_phys_map;
        /// @brief stores a map of virt to phys translations
        bsl::unordered_map<void *, bf_uint64_t> m_virt_to_phys_map;
        /// @brief stores a map of phys to virt translations
        bsl::unordered_map<bf_uint64_t, bsl::uint8 *> m_phys_to_virt_map;

        // clang-format on

    public:
        /// <!-- description -->
        ///   @brief Initializes the bf_syscall_t by opening a handle and
        ///     registering all of the required handlers. If this function
        ///     fails, the handle is closed automatically.
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
            bf_uint32_t const &version,
            bf_callback_handler_bootstrap_t const pmut_bootstrap_handler,
            bf_callback_handler_vmexit_t const pmut_vmexit_handler,
            bf_callback_handler_fail_t const pmut_fail_handler) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!version)) {
                bsl::error() << "invalid version\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(version.is_zero())) {
                bsl::error() << "version cannot be zero\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(nullptr == pmut_bootstrap_handler)) {
                bsl::error() << "invalid bootstrap_handler\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(nullptr == pmut_vmexit_handler)) {
                bsl::error() << "invalid vmexit_handler\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(nullptr == pmut_fail_handler)) {
                bsl::error() << "invalid fail_handler\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

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
        bf_tls_rax() const noexcept -> bf_uint64_t
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
        bf_tls_set_rax(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_RAX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rbx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rbx
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rbx() const noexcept -> bf_uint64_t
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
        bf_tls_set_rbx(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_RBX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rcx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rcx
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rcx() const noexcept -> bf_uint64_t
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
        bf_tls_set_rcx(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_RCX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rdx
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rdx
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rdx() const noexcept -> bf_uint64_t
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
        bf_tls_set_rdx(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_RDX) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rbp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rbp
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rbp() const noexcept -> bf_uint64_t
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
        bf_tls_set_rbp(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_RBP) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rsi
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rsi
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rsi() const noexcept -> bf_uint64_t
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
        bf_tls_set_rsi(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_RSI) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.rdi
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.rdi
        ///
        [[nodiscard]] constexpr auto
        bf_tls_rdi() const noexcept -> bf_uint64_t
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
        bf_tls_set_rdi(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_RDI) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r8
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r8
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r8() const noexcept -> bf_uint64_t
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
        bf_tls_set_r8(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R8) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r9
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r9
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r9() const noexcept -> bf_uint64_t
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
        bf_tls_set_r9(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R9) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r10
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r10
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r10() const noexcept -> bf_uint64_t
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
        bf_tls_set_r10(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R10) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r11
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r11
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r11() const noexcept -> bf_uint64_t
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
        bf_tls_set_r11(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R11) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r12
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r12
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r12() const noexcept -> bf_uint64_t
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
        bf_tls_set_r12(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R12) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r13
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r13
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r13() const noexcept -> bf_uint64_t
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
        bf_tls_set_r13(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R13) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r14
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r14
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r14() const noexcept -> bf_uint64_t
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
        bf_tls_set_r14(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R14) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.r15
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.r15
        ///
        [[nodiscard]] constexpr auto
        bf_tls_r15() const noexcept -> bf_uint64_t
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
        bf_tls_set_r15(bf_uint64_t const &val) noexcept
        {
            if (bsl::unlikely(!val)) {
                bsl::alert() << "invalid val\n" << bsl::here();
                return;
            }

            m_tls.at(TLS_OFFSET_R15) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.extid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.extid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_extid() const noexcept -> bsl::safe_uint16
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
        bf_tls_set_extid(bf_uint16_t const &val) noexcept
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
        bf_tls_vmid() const noexcept -> bsl::safe_uint16
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
        bf_tls_set_vmid(bf_uint16_t const &val) noexcept
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
        bf_tls_vpid() const noexcept -> bsl::safe_uint16
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
        bf_tls_set_vpid(bf_uint16_t const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ACTIVE_VPID) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.vpsid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.vpsid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_vpsid() const noexcept -> bsl::safe_uint16
        {
            return bsl::to_u16(m_tls.at(TLS_OFFSET_ACTIVE_VPSID));
        }

        /// <!-- description -->
        ///   @brief Sets the value of tls.vpsid (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val The value to set tls.vpsid to
        ///
        constexpr void
        bf_tls_set_vpsid(bf_uint16_t const &val) noexcept
        {
            m_tls.at(TLS_OFFSET_ACTIVE_VPSID) = bsl::to_u64(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of tls.ppid
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tls.ppid
        ///
        [[nodiscard]] constexpr auto
        bf_tls_ppid() const noexcept -> bsl::safe_uint16
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
        bf_tls_set_ppid(bf_uint16_t const &val) noexcept
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
        bf_tls_online_pps() const noexcept -> bsl::safe_uint16
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
        bf_tls_set_online_pps(bf_uint16_t const &val) noexcept
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
        bf_vm_op_create_vm() noexcept -> bf_uint16_t
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
        set_bf_vm_op_create_vm(bf_uint16_t const &vmid) noexcept
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
        bf_vm_op_destroy_vm(bf_uint16_t const &vmid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

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
        set_bf_vm_op_destroy_vm(bf_uint16_t const &vmid, bsl::errc_type const errc) noexcept
        {
            m_bf_vm_op_destroy_vm.at(vmid) = errc;
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
        bf_vp_op_create_vp(bf_uint16_t const &vmid, bf_uint16_t const &ppid) noexcept -> bf_uint16_t
        {
            if (bsl::unlikely(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            if (bsl::unlikely(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

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
            bf_uint16_t const &vmid, bf_uint16_t const &ppid, bf_uint16_t const &vpid) noexcept
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
        bf_vp_op_destroy_vp(bf_uint16_t const &vpid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

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
        set_bf_vp_op_destroy_vp(bf_uint16_t const &vpid, bsl::errc_type const errc) noexcept
        {
            m_bf_vp_op_destroy_vp.at(vpid) = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to migrate a VP from one PP
        ///     to another PP. This function does not execute the VP (use
        ///     bf_vps_op_run for that), but instead allows bf_vps_op_run to
        ///     execute a VP on a PP that it was not originally assigned to.
        ///
        ///     When a VP is migrated, all of the VPSs that are assigned to the
        ///     requested VP are also migrated to this new PP as well. From an
        ///     AMD/Intel point of view, this clears the VMCS/VMCB for each VPS
        ///     assigned to the VP. On Intel, it also loads the newly cleared VPS
        ///     and sets the launched state to false, ensuring the next
        ///     bf_vps_op_run will use VMLaunch instead of VMResume.
        ///
        ///     It should be noted that the migration of a VPS from one PP to
        ///     another does not happen during the execution of this ABI. This
        ///     ABI simply tells the microkernel that the requested VP may now
        ///     execute on the requested PP. This will cause a mismatch between
        ///     the assigned PP for a VP and the assigned PP for a VPS. The
        ///     microkernel will detect this mismatch when an extension attempts
        ///     to execute bf_vps_op_run. When this occurs, the microkernel will
        ///     ensure the VP is being run on the PP it was assigned to during
        ///     migration, and then it will check to see if the PP of the VPS
        ///     matches. If it doesn't, it will then perform a migration of that
        ///     VPS at that time. This ensures that the microkernel is only
        ///     migrations VPSs when it needs to, and it ensures the VPS is
        ///     cleared an loaded (in the case of Intel) on the PP it will be
        ///     executed on, which is a requirement for VMCS migration. An
        ///     extension can determine which VPSs have been migrated by looking
        ///     at the assigned PP of a VPS. If it doesn't match the VP it was
        ///     assigned to, it has not been migrated. Finally, an extension is
        ///     free to read/write to the VPSs state, even if it has not been
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
        bf_vp_op_migrate(bf_uint16_t const &vpid, bf_uint16_t const &ppid) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

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
            bf_uint16_t const &vpid, bf_uint16_t const &ppid, bsl::errc_type const errc) noexcept
        {
            m_bf_vp_op_migrate.at({vpid, ppid}) = errc;
        }

        // ---------------------------------------------------------------------
        // bf_vps_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to create a VPS
        ///     and return it's ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to assign the newly created VPS to
        ///   @param ppid The resulting VPSID of the newly created VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_create_vps(bf_uint16_t const &vpid, bf_uint16_t const &ppid) noexcept
            -> bf_uint16_t
        {
            if (bsl::unlikely(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            if (bsl::unlikely(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bf_uint16_t::failure();
            }

            return m_bf_vps_op_create_vps.at({vpid, ppid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_create_vps.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpid The ID of the VP to assign the newly created VPS to
        ///   @param ppid The resulting VPSID of the newly created VPS
        ///   @param vspid the ID to return when executing
        ///     set_bf_vps_op_create_vps
        ///
        constexpr void
        set_bf_vps_op_create_vps(
            bf_uint16_t const &vpid, bf_uint16_t const &ppid, bf_uint16_t const &vspid) noexcept
        {
            m_bf_vps_op_create_vps.at({vpid, ppid}) = vspid;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to destroy a VPS
        ///     given an ID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to destroy
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_destroy_vps(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_vps_op_destroy_vps.at(vpsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_destroy_vps.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to destroy
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_destroy_vps
        ///
        constexpr void
        set_bf_vps_op_destroy_vps(bf_uint16_t const &vpsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_destroy_vps.at(vpsid) = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to initialize a VPS using
        ///     the root VP state provided by the loader using the current PPID.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to initialize
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_init_as_root(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_vps_op_init_as_root.at(vpsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_init_as_root.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to initialize
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_init_as_root
        ///
        constexpr void
        set_bf_vps_op_init_as_root(bf_uint16_t const &vpsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_init_as_root.at(vpsid) = errc;
        }

        /// <!-- description -->
        ///   @brief Reads a CPU register from the VPS given a bf_reg_t. Note
        ///     that the bf_reg_t is architecture specific.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to read from
        ///   @param reg A bf_reg_t defining which register to read
        ///   @return Returns the value read, or bf_uint64_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_read(bf_uint16_t const &vpsid, bf_reg_t const reg) const noexcept -> bf_uint64_t
        {
            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            return m_bf_vps_op_read.at({vpsid, reg});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_read.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to read from
        ///   @param reg A bf_reg_t defining which register to read
        ///   @param value the value to return when executing
        ///     bf_vps_op_read
        ///
        constexpr void
        set_bf_vps_op_read(
            bf_uint16_t const &vpsid, bf_reg_t const reg, bf_uint64_t const &value) noexcept
        {
            m_bf_vps_op_read.at({vpsid, reg}) = value;
        }

        /// <!-- description -->
        ///   @brief Writes to a CPU register in the VPS given a bf_reg_t and the
        ///     value to write. Note that the bf_reg_t is architecture specific.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to write to
        ///   @param reg A bf_reg_t defining which register to write to
        ///   @param value The value to write to the requested register
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_write(
            bf_uint16_t const &vpsid, bf_reg_t const reg, bf_uint64_t const &value) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (m_bf_vps_op_write.at({vpsid, reg, value})) {
                m_bf_vps_op_read.at({vpsid, reg}) = value;
            }
            else {
                bsl::touch();
            }

            return m_bf_vps_op_write.at({vpsid, reg, value});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_write.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to write to
        ///   @param reg A bf_reg_t defining which register to write to
        ///   @param value The value to write to the requested field
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_write
        ///
        constexpr void
        set_bf_vps_op_write(
            bf_uint16_t const &vpsid,
            bf_reg_t const reg,
            bf_uint64_t const &value,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_write.at({vpsid, reg, value}) = errc;
        }

        /// <!-- description -->
        ///   @brief bf_vps_op_run tells the microkernel to execute a given VPS on
        ///     behalf of a given VP and VM. This system call only returns if an
        ///     error occurs. On success, this system call will physically execute
        ///     the requested VM and VP using the requested VPS, and the extension
        ///     will only execute again on the next VMExit.
        ///
        ///     Unless an extension needs to change the active VM, VP or VPS, the
        ///     extension should use bf_vps_op_run_current instead of
        ///     bf_vps_op_run. bf_vps_op_run is slow as it must perform a series of
        ///     checks to determine if it has any work to perform before execution
        ///     of a VM can occur.
        ///
        ///     Unlike bf_vps_op_run_current which is really just a return to
        ///     microkernel execution, bf_vps_op_run must perform the following
        ///     operations:
        ///     - It first verifies that the provided VM, VP and VPS are all
        ///       created. Meaning, and extension must first use the create ABI
        ///       to properly create a VM, VP and VPS before it may be used.
        ///     - Next, it must ensure VM, VP and VPS assignment is correct. A
        ///       newly created VP and VPS are unassigned. Once bf_vps_op_run is
        ///       executed, the VP is assigned to the provided VM and the VPS is
        ///       assigned to the provided VP. The VP and VPS are also both
        ///       assigned to the PP bf_vps_op_run is executed on. Once these
        ///       assignments take place, an extension cannot change them, and any
        ///       attempt to run a VP or VPS on a VM, VP or PP they are not
        ///       assigned to will fail. It is impossible to change the assigned of
        ///       a VM or VP, but an extension can change the assignment of a VP
        ///       and VPSs PP by using the bf_vp_op_migrate function.
        ///     - Next, bf_vps_op_run must determine if it needs to migrate a VPS
        ///       to the PP the VPS is being executed on by bf_vps_op_run. For more
        ///       information about how this works, please see bf_vp_op_migrate.
        ///     - Finally, bf_vps_op_run must ensure the active VM, VP and VPS are
        ///       set to the VM, VP and VPS provided to this ABI. Any changes in
        ///       the active state could cause additional operations to take place.
        ///       For example, the VPS must transfer the TLS state of the general
        ///       purpose registers to its internal cache so that the VPS that is
        ///       about to become active can use the TLS block instead.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to run
        ///   @param vpid The VPID of the VP to run
        ///   @param vpsid The VPSID of the VPS to run
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_run(
            bf_uint16_t const &vmid, bf_uint16_t const &vpid, bf_uint16_t const &vpsid) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!vmid)) {
                bsl::error() << "invalid vmid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_vps_op_run.at({vmid, vpid, vpsid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_run.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmid The VMID of the VM to run
        ///   @param vpid The VPID of the VP to run
        ///   @param vpsid The VPSID of the VPS to run
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_run
        ///
        constexpr void
        set_bf_vps_op_run(
            bf_uint16_t const &vmid,
            bf_uint16_t const &vpid,
            bf_uint16_t const &vpsid,
            bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_run.at({vmid, vpid, vpsid}) = errc;
        }

        /// <!-- description -->
        ///   @brief bf_vps_op_run_current tells the microkernel to execute the
        ///     currently active VPS, VP and VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_run_current() noexcept -> bsl::errc_type
        {
            return m_bf_vps_op_run_current;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_run_current.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_run_current
        ///
        constexpr void
        set_bf_vps_op_run_current(bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_run_current = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to advance the instruction
        ///     pointer in the requested VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS advance the IP in
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_advance_ip(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_vps_op_advance_ip.at(vpsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_advance_ip.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS advance the IP in
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_advance_ip
        ///
        constexpr void
        set_bf_vps_op_advance_ip(bf_uint16_t const &vpsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_advance_ip.at(vpsid) = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to advance the instruction
        ///     pointer in the currently active VPS and run the currently active
        ///     VPS, VP and VM (i.e., this combines bf_vps_op_advance_ip and
        ///     bf_vps_op_advance_ip).
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_advance_ip_and_run_current() noexcept -> bsl::errc_type
        {
            return m_bf_vps_op_advance_ip_and_run_current;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_advance_ip_and_run_current.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_advance_ip_and_run_current
        ///
        constexpr void
        set_bf_vps_op_advance_ip_and_run_current(bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_advance_ip_and_run_current = errc;
        }

        /// <!-- description -->
        ///   @brief This syscall tells the microkernel to promote the requested
        ///     VPS. This will stop the hypervisor complete on the physical
        ///     processor that this syscall is executed on and replace it's state
        ///     with the state in the VPS. Note that this syscall only returns
        ///     on error.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to promote
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_promote(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_vps_op_promote.at(vpsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_promote.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to promote
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_promote
        ///
        constexpr void
        set_bf_vps_op_promote(bf_uint16_t const &vpsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_promote.at(vpsid) = errc;
        }

        /// <!-- description -->
        ///   @brief bf_vps_op_clear_vps tells the microkernel to clear the VPS's
        ///     hardware cache, if one exists. How this is used depends entirely
        ///     on the hardware and is associated with AMD's VMCB Clean Bits,
        ///     and Intel's VMClear instruction. See the associated documentation
        ///     for more details. On AMD, this ABI clears the entire VMCB. For more
        ///     fine grained control, use the write ABIs to manually modify the
        ///     VMCB.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to clear
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_vps_op_clear_vps(bf_uint16_t const &vpsid) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!vpsid)) {
                bsl::error() << "invalid vpsid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_vps_op_clear_vps.at(vpsid);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_vps_op_clear_vps.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param vpsid The VPSID of the VPS to clear
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_vps_op_clear_vps
        ///
        constexpr void
        set_bf_vps_op_clear_vps(bf_uint16_t const &vpsid, bsl::errc_type const errc) noexcept
        {
            m_bf_vps_op_clear_vps.at(vpsid) = errc;
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
        ///   @return Returns the value read, or bf_uint64_t::failure()
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_rdmsr(bf_uint32_t const &msr) const noexcept -> bf_uint64_t
        {
            if (bsl::unlikely(!msr)) {
                bsl::error() << "invalid msr\n" << bsl::here();
                return bf_uint64_t::failure();
            }

            return m_bf_intrinsic_op_rdmsr.at(msr);
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_intrinsic_op_rdmsr.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to read
        ///   @param value the value to return when executing
        ///     bf_intrinsic_op_rdmsr
        ///
        constexpr void
        set_bf_intrinsic_op_rdmsr(bf_uint32_t const &msr, bf_uint64_t const &value) noexcept
        {
            m_bf_intrinsic_op_rdmsr.at(msr) = value;
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
        ///   @param value The value to write to the requested MSR
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_wrmsr(bf_uint32_t const &msr, bf_uint64_t const &value) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!msr)) {
                bsl::error() << "invalid msr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!value)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (m_bf_intrinsic_op_wrmsr.at({msr, value})) {
                m_bf_intrinsic_op_rdmsr.at(msr) = value;
            }
            else {
                bsl::touch();
            }

            return m_bf_intrinsic_op_wrmsr.at({msr, value});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_intrinsic_op_wrmsr.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr The address of the MSR to write to
        ///   @param value The value to write to the requested MSR
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_intrinsic_op_wrmsr
        ///
        constexpr void
        set_bf_intrinsic_op_wrmsr(
            bf_uint32_t const &msr, bf_uint64_t const &value, bsl::errc_type const errc) noexcept
        {
            m_bf_intrinsic_op_wrmsr.at({msr, value}) = errc;
        }

        /// <!-- description -->
        ///   @brief Invalidates the TLB mapping for a given virtual page and a
        ///     given ASID. Note that this is specific to AMD only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr The address to invalidate
        ///   @param asid The ASID to invalidate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_invlpga(bf_uint64_t const &addr, bf_uint64_t const &asid) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!addr)) {
                bsl::error() << "invalid addr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!asid)) {
                bsl::error() << "invalid asid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_intrinsic_op_invlpga.at({addr, asid});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_intrinsic_op_invlpga.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr The address to invalidate
        ///   @param asid The ASID to invalidate
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_intrinsic_op_invlpga
        ///
        constexpr void
        set_bf_intrinsic_op_invlpga(
            bf_uint64_t const &addr, bf_uint64_t const &asid, bsl::errc_type const errc) noexcept
        {
            m_bf_intrinsic_op_invlpga.at({addr, asid}) = errc;
        }

        /// <!-- description -->
        ///   @brief Invalidates mappings in the translation lookaside buffers
        ///     (TLBs) and paging-structure caches that were derived from extended
        ///     page tables (EPT). Note that this is specific to Intel only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param eptp The EPTP to invalidate
        ///   @param type The INVEPT type (see the Intel SDM for details)
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_invept(bf_uint64_t const &eptp, bf_uint64_t const &type) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!eptp)) {
                bsl::error() << "invalid eptp\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!type)) {
                bsl::error() << "invalid type\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_intrinsic_op_invept.at({eptp, type});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_intrinsic_op_invept.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param eptp The EPTP to invalidate
        ///   @param type The INVEPT type (see the Intel SDM for details)
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_intrinsic_op_invept
        ///
        constexpr void
        set_bf_intrinsic_op_invept(
            bf_uint64_t const &eptp, bf_uint64_t const &type, bsl::errc_type const errc) noexcept
        {
            m_bf_intrinsic_op_invept.at({eptp, type}) = errc;
        }

        /// <!-- description -->
        ///   @brief Invalidates mappings in the translation lookaside buffers
        ///     (TLBs) and paging-structure caches based on virtual-processor
        ///     identifier (VPID). Note that this is specific to Intel only.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr The address to invalidate
        ///   @param vpid The VPID to invalidate
        ///   @param type The INVVPID type (see the Intel SDM for details)
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_intrinsic_op_invvpid(
            bf_uint64_t const &addr, bf_uint16_t const &vpid, bf_uint64_t const &type) noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(!addr)) {
                bsl::error() << "invalid addr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!type)) {
                bsl::error() << "invalid type\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            return m_bf_intrinsic_op_invvpid.at({addr, vpid, type});
        }

        /// <!-- description -->
        ///   @brief Sets the return value of bf_intrinsic_op_invvpid.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr The address to invalidate
        ///   @param vpid The VPID to invalidate
        ///   @param type The INVVPID type (see the Intel SDM for details)
        ///   @param errc the bsl::errc_type to return when executing
        ///     bf_intrinsic_op_invvpid
        ///
        constexpr void
        set_bf_intrinsic_op_invvpid(
            bf_uint64_t const &addr,
            bf_uint16_t const &vpid,
            bf_uint64_t const &type,
            bsl::errc_type const errc) noexcept
        {
            m_bf_intrinsic_op_invvpid.at({addr, vpid, type}) = errc;
        }

        // ---------------------------------------------------------------------
        // bf_mem_ops
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_page allocates a page, and maps this page
        ///     into the direct map of the VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_phys The mut_physical address of the resulting page
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_page(bf_uint64_t &mut_phys) noexcept -> void *
        {
            if (bsl::unlikely(!mut_phys)) {
                bsl::error() << "invalid mut_phys\n" << bsl::here();
                return nullptr;
            }

            if (!m_bf_mem_op_alloc_page) {
                return nullptr;
            }

            auto *const pmut_virt{new bsl::uint8[HYPERVISOR_PAGE_SIZE.get()]};
            m_alloc_free_map.at(pmut_virt) = HYPERVISOR_PAGE_SIZE;

            mut_phys = (m_alloc_free_map.size() * HYPERVISOR_PAGE_SIZE);
            m_virt_to_phys_map.at(pmut_virt) = mut_phys;
            m_phys_to_virt_map.at(mut_phys) = pmut_virt;

            return pmut_virt;
        }

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_page allocates a page, and maps this page
        ///     into the direct map of the VM.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_page() noexcept -> void *
        {
            bf_uint64_t mut_ignored{};
            return this->bf_mem_op_alloc_page(mut_ignored);
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
        ///   @param pmut_addr The virtual address of the page to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_free_page(void *const pmut_addr) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(nullptr == pmut_addr)) {
                bsl::error() << "pmut_addr is a nullptr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (!m_bf_mem_op_free_page) {
                return m_bf_mem_op_free_page;
            }

            if (m_alloc_free_map.at(pmut_addr).is_zero()) {
                return bsl::errc_failure;
            }

            auto const phys{m_virt_to_phys_map.at(pmut_addr)};
            auto *const pmut_virt{m_phys_to_virt_map.at(phys)};
            m_virt_to_phys_map.at(pmut_virt) = {};
            m_phys_to_virt_map.at(phys) = {};

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete[] pmut_virt;    // GRCOV_EXCLUDE_BR
            m_alloc_free_map.at(pmut_virt) = {};

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
        ///   @param size The total number of bytes to allocate
        ///   @param mut_phys The physical address of the resulting memory
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_huge(bf_uint64_t const &size, bf_uint64_t &mut_phys) noexcept -> void *
        {
            if (bsl::unlikely(!size)) {
                bsl::error() << "invalid size\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(size.is_zero())) {
                bsl::error() << "size cannot be 0\n" << bsl::here();
                return nullptr;
            }

            if (bsl::unlikely(!mut_phys)) {
                bsl::error() << "invalid mut_phys\n" << bsl::here();
                return nullptr;
            }

            if (!m_bf_mem_op_alloc_huge) {
                return nullptr;
            }

            auto *const pmut_virt{new bsl::uint8[size.get()]};
            m_alloc_free_map.at(pmut_virt) = size;

            mut_phys = (m_alloc_free_map.size() * HYPERVISOR_PAGE_SIZE);
            m_virt_to_phys_map.at(pmut_virt) = mut_phys;
            m_phys_to_virt_map.at(mut_phys) = pmut_virt;

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
        ///   @param size The total number of bytes to allocate
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_alloc_huge(bf_uint64_t const &size) noexcept -> void *
        {
            bf_uint64_t mut_ignored{};
            return this->bf_mem_op_alloc_huge(size, mut_ignored);
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
        ///   @param pmut_addr The virtual address of the memory to free
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        bf_mem_op_free_huge(void *const pmut_addr) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(nullptr == pmut_addr)) {
                bsl::error() << "pmut_addr is a nullptr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (!m_bf_mem_op_free_huge) {
                return m_bf_mem_op_free_huge;
            }

            if (m_alloc_free_map.at(pmut_addr).is_zero()) {
                return bsl::errc_failure;
            }

            auto const phys{m_virt_to_phys_map.at(pmut_addr)};
            auto *const pmut_virt{m_phys_to_virt_map.at(phys)};
            m_virt_to_phys_map.at(pmut_virt) = {};
            m_phys_to_virt_map.at(phys) = {};

            // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
            delete[] pmut_virt;    // GRCOV_EXCLUDE_BR
            m_alloc_free_map.at(pmut_virt) = {};

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

        /// <!-- description -->
        ///   @brief bf_mem_op_alloc_heap allocates heap memory. When allocating
        ///     heap memory, the extension should keep in mind the following:
        ///       - This ABI is designed to work similar to sbrk() to support
        ///         malloc/free implementations common with existing open source
        ///         libraries.
        ///       - Calling this ABI with with a size of 0 will return the current
        ///         heap location.
        ///       - Calling this ABI with a size (in bytes) will result in return
        ///         the previous heap location. The current heap location will be
        ///         set to the previous location, plus the provide size, rounded to
        ///         the nearest page size.
        ///       - The heap is not mapped into the direct map, so virtual to
        ///         physical (and vice versa) translations are not possible.
        ///       - There is no ability to free heap memory
        ///
        /// <!-- inputs/outputs -->
        ///   @param size The number of bytes to increase the heap by
        ///   @return Returns a pointer to the newly allocated memory on success,
        ///     or a nullptr on failure.
        ///
        [[nodiscard]] static constexpr auto
        bf_mem_op_alloc_heap(bf_uint64_t const &size) noexcept -> void *
        {
            bsl::discard(size);

            /// NOTE:
            /// - This API is currently not supported by this unit test
            ///   library. This API is designed to support the implementation
            ///   of a malloc/free engine, and mimics sbrk(). To implement
            ///   this, the unit test would have to provide a contiguous
            ///   memory block that doesn't change, but can grow, at least
            ///   enough for the unit tests.
            /// - In general, any code that is using this API would generally
            ///   be using whatever malloc/free engine this API is designed
            ///   to support, so during a unit test, malloc/free can simply
            ///   be used (or hopefully new/delete so that constexpr unit tests
            ///   can still be used). As a result, the only actual code that
            ///   would need this for testing would be the malloc/free engine.
            /// - To unit test that code, simply set up the code to use sbrk()
            ///   and don't include a libc in your example (or at least do not
            ///   perform any allocations using malloc/free from libc).
            /// - Due to the ability to set up unit tests to get 100% without
            ///   actually needing to use this API directly, we do not provide
            ///   it and instead encourage the above approach as needed.
            /// - Code that doesn't use a heap does not need to worry about
            ///   any of this, and instead can use the page allocation APIs
            ///   above for doing a full memory analysis during unit testing.
            ///

            bsl::error() << "bf_mem_op_alloc_heap not supported\n" << bsl::here();
            return nullptr;
        }

        // ---------------------------------------------------------------------
        // direct map helpers
        // ---------------------------------------------------------------------

        /// <!-- description -->
        ///   @brief Returns the value at the provided physical address
        ///     on success, or returns bsl::safe_integral<T>::failure()
        ///     on failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of integral to read
        ///   @param phys the physical address to read
        ///   @return Returns the value at the provided physical address
        ///     on success, or returns bsl::safe_integral<T>::failure()
        ///     on failure.
        ///
        template<typename T = bsl::uintmax>
        [[nodiscard]] constexpr auto
        bf_read_phys(bf_uint64_t const &phys) const noexcept -> bsl::safe_integral<T>
        {
            static_assert(bsl::is_unsigned<T>::value);

            if (bsl::unlikely(!phys)) {
                bsl::error() << "invalid phys\n" << bsl::here();
                return bsl::safe_integral<T>::failure();
            }

            if (bsl::unlikely(phys.is_zero())) {
                bsl::error() << "phys is a nullptr\n" << bsl::here();
                return bsl::safe_integral<T>::failure();
            }

            auto const virt{phys + HYPERVISOR_EXT_DIRECT_MAP_ADDR};
            if (bsl::unlikely(!virt)) {
                bsl::error() << "bf_read_phys failed due to invalid physical address "    // --
                             << bsl::hex(phys) << bsl::endl                               // --
                             << bsl::here();

                return bsl::safe_integral<T>::failure();
            }

            return bsl::convert<T>(m_read_write_phys_map.at(phys));
        }

        /// <!-- description -->
        ///   @brief Writes the provided value at the provided physical address
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of integral to write
        ///   @param phys the physical address to write
        ///   @param val the value to write to the provided physical address
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename T = bsl::uintmax>
        [[nodiscard]] constexpr auto
        bf_write_phys(bf_uint64_t const &phys, bsl::safe_integral<T> const &val) noexcept
            -> bsl::errc_type
        {
            static_assert(bsl::is_unsigned<T>::value);

            if (bsl::unlikely(!phys)) {
                bsl::error() << "invalid phys\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(phys.is_zero())) {
                bsl::error() << "phys is a nullptr\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val\n" << bsl::here();
                return bsl::errc_invalid_argument;
            }

            auto const virt{phys + HYPERVISOR_EXT_DIRECT_MAP_ADDR};
            if (bsl::unlikely(!virt)) {
                bsl::error() << "bf_write_phys failed due to invalid physical address "    // --
                             << bsl::hex(phys) << bsl::endl                                // --
                             << bsl::here();

                return bsl::errc_failure;
            }

            m_read_write_phys_map.at(phys) = bsl::to_u64(val);
            return bsl::errc_success;
        }
    };
}

#endif

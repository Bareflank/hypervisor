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

#ifndef MOCKS_BF_SYSCALL_IMPL_HPP
#define MOCKS_BF_SYSCALL_IMPL_HPP

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <bf_types.hpp>
#include <iomanip>
#include <iostream>

#include <bsl/char_type.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/discard.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unordered_map.hpp>

#pragma clang diagnostic ignored "-Wglobal-constructors"
#pragma clang diagnostic ignored "-Wexit-time-destructors"

namespace syscall
{
    /// NOTE:
    /// - In general, this set of mocked "impl" APIs should not be used
    ///   directly. Most of these APIs should be used through the bf_syscall_t
    ///   wrapper, and the mocked version of that wrapper should be used
    ///   instead as it was far more capable.
    /// - There are some APIs in this library that provide some facilities.
    ///   These specifically include the control ops and the debug ops.
    ///   The syscall library provides these ops outside of the bf_syscall_t
    ///   so that they can be used by an extension on their own.
    /// - The control ops APIs should only be used in a single unit test
    ///   designed to ensure the main.cpp (or whatever file the entry points
    ///   are located in) are tested as this is the only file that should
    ///   contain these control ops.
    /// - The debug ops should only be used by whatever runtime library is
    ///   used. This runtime library will provide the logic for how to
    ///   handle the platform BSL functions. All other extension logic can
    ///   simply use the BSL as it is, as the BSL already provides platform
    ///   support for Windows and Linux which is what the unit tests will
    ///   run on, meaning these libraries are only needed to support unit
    ///   testing of the code that implements the syscall version of the
    ///   BSL platform logic.
    ///

    // -------------------------------------------------------------------------
    // global variables used by the impl mocks
    // -------------------------------------------------------------------------

    /// @brief stores the data to return for an API
    constinit inline bsl::unordered_map<std::string, bsl::safe_uint64>
        g_mut_data{};    // GRCOV_EXCLUDE_BR
    /// @brief stores the error code to return for an API
    constinit inline bsl::unordered_map<std::string, bf_status_t>
        g_mut_errc{};    // GRCOV_EXCLUDE_BR
    /// @brief stores the pointers to return for an API
    constinit inline bsl::unordered_map<std::string, void *> g_mut_ptrs{};    // GRCOV_EXCLUDE_BR

    /// @brief stores whether or not bf_control_op_exit_impl was executed
    constinit inline bool g_mut_bf_control_op_exit_impl_executed{};
    /// @brief stores whether or not bf_control_op_wait_impl was executed
    constinit inline bool g_mut_bf_control_op_wait_impl_executed{};

    /// @brief stores whether or not bf_debug_op_out_impl was executed
    constinit inline bool g_mut_bf_debug_op_out_impl_executed{};
    /// @brief stores whether or not bf_debug_op_dump_vm_impl was executed
    constinit inline bool g_mut_bf_debug_op_dump_vm_impl_executed{};
    /// @brief stores whether or not bf_debug_op_dump_vp_impl was executed
    constinit inline bool g_mut_bf_debug_op_dump_vp_impl_executed{};
    /// @brief stores whether or not bf_debug_op_dump_vps_impl was executed
    constinit inline bool g_mut_bf_debug_op_dump_vps_impl_executed{};
    /// @brief stores whether or not bf_debug_op_dump_vmexit_log_impl was executed
    constinit inline bool g_mut_bf_debug_op_dump_vmexit_log_impl_executed{};
    /// @brief stores whether or not bf_debug_op_write_c_impl was executed
    constinit inline bool g_mut_bf_debug_op_write_c_impl_executed{};
    /// @brief stores whether or not bf_debug_op_write_str_impl was executed
    constinit inline bool g_mut_bf_debug_op_write_str_impl_executed{};
    /// @brief stores whether or not bf_debug_op_dump_ext_impl was executed
    constinit inline bool g_mut_bf_debug_op_dump_ext_impl_executed{};
    /// @brief stores whether or not bf_debug_op_dump_page_pool_impl was executed
    constinit inline bool g_mut_bf_debug_op_dump_page_pool_impl_executed{};
    /// @brief stores whether or not bf_debug_op_dump_huge_pool_impl was executed
    constinit inline bool g_mut_bf_debug_op_dump_huge_pool_impl_executed{};

    // -------------------------------------------------------------------------
    // dummy callbacks
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements a dummy bootstrap entry function.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ppid the physical process to bootstrap
    ///
    extern "C" inline void
    dummy_bootstrap_entry(bsl::safe_uint16::value_type const ppid) noexcept
    {
        bsl::discard(ppid);
    }

    /// <!-- description -->
    ///   @brief Implements a dummy VMExit entry function.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid the ID of the VPS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    extern "C" inline void
    dummy_vmexit_entry(
        bsl::safe_uint16::value_type const vpsid,
        bsl::safe_uint64::value_type const exit_reason) noexcept
    {
        bsl::discard(vpsid);
        bsl::discard(exit_reason);
    }

    /// <!-- description -->
    ///   @brief Implements a dummy fast fail entry function.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid the ID of the VPS that generated the fail
    ///   @param fail_reason the exit reason associated with the fail
    ///
    extern "C" inline void
    dummy_fail_entry(
        bsl::safe_uint16::value_type const vpsid,
        syscall::bf_status_t::value_type const fail_reason) noexcept
    {
        bsl::discard(vpsid);
        bsl::discard(fail_reason);
    }

    // -------------------------------------------------------------------------
    // TLS ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_rax_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_rax").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_rax_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_rax") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_rbx_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_rbx").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_rbx_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_rbx") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_rcx_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_rcx").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_rcx_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_rcx") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_rdx_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_rdx").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_rdx_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_rdx") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_rbp_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_rbp").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_rbp_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_rbp") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_rsi_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_rsi").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_rsi_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_rsi") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_rdi_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_rdi").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_rdi_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_rdi") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r8_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r8").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r8_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r8") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r9_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r9").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r9_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r9") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r10_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r10").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r10_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r10") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r11_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r11").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r11_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r11") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r12_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r12").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r12_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r12") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r13_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r13").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r13_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r13") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r14_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r14").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r14_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r14") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_r15_impl() noexcept -> bsl::safe_uint64::value_type
    {
        return g_mut_data.at("bf_tls_r15").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" inline void
    bf_tls_set_r15_impl(bsl::safe_uint64::value_type const val) noexcept
    {
        g_mut_data.at("bf_tls_r15") = val;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_extid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_extid_impl() noexcept -> bsl::safe_uint16::value_type
    {
        return bsl::to_u16(g_mut_data.at("bf_tls_extid")).get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vmid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_vmid_impl() noexcept -> bsl::safe_uint16::value_type
    {
        return bsl::to_u16(g_mut_data.at("bf_tls_vmid")).get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vpid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_vpid_impl() noexcept -> bsl::safe_uint16::value_type
    {
        return bsl::to_u16(g_mut_data.at("bf_tls_vpid")).get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vpsid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_vpsid_impl() noexcept -> bsl::safe_uint16::value_type
    {
        return bsl::to_u16(g_mut_data.at("bf_tls_vpsid")).get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_ppid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_ppid_impl() noexcept -> bsl::safe_uint16::value_type
    {
        return bsl::to_u16(g_mut_data.at("bf_tls_ppid")).get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_online_pps.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_tls_online_pps_impl() noexcept -> bsl::safe_uint16::value_type
    {
        return bsl::to_u16(g_mut_data.at("bf_tls_online_pps")).get();
    }

    // -------------------------------------------------------------------------
    // bf_control_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_control_op_exit.
    ///
    extern "C" inline void
    bf_control_op_exit_impl() noexcept
    {
        g_mut_bf_control_op_exit_impl_executed = true;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_control_op_wait.
    ///
    extern "C" inline void
    bf_control_op_wait_impl() noexcept
    {
        g_mut_bf_control_op_wait_impl_executed = true;
    }

    // -------------------------------------------------------------------------
    // bf_handle_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_handle_op_open_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_handle_op_open_handle_impl(
        bsl::safe_uint32::value_type const reg0_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_handle_op_open_handle_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = g_mut_data.at("bf_handle_op_open_handle_impl_reg0_out").get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_handle_op_open_handle_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_handle_op_close_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_handle_op_close_handle_impl(bsl::safe_uint64::value_type const reg0_in) noexcept
        -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        return g_mut_errc.at("bf_handle_op_close_handle_impl").get();
    }

    // -------------------------------------------------------------------------
    // bf_debug_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_out.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///
    extern "C" inline void
    bf_debug_op_out_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in) noexcept
    {
        g_mut_bf_debug_op_out_impl_executed = true;
        // NOLINTNEXTLINE(bsl-function-name-use)
        std::cout << std::hex << "0x" << reg0_in << " 0x" << reg1_in << '\n';
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_dump_vm_impl(bsl::safe_uint16::value_type const reg0_in) noexcept
    {
        g_mut_bf_debug_op_dump_vm_impl_executed = true;
        // NOLINTNEXTLINE(bsl-function-name-use)
        std::cout << std::hex << "vm [0x" << reg0_in << "] dump: mock empty\n";
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_dump_vp_impl(bsl::safe_uint16::value_type const reg0_in) noexcept
    {
        g_mut_bf_debug_op_dump_vp_impl_executed = true;
        // NOLINTNEXTLINE(bsl-function-name-use)
        std::cout << std::hex << "vp [0x" << reg0_in << "] dump: mock empty\n";
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_dump_vps_impl(bsl::safe_uint16::value_type const reg0_in) noexcept
    {
        g_mut_bf_debug_op_dump_vps_impl_executed = true;
        // NOLINTNEXTLINE(bsl-function-name-use)
        std::cout << std::hex << "vps [0x" << reg0_in << "] dump: mock empty\n";
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vmexit_log.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_dump_vmexit_log_impl(bsl::safe_uint16::value_type const reg0_in) noexcept
    {
        g_mut_bf_debug_op_dump_vmexit_log_impl_executed = true;
        // NOLINTNEXTLINE(bsl-function-name-use)
        std::cout << std::hex << "vmexit log for pp [0x" << reg0_in << "]: mock empty\n";
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_c.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_write_c_impl(bsl::char_type const reg0_in) noexcept
    {
        g_mut_bf_debug_op_write_c_impl_executed = true;
        std::cout << reg0_in;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_str.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_write_str_impl(bsl::char_type const *const reg0_in) noexcept
    {
        g_mut_bf_debug_op_write_str_impl_executed = true;
        std::cout << reg0_in;
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_ext.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" inline void
    bf_debug_op_dump_ext_impl(bsl::safe_uint16::value_type const reg0_in) noexcept
    {
        g_mut_bf_debug_op_dump_ext_impl_executed = true;
        // NOLINTNEXTLINE(bsl-function-name-use)
        std::cout << std::hex << "ext [0x" << reg0_in << "] dump: mock empty\n";
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_page_pool.
    ///
    extern "C" inline void
    bf_debug_op_dump_page_pool_impl() noexcept
    {
        g_mut_bf_debug_op_dump_page_pool_impl_executed = true;
        std::cout << "page pool dump: mock empty\n";
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_huge_pool.
    ///
    extern "C" inline void
    bf_debug_op_dump_huge_pool_impl() noexcept
    {
        g_mut_bf_debug_op_dump_huge_pool_impl_executed = true;
        std::cout << "huge pool dump: mock empty\n";
    }

    // -------------------------------------------------------------------------
    // bf_callback_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_bootstrap.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_callback_op_register_bootstrap_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bf_callback_handler_bootstrap_t const pmut_reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(pmut_reg1_in);

        return g_mut_errc.at("bf_callback_op_register_bootstrap_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_vmexit.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_callback_op_register_vmexit_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bf_callback_handler_vmexit_t const pmut_reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(pmut_reg1_in);

        return g_mut_errc.at("bf_callback_op_register_vmexit_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_fail.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_callback_op_register_fail_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bf_callback_handler_fail_t const pmut_reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(pmut_reg1_in);

        return g_mut_errc.at("bf_callback_op_register_fail_impl").get();
    }

    // -------------------------------------------------------------------------
    // bf_vm_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_create_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vm_op_create_vm_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_vm_op_create_vm_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = bsl::to_u16(g_mut_data.at("bf_vm_op_create_vm_impl_reg0_out")).get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_vm_op_create_vm_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_destroy_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vm_op_destroy_vm_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        return g_mut_errc.at("bf_vm_op_destroy_vm_impl").get();
    }

    // -------------------------------------------------------------------------
    // bf_vp_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_create_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vp_op_create_vp_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint16::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_vp_op_create_vp_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = bsl::to_u16(g_mut_data.at("bf_vp_op_create_vp_impl_reg0_out")).get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_vp_op_create_vp_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_destroy_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vp_op_destroy_vp_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        return g_mut_errc.at("bf_vp_op_destroy_vp_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_migrate.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vp_op_migrate_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);

        return g_mut_errc.at("bf_vp_op_migrate_impl").get();
    }

    // -------------------------------------------------------------------------
    // bf_vps_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_create_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_create_vps_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint16::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_vps_op_create_vps_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = bsl::to_u16(g_mut_data.at("bf_vps_op_create_vps_impl_reg0_out")).get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_vps_op_create_vps_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_destroy_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_destroy_vps_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        return g_mut_errc.at("bf_vps_op_destroy_vps_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_init_as_root.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_init_as_root_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        return g_mut_errc.at("bf_vps_op_init_as_root_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_read_impl.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_read_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bf_reg_t const reg2_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_vps_op_read_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = g_mut_data.at("bf_vps_op_read_impl_reg0_out").get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_vps_op_read_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_write.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_write_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bf_reg_t const reg2_in,
        bsl::safe_uint64::value_type const reg3_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);

        if (g_mut_errc.at("bf_vps_op_write_impl") == BF_STATUS_SUCCESS) {
            g_mut_data.at("bf_vps_op_write_impl") = bsl::to_u64(reg3_in);
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_vps_op_write_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_run.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_run_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint16::value_type const reg3_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);
        bsl::discard(reg3_in);

        return g_mut_errc.at("bf_vps_op_run_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_run_current_impl(bsl::safe_uint64::value_type const reg0_in) noexcept
        -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        return g_mut_errc.at("bf_vps_op_run_current_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_advance_ip.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_advance_ip_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        return g_mut_errc.at("bf_vps_op_advance_ip_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_advance_ip_and_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_advance_ip_and_run_current_impl(bsl::safe_uint64::value_type const reg0_in) noexcept
        -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        return g_mut_errc.at("bf_vps_op_advance_ip_and_run_current_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_promote.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_promote_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        return g_mut_errc.at("bf_vps_op_promote_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_clear_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_vps_op_clear_vps_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        return g_mut_errc.at("bf_vps_op_clear_vps_impl").get();
    }

    // -------------------------------------------------------------------------
    // bf_intrinsic_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_rdmsr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_intrinsic_op_rdmsr_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint32::value_type const reg1_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_intrinsic_op_rdmsr_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = g_mut_data.at("bf_intrinsic_op_rdmsr_impl_reg0_out").get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_intrinsic_op_rdmsr_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_wrmsr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_intrinsic_op_wrmsr_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint32::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        if (g_mut_errc.at("bf_intrinsic_op_wrmsr_impl") == BF_STATUS_SUCCESS) {
            g_mut_data.at("bf_intrinsic_op_wrmsr_impl") = bsl::to_u64(reg2_in);
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_intrinsic_op_wrmsr_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invlpga.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_intrinsic_op_invlpga_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);

        return g_mut_errc.at("bf_intrinsic_op_invlpga_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invept.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_intrinsic_op_invept_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);

        return g_mut_errc.at("bf_intrinsic_op_invept_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invvpid.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @param reg3_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_intrinsic_op_invvpid_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint64::value_type const reg3_in) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);
        bsl::discard(reg2_in);
        bsl::discard(reg3_in);

        return g_mut_errc.at("bf_intrinsic_op_invvpid_impl").get();
    }

    // -------------------------------------------------------------------------
    // bf_mem_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_alloc_page.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @param pmut_reg1_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_mem_op_alloc_page_impl(
        bsl::safe_uint64::value_type const reg0_in,
        void **const pmut_reg0_out,
        bsl::safe_uint64::value_type *const pmut_reg1_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (bsl::unlikely(nullptr == pmut_reg1_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_mem_op_alloc_page_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = g_mut_ptrs.at("bf_mem_op_alloc_page_impl_reg0_out");
            *pmut_reg1_out = g_mut_data.at("bf_mem_op_alloc_page_impl_reg1_out").get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_mem_op_alloc_page_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_free_page.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_mem_op_free_page_impl(
        bsl::safe_uint64::value_type const reg0_in, void *const pmut_reg1_in) noexcept
        -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(pmut_reg1_in);

        return g_mut_errc.at("bf_mem_op_free_page_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_alloc_huge.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @param pmut_reg1_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_mem_op_alloc_huge_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        void **const pmut_reg0_out,
        bsl::safe_uint64::value_type *const pmut_reg1_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (bsl::unlikely(nullptr == pmut_reg1_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_mem_op_alloc_huge_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = g_mut_ptrs.at("bf_mem_op_alloc_huge_impl_reg0_out");
            *pmut_reg1_out = g_mut_data.at("bf_mem_op_alloc_huge_impl_reg1_out").get();
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_mem_op_alloc_huge_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_free_huge.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_mem_op_free_huge_impl(
        bsl::safe_uint64::value_type const reg0_in, void *const pmut_reg1_in) noexcept
        -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(pmut_reg1_in);

        return g_mut_errc.at("bf_mem_op_free_huge_impl").get();
    }

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_alloc_heap.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] inline auto
    bf_mem_op_alloc_heap_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        void **const pmut_reg0_out) noexcept -> bf_status_t::value_type
    {
        bsl::discard(reg0_in);
        bsl::discard(reg1_in);

        if (bsl::unlikely(nullptr == pmut_reg0_out)) {
            return BF_STATUS_FAILURE_UNKNOWN.get();
        }

        if (g_mut_errc.at("bf_mem_op_alloc_heap_impl") == BF_STATUS_SUCCESS) {
            *pmut_reg0_out = g_mut_ptrs.at("bf_mem_op_alloc_heap_impl_reg0_out");
        }
        else {
            bsl::touch();
        }

        return g_mut_errc.at("bf_mem_op_alloc_heap_impl").get();
    }
}

#endif

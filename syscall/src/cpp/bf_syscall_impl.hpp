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

#ifndef BF_SYSCALL_IMPL_HPP
#define BF_SYSCALL_IMPL_HPP

#include <bf_reg_t.hpp>
#include <bf_types.hpp>

#include <bsl/char_type.hpp>
#include <bsl/cstr_type.hpp>

namespace syscall
{
    // -------------------------------------------------------------------------
    // TLS ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rax_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rax.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rax_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rbx_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rbx_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rcx_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rcx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rcx_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rdx_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdx.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rdx_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rbp_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rbp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rbp_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rsi_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rsi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rsi_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_rdi_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_rdi.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_rdi_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r8_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r8.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r8_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r9_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r9.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r9_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r10_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r10.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r10_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r11_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r11.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r11_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r12_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r12.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r12_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r13_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r13.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r13_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r14_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r14.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r14_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_r15_impl() noexcept -> bsl::safe_uint64::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_set_r15.
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void bf_tls_set_r15_impl(bsl::safe_uint64::value_type const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_extid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_extid_impl() noexcept -> bsl::safe_uint16::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vmid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_vmid_impl() noexcept -> bsl::safe_uint16::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vpid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_vpid_impl() noexcept -> bsl::safe_uint16::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_vpsid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_vpsid_impl() noexcept -> bsl::safe_uint16::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_ppid.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_ppid_impl() noexcept -> bsl::safe_uint16::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_tls_online_pps.
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_tls_online_pps_impl() noexcept -> bsl::safe_uint16::value_type;

    // -------------------------------------------------------------------------
    // bf_control_ops
    // -------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_control_op_exit.
    ///
    extern "C" void bf_control_op_exit_impl() noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_control_op_wait.
    ///
    extern "C" void bf_control_op_wait_impl() noexcept;

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
    extern "C" [[nodiscard]] auto bf_handle_op_open_handle_impl(
        bsl::safe_uint32::value_type const reg0_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_handle_op_close_handle.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    bf_handle_op_close_handle_impl(bsl::safe_uint64::value_type const reg0_in) noexcept
        -> bf_status_t::value_type;

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
    extern "C" void bf_debug_op_out_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_vm_impl(bsl::safe_uint16::value_type const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_vp_impl(bsl::safe_uint16::value_type const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_vps_impl(bsl::safe_uint16::value_type const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_vmexit_log.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void
    bf_debug_op_dump_vmexit_log_impl(bsl::safe_uint16::value_type const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_c.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_write_c_impl(bsl::char_type const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_write_str.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_write_str_impl(bsl::char_type const *const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_ext.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///
    extern "C" void bf_debug_op_dump_ext_impl(bsl::safe_uint16::value_type const reg0_in) noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_page_pool.
    ///
    extern "C" void bf_debug_op_dump_page_pool_impl() noexcept;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_debug_op_dump_huge_pool.
    ///
    extern "C" void bf_debug_op_dump_huge_pool_impl() noexcept;

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
    extern "C" [[nodiscard]] auto bf_callback_op_register_bootstrap_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bf_callback_handler_bootstrap_t const pmut_reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_vmexit.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_callback_op_register_vmexit_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bf_callback_handler_vmexit_t const pmut_reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_callback_op_register_fail.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_callback_op_register_fail_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bf_callback_handler_fail_t const pmut_reg1_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_vm_op_create_vm_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vm_op_destroy_vm.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vm_op_destroy_vm_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_vp_op_create_vp_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint16::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_destroy_vp.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vp_op_destroy_vp_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vp_op_migrate.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vp_op_migrate_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_vps_op_create_vps_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint16::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_destroy_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_destroy_vps_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_init_as_root.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_init_as_root_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_vps_op_read_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bf_reg_t const reg2_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_vps_op_write_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bf_reg_t const reg2_in,
        bsl::safe_uint64::value_type const reg3_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_vps_op_run_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint16::value_type const reg3_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    bf_vps_op_run_current_impl(bsl::safe_uint64::value_type const reg0_in) noexcept
        -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_advance_ip.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_advance_ip_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_advance_ip_and_run_current.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    bf_vps_op_advance_ip_and_run_current_impl(bsl::safe_uint64::value_type const reg0_in) noexcept
        -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_promote.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_promote_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_vps_op_clear_vps.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_vps_op_clear_vps_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint16::value_type const reg1_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_intrinsic_op_rdmsr_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint32::value_type const reg1_in,
        bsl::safe_uint64::value_type *const pmut_reg0_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_wrmsr.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_intrinsic_op_wrmsr_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint32::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invlpga.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_intrinsic_op_invlpga_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_intrinsic_op_invept.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param reg2_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_intrinsic_op_invept_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        bsl::safe_uint64::value_type const reg2_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_intrinsic_op_invvpid_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        bsl::safe_uint16::value_type const reg2_in,
        bsl::safe_uint64::value_type const reg3_in) noexcept -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_mem_op_alloc_page_impl(
        bsl::safe_uint64::value_type const reg0_in,
        void **const pmut_reg0_out,
        bsl::safe_uint64::value_type *const pmut_reg1_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_free_page.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_mem_op_free_page_impl(
        bsl::safe_uint64::value_type const reg0_in, void *const pmut_reg1_in) noexcept
        -> bf_status_t::value_type;

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
    extern "C" [[nodiscard]] auto bf_mem_op_alloc_huge_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        void **const pmut_reg0_out,
        bsl::safe_uint64::value_type *const pmut_reg1_out) noexcept -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_free_huge.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param pmut_reg1_in n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_mem_op_free_huge_impl(
        bsl::safe_uint64::value_type const reg0_in, void *const pmut_reg1_in) noexcept
        -> bf_status_t::value_type;

    /// <!-- description -->
    ///   @brief Implements the ABI for bf_mem_op_alloc_heap.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg0_in n/a
    ///   @param reg1_in n/a
    ///   @param pmut_reg0_out n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto bf_mem_op_alloc_heap_impl(
        bsl::safe_uint64::value_type const reg0_in,
        bsl::safe_uint64::value_type const reg1_in,
        void **const pmut_reg0_out) noexcept -> bf_status_t::value_type;
}

#endif

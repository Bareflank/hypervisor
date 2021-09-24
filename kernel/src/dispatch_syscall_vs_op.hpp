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

#ifndef DISPATCH_SYSCALL_VS_OP_HPP
#define DISPATCH_SYSCALL_VS_OP_HPP

#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <promote.hpp>
#include <return_to_mk.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    [[nodiscard]] constexpr auto syscall_vs_op_set_active(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        ext_pool_t &mut_ext_pool,
        bool const advance_ip) noexcept -> syscall::bf_status_t;

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_create_vs syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_create_vs(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        intrinsic_t &mut_intrinsic,
        vp_pool_t const &vp_pool,
        vs_pool_t &mut_vs_pool) noexcept -> syscall::bf_status_t
    {
        auto const vpid{get_allocated_vpid(mut_tls.ext_reg1, vp_pool)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const ppid{get_ppid(mut_tls, mut_tls.ext_reg2)};
        if (bsl::unlikely(ppid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        auto const vsid{mut_vs_pool.allocate(mut_tls, mut_page_pool, mut_intrinsic, vpid, ppid)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = bsl::merge_umx_with_u16(mut_tls.ext_reg0, vsid).get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_destroy_vs syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_destroy_vs(
        tls_t &mut_tls, page_pool_t &mut_page_pool, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vsid{get_allocated_vsid(mut_tls.ext_reg1, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        bool const vs_destroyable{is_vs_destroyable(mut_vs_pool, vsid)};
        if (bsl::unlikely(!vs_destroyable)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_vs_pool.deallocate(mut_tls, mut_page_pool, vsid);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_init_as_root syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_init_as_root(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vsid{get_locally_assigned_vsid(mut_tls, mut_tls.ext_reg1, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        bool const vs_a_root_vs{is_vs_a_root_vs(mut_tls, vsid)};
        if (bsl::unlikely(!vs_a_root_vs)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        mut_vs_pool.state_save_to_vs(mut_tls, mut_intrinsic, mut_tls.root_vp_state, vsid);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_read syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_read(
        tls_t &mut_tls, intrinsic_t const &intrinsic, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vsid{get_locally_assigned_vsid(mut_tls, mut_tls.ext_reg1, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const reg{get_reg(mut_tls.ext_reg2)};
        if (bsl::unlikely(syscall::bf_reg_t::bf_reg_t_invalid == reg)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        auto const val{mut_vs_pool.read(mut_tls, intrinsic, reg, vsid)};
        if (bsl::unlikely(val.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = val.get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_write syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_write(tls_t &mut_tls, intrinsic_t &mut_intrinsic, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vsid{get_locally_assigned_vsid(mut_tls, mut_tls.ext_reg1, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const reg{get_reg(mut_tls.ext_reg2)};
        if (bsl::unlikely(syscall::bf_reg_t::bf_reg_t_invalid == reg)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        auto const ret{
            mut_vs_pool.write(mut_tls, mut_intrinsic, reg, bsl::to_u64(mut_tls.ext_reg3), vsid)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_run syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @param advance_ip if true, the IP of the requested VS is advanced
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_run(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        ext_pool_t &mut_ext_pool,
        bool const advance_ip) noexcept -> syscall::bf_status_t
    {
        auto const ret{syscall_vs_op_set_active(
            mut_tls,
            mut_intrinsic,
            mut_vm_pool,
            mut_vp_pool,
            mut_vs_pool,
            mut_ext_pool,
            advance_ip)};

        if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        return_to_mk(bsl::errc_success);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_run_current syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param advance_ip if true, the IP of the requested VS is advanced
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] inline auto
    syscall_vs_op_run_current(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vs_pool_t &mut_vs_pool,
        bool const advance_ip) noexcept -> syscall::bf_status_t
    {
        if (advance_ip) {
            mut_vs_pool.advance_ip(mut_tls, mut_intrinsic, bsl::to_u16(mut_tls.active_vsid));
        }
        else {
            bsl::touch();
        }

        return_to_mk(bsl::errc_success);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_advance_ip syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_advance_ip_and_run(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        return syscall_vs_op_run(
            mut_tls, mut_intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, mut_ext_pool, true);
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_advance_ip_and_run_current syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_advance_ip_and_run_current(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        return syscall_vs_op_run_current(mut_tls, mut_intrinsic, mut_vs_pool, true);
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_promote syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_promote(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vsid{get_locally_assigned_vsid(mut_tls, mut_tls.ext_reg1, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        mut_vs_pool.advance_ip(mut_tls, mut_intrinsic, vsid);
        mut_vs_pool.vs_to_state_save(mut_tls, mut_intrinsic, mut_tls.root_vp_state, vsid);

        promote(mut_tls.root_vp_state);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_clear syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_clear(
        tls_t &mut_tls, intrinsic_t const &intrinsic, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vsid{get_locally_assigned_vsid(mut_tls, mut_tls.ext_reg1, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const ret{mut_vs_pool.clear(mut_tls, intrinsic, vsid)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_migrate syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_migrate(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vs_pool_t &mut_vs_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vsid{get_allocated_vsid(mut_tls.ext_reg1, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const ppid{get_ppid(mut_tls, mut_tls.ext_reg2)};
        if (bsl::unlikely(ppid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        auto const assigned_ppid{mut_vs_pool.assigned_pp(vsid)};
        if (bsl::unlikely(ppid == assigned_ppid)) {
            return syscall::BF_STATUS_SUCCESS;
        }

        bool const vs_migratable{is_vs_migratable(mut_vs_pool, vsid)};
        if (bsl::unlikely(!vs_migratable)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        auto const ret{mut_vs_pool.migrate(mut_tls, mut_intrinsic, ppid, vsid)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_set_active syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @param advance_ip if true, the IP of the requested VS is advanced
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_set_active(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        ext_pool_t &mut_ext_pool,
        bool const advance_ip) noexcept -> syscall::bf_status_t
    {
        // ---------------------------------------------------------------------
        // Gather Arguments
        // ---------------------------------------------------------------------

        auto const vmid{get_allocated_vmid(mut_tls.ext_reg1, mut_vm_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const vpid{get_allocated_vpid(mut_tls.ext_reg2, mut_vp_pool)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        auto const vsid{get_locally_assigned_vsid(mut_tls, mut_tls.ext_reg3, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG3;
        }

        // ---------------------------------------------------------------------
        // Validate Assignment
        // ---------------------------------------------------------------------

        bool const vp_assigned_to_vm{is_vp_assigned_to_vm(mut_vp_pool, vpid, vmid)};
        if (bsl::unlikely(!vp_assigned_to_vm)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        bool const vs_assigned_to_vp{is_vs_assigned_to_vp(mut_vs_pool, vsid, vpid)};
        if (bsl::unlikely(!vs_assigned_to_vp)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG3;
        }

        // ---------------------------------------------------------------------
        // IP Advancement
        // ---------------------------------------------------------------------

        if (advance_ip) {
            mut_vs_pool.advance_ip(mut_tls, mut_intrinsic, vsid);
        }
        else {
            bsl::touch();
        }

        // ---------------------------------------------------------------------
        // Activate
        // ---------------------------------------------------------------------

        bool const vm_active_on_this_pp{mut_vm_pool.is_active_on_this_pp(mut_tls, vmid)};
        if (!vm_active_on_this_pp) {
            mut_vm_pool.set_inactive(mut_tls, bsl::to_u16(mut_tls.active_vmid));
            mut_vm_pool.set_active(mut_tls, vmid);
        }
        else {
            bsl::touch();
        }

        bool const vp_active_on_this_pp{mut_vp_pool.is_active_on_this_pp(mut_tls, vpid)};
        if (!vp_active_on_this_pp) {
            mut_vp_pool.set_inactive(mut_tls, bsl::to_u16(mut_tls.active_vpid));
            mut_vp_pool.set_active(mut_tls, vpid);
        }
        else {
            bsl::touch();
        }

        bool const vs_active_on_this_pp{mut_vs_pool.is_active_on_this_pp(mut_tls, vsid)};
        if (!vs_active_on_this_pp) {
            mut_vs_pool.set_inactive(mut_tls, mut_intrinsic, bsl::to_u16(mut_tls.active_vsid));
            mut_vs_pool.set_active(mut_tls, mut_intrinsic, vsid);
        }
        else {
            bsl::touch();
        }

        mut_ext_pool.signal_vm_active(mut_tls, mut_intrinsic, vmid);

        // ---------------------------------------------------------------------
        // Done
        // ---------------------------------------------------------------------

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vs_op_advance_ip_and_set_active syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vs_op_advance_ip_and_set_active(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        mut_vs_pool.advance_ip(mut_tls, mut_intrinsic, bsl::to_u16(mut_tls.active_vsid));

        return syscall_vs_op_set_active(
            mut_tls, mut_intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, mut_ext_pool, false);
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vs_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_vs_op(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        if (bsl::unlikely(!verify_handle_for_current_ext(mut_tls))) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        if (bsl::unlikely(!is_the_active_ext_the_vmexit_ext(mut_tls))) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_PERM_DENIED;
        }

        switch (syscall::bf_syscall_index(mut_tls.ext_syscall).get()) {
            case syscall::BF_VS_OP_CREATE_VS_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_create_vs(
                    mut_tls, mut_page_pool, mut_intrinsic, mut_vp_pool, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_DESTROY_VS_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_destroy_vs(mut_tls, mut_page_pool, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_INIT_AS_ROOT_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_init_as_root(mut_tls, mut_intrinsic, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_READ_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_read(mut_tls, mut_intrinsic, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_WRITE_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_write(mut_tls, mut_intrinsic, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_RUN_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_run(
                    mut_tls,
                    mut_intrinsic,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    mut_ext_pool,
                    false)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_RUN_CURRENT_IDX_VAL.get(): {
                auto const ret{
                    syscall_vs_op_run_current(mut_tls, mut_intrinsic, mut_vs_pool, false)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_advance_ip_and_run(
                    mut_tls, mut_intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, mut_ext_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL.get(): {
                auto const ret{
                    syscall_vs_op_advance_ip_and_run_current(mut_tls, mut_intrinsic, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_PROMOTE_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_promote(mut_tls, mut_intrinsic, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_CLEAR_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_clear(mut_tls, mut_intrinsic, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_MIGRATE_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_migrate(mut_tls, mut_intrinsic, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_SET_ACTIVE_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_set_active(
                    mut_tls,
                    mut_intrinsic,
                    mut_vm_pool,
                    mut_vp_pool,
                    mut_vs_pool,
                    mut_ext_pool,
                    false)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VS_OP_ADVANCE_IP_AND_SET_ACTIVE_IDX_VAL.get(): {
                auto const ret{syscall_vs_op_advance_ip_and_set_active(
                    mut_tls, mut_intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, mut_ext_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            default: {
                break;
            }
        }

        return report_syscall_unknown_unsupported(mut_tls);
    }
}

#endif

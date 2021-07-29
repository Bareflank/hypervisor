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

#ifndef DISPATCH_SYSCALL_VPS_OP_HPP
#define DISPATCH_SYSCALL_VPS_OP_HPP

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
#include <vps_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_create_vps syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_create_vps(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        intrinsic_t &mut_intrinsic,
        vps_pool_t &mut_vps_pool) noexcept -> syscall::bf_status_t
    {
        auto const vpsid{mut_vps_pool.allocate(
            mut_tls,
            mut_page_pool,
            mut_intrinsic,
            bsl::to_u16_unsafe(mut_tls.ext_reg1),
            bsl::to_u16_unsafe(mut_tls.ext_reg2))};

        if (bsl::unlikely(!vpsid)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = bsl::to_umax_upper_lower(mut_tls.ext_reg0, vpsid).get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_destroy_vps syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_destroy_vps(
        tls_t &mut_tls, page_pool_t &mut_page_pool, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{
            mut_vps_pool.deallocate(mut_tls, mut_page_pool, bsl::to_u16_unsafe(mut_tls.ext_reg1))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_init_as_root syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_init_as_root(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{mut_vps_pool.state_save_to_vps(
            mut_tls, mut_intrinsic, bsl::to_u16_unsafe(mut_tls.ext_reg1), *mut_tls.root_vp_state)};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_read syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_read(
        tls_t &mut_tls, intrinsic_t const &intrinsic, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const val{mut_vps_pool.read(
            mut_tls,
            intrinsic,
            bsl::to_u16_unsafe(mut_tls.ext_reg1),
            static_cast<syscall::bf_reg_t>(mut_tls.ext_reg2))};

        if (bsl::unlikely(!val)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = val.get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_write syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_write(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{mut_vps_pool.write(
            mut_tls,
            mut_intrinsic,
            bsl::to_u16_unsafe(mut_tls.ext_reg1),
            static_cast<syscall::bf_reg_t>(mut_tls.ext_reg2),
            bsl::to_u64(mut_tls.ext_reg3))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_run syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsics to use
    ///   @param mut_vm_pool the VM pool to use
    ///   @param mut_vp_pool the VP pool to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_run(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vps_pool_t &mut_vps_pool) noexcept -> syscall::bf_status_t
    {
        // ---------------------------------------------------------------------
        // Gather Arguments
        // ---------------------------------------------------------------------

        auto const vmid{bsl::to_u16_unsafe(mut_tls.ext_reg1)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vmid)) {
            bsl::error() << "vmid "           // --
                         << bsl::hex(vmid)    // --
                         << " is invalid"     // --
                         << bsl::endl         // --
                         << bsl::here();      // --

            return syscall::BF_STATUS_INVALID_PARAMS1;
        }

        auto const vpid{bsl::to_u16_unsafe(mut_tls.ext_reg2)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vpid)) {
            bsl::error() << "vpid "           // --
                         << bsl::hex(vpid)    // --
                         << " is invalid"     // --
                         << bsl::endl         // --
                         << bsl::here();      // --

            return syscall::BF_STATUS_INVALID_PARAMS2;
        }

        auto const vpsid{bsl::to_u16_unsafe(mut_tls.ext_reg3)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vpsid)) {
            bsl::error() << "vpsid "           // --
                         << bsl::hex(vpsid)    // --
                         << " is invalid"      // --
                         << bsl::endl          // --
                         << bsl::here();       // --

            return syscall::BF_STATUS_INVALID_PARAMS3;
        }

        // ---------------------------------------------------------------------
        // Validate Assignment
        // ---------------------------------------------------------------------

        /// TODO:
        /// - Add assignment checks here

        // ---------------------------------------------------------------------
        // Migrate
        // ---------------------------------------------------------------------

        /// TODO:
        /// - Add migration here

        // ---------------------------------------------------------------------
        // Activate VM
        // ---------------------------------------------------------------------

        if (mut_tls.active_vmid != vmid) {
            if (syscall::BF_INVALID_ID != mut_tls.active_vmid) {
                auto const ret{mut_vm_pool.set_inactive(mut_tls, bsl::to_u16(mut_tls.active_vmid))};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_FAILURE_UNKNOWN;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto const ret{mut_vm_pool.set_active(mut_tls, vmid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            bsl::touch();
        }
        else {
            bsl::touch();
        }

        // ---------------------------------------------------------------------
        // Activate VP
        // ---------------------------------------------------------------------

        if (mut_tls.active_vpid != vpid) {
            if (syscall::BF_INVALID_ID != mut_tls.active_vpid) {
                auto const ret{mut_vp_pool.set_inactive(mut_tls, bsl::to_u16(mut_tls.active_vpid))};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_FAILURE_UNKNOWN;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto const ret{mut_vp_pool.set_active(mut_tls, vpid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            bsl::touch();
        }
        else {
            bsl::touch();
        }

        // ---------------------------------------------------------------------
        // Activate VPS
        // ---------------------------------------------------------------------

        if (mut_tls.active_vpsid != vpsid) {
            if (syscall::BF_INVALID_ID != mut_tls.active_vpsid) {
                auto const ret{mut_vps_pool.set_inactive(
                    mut_tls, mut_intrinsic, bsl::to_u16(mut_tls.active_vpsid))};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_FAILURE_UNKNOWN;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto const ret{mut_vps_pool.set_active(mut_tls, mut_intrinsic, vpsid)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            bsl::touch();
        }
        else {
            bsl::touch();
        }

        // ---------------------------------------------------------------------
        // Done
        // ---------------------------------------------------------------------

        return_to_mk(bsl::exit_success);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_run_current syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] inline auto
    syscall_vps_op_run_current() noexcept -> syscall::bf_status_t
    {
        return_to_mk(bsl::exit_success);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_advance_ip syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_advance_ip(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{
            mut_vps_pool.advance_ip(mut_tls, mut_intrinsic, bsl::to_u16_unsafe(mut_tls.ext_reg1))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_advance_ip_and_run_current syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_advance_ip_and_run_current(
        tls_t &mut_tls, intrinsic_t &mut_intrinsic, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{
            mut_vps_pool.advance_ip(mut_tls, mut_intrinsic, bsl::to_u16(mut_tls.active_vpsid))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return_to_mk(bsl::exit_success);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_promote syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_promote(
        tls_t &mut_tls, intrinsic_t const &intrinsic, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{mut_vps_pool.vps_to_state_save(
            mut_tls, intrinsic, bsl::to_u16_unsafe(mut_tls.ext_reg1), *mut_tls.root_vp_state)};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        promote(mut_tls.root_vp_state);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vps_op_clear_vps syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vps_op_clear_vps(
        tls_t &mut_tls, intrinsic_t const &intrinsic, vps_pool_t &mut_vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{
            mut_vps_pool.clear(mut_tls, intrinsic, bsl::to_u16_unsafe(mut_tls.ext_reg1))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vps_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_intrinsic the intrinsics to use
    ///   @param mut_vm_pool the VM pool to use
    ///   @param mut_vp_pool the VP pool to use
    ///   @param mut_vps_pool the VPS pool to use
    ///   @param ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_vps_op(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vps_pool_t &mut_vps_pool,
        ext_t const &ext) noexcept -> syscall::bf_status_t
    {
        if (bsl::unlikely(!ext.is_handle_valid(bsl::to_u64(mut_tls.ext_reg0)))) {
            bsl::error() << "invalid handle "             // --
                         << bsl::hex(mut_tls.ext_reg0)    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        if (bsl::unlikely(mut_tls.ext != mut_tls.ext_vmexit)) {
            bsl::error() << "vps ops are not allowed by ext "       // --
                         << bsl::hex(ext.id())                      // --
                         << " as it didn't register for vmexits"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return syscall::BF_STATUS_INVALID_PERM_DENIED;
        }

        switch (syscall::bf_syscall_index(bsl::to_u64(mut_tls.ext_syscall)).get()) {
            case syscall::BF_VPS_OP_CREATE_VPS_IDX_VAL.get(): {
                auto const ret{
                    syscall_vps_op_create_vps(mut_tls, mut_page_pool, mut_intrinsic, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_DESTROY_VPS_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_destroy_vps(mut_tls, mut_page_pool, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_INIT_AS_ROOT_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_init_as_root(mut_tls, mut_intrinsic, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_READ_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_read(mut_tls, mut_intrinsic, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_WRITE_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_write(mut_tls, mut_intrinsic, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_RUN_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_run(
                    mut_tls, mut_intrinsic, mut_vm_pool, mut_vp_pool, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_RUN_CURRENT_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_run_current()};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_ADVANCE_IP_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_advance_ip(mut_tls, mut_intrinsic, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_ADVANCE_IP_AND_RUN_CURRENT_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_advance_ip_and_run_current(
                    mut_tls, mut_intrinsic, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_PROMOTE_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_promote(mut_tls, mut_intrinsic, mut_vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VPS_OP_CLEAR_VPS_IDX_VAL.get(): {
                auto const ret{syscall_vps_op_clear_vps(mut_tls, mut_intrinsic, mut_vps_pool)};
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

        bsl::error() << "unknown syscall "               //--
                     << bsl::hex(mut_tls.ext_syscall)    //--
                     << bsl::endl                        //--
                     << bsl::here();                     //--

        return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
    }
}

#endif

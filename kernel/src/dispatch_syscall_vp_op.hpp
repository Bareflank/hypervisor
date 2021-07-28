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

#ifndef DISPATCH_SYSCALL_VP_OP_HPP
#define DISPATCH_SYSCALL_VP_OP_HPP

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_vp_op_create_vp syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_vp_pool the VP pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vp_op_create_vp(tls_t &mut_tls, vp_pool_t &mut_vp_pool) noexcept -> syscall::bf_status_t
    {
        auto const vpid{mut_vp_pool.allocate(
            mut_tls, bsl::to_u16_unsafe(mut_tls.ext_reg1), bsl::to_u16_unsafe(mut_tls.ext_reg2))};

        if (bsl::unlikely(!vpid)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = bsl::to_umax_upper_lower(mut_tls.ext_reg0, vpid).get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vp_op_destroy_vp syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_vp_pool the VP pool to use
    ///   @param vps_pool the VPS pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vp_op_destroy_vp(
        tls_t &mut_tls, vp_pool_t &mut_vp_pool, vps_pool_t const &vps_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const ret{
            mut_vp_pool.deallocate(mut_tls, vps_pool, bsl::to_u16_unsafe(mut_tls.ext_reg1))};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vp_op_migrate syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_vp_pool the VP pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vp_op_migrate(tls_t &mut_tls, vp_pool_t &mut_vp_pool) noexcept -> syscall::bf_status_t
    {
        auto const ret{mut_vp_pool.migrate(
            mut_tls, bsl::to_u16_unsafe(mut_tls.ext_reg1), bsl::to_u16_unsafe(mut_tls.ext_reg2))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vp_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_vp_pool the VP pool to use
    ///   @param vps_pool the VPS pool to use
    ///   @param ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_vp_op(
        tls_t &mut_tls,
        vp_pool_t &mut_vp_pool,
        vps_pool_t const &vps_pool,
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
            bsl::error() << "vp ops are not allowed by ext "        // --
                         << bsl::hex(ext.id())                      // --
                         << " as it didn't register for vmexits"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return syscall::BF_STATUS_INVALID_PERM_DENIED;
        }

        switch (syscall::bf_syscall_index(bsl::to_u64(mut_tls.ext_syscall)).get()) {
            case syscall::BF_VP_OP_CREATE_VP_IDX_VAL.get(): {
                auto const ret{syscall_vp_op_create_vp(mut_tls, mut_vp_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VP_OP_DESTROY_VP_IDX_VAL.get(): {
                auto const ret{syscall_vp_op_destroy_vp(mut_tls, mut_vp_pool, vps_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VP_OP_MIGRATE_IDX_VAL.get(): {
                auto const ret{syscall_vp_op_migrate(mut_tls, mut_vp_pool)};
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

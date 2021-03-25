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

#ifndef DISPATCH_SYSCALL_VP_OP_FAILURE_HPP
#define DISPATCH_SYSCALL_VP_OP_FAILURE_HPP

#include <bf_constants.hpp>
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
    ///   @param tls the current TLS block
    ///   @param vp_pool the VP pool to use
    ///   @param vps_pool the VPS pool to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_vp_op_create_vp_failure(tls_t &tls, vp_pool_t &vp_pool, vps_pool_t &vps_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type ret{};

        if (!tls.state_reversal_required) {
            return bsl::errc_success;
        }

        ret = vp_pool.deallocate(tls, vps_pool, tls.log_vpid);
        if (bsl::unlikely(!bsl::success_or_precondition(ret))) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vp_op_destroy_vp syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param vp_pool the VP pool to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_vp_op_destroy_vp_failure(tls_t &tls, vp_pool_t &vp_pool) noexcept -> bsl::errc_type
    {
        bsl::errc_type ret{};

        if (!tls.state_reversal_required) {
            return bsl::errc_success;
        }

        ret = vp_pool.zombify(bsl::to_u16_unsafe(tls.ext_reg1));
        if (bsl::unlikely(!bsl::success_or_precondition(ret))) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vp_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param vp_pool the VP pool to use
    ///   @param vps_pool the VPS pool to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_vp_op_failure(tls_t &tls, vp_pool_t &vp_pool, vps_pool_t &vps_pool) noexcept
        -> bsl::errc_type
    {
        bsl::errc_type ret{};

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_VP_OP_CREATE_VP_IDX_VAL.get(): {
                ret = syscall_vp_op_create_vp_failure(tls, vp_pool, vps_pool);
                return ret;
            }

            case syscall::BF_VP_OP_DESTROY_VP_IDX_VAL.get(): {
                ret = syscall_vp_op_destroy_vp_failure(tls, vp_pool);
                return ret;
            }

            case syscall::BF_VP_OP_MIGRATE_IDX_VAL.get(): {
                break;
            }

            default: {
                break;
            }
        }

        return bsl::errc_success;
    }
}

#endif

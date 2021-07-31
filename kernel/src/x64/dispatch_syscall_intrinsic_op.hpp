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

#ifndef DISPATCH_SYSCALL_INTRINSIC_OP_HPP
#define DISPATCH_SYSCALL_INTRINSIC_OP_HPP

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_intrinsic_op_rdmsr syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param intrinsic the intrinsic_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_intrinsic_op_rdmsr(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept
        -> syscall::bf_status_t
    {
        auto const msr{get_msr(mut_tls.ext_reg1)};
        if (bsl::unlikely(msr.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const val{intrinsic.rdmsr(msr)};
        if (bsl::unlikely(val.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = val.get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_intrinsic_op_wrmsr syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_intrinsic_op_wrmsr(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
        -> syscall::bf_status_t
    {
        auto const msr{get_msr(mut_tls.ext_reg1)};
        if (bsl::unlikely(msr.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const ret{mut_intrinsic.wrmsr(msr, bsl::to_u64(mut_tls.ext_reg2))};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_intrinsic_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_intrinsic_op(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
        -> syscall::bf_status_t
    {
        if (bsl::unlikely(!verify_handle_for_current_ext(mut_tls))) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        switch (syscall::bf_syscall_index(mut_tls.ext_syscall).get()) {
            case syscall::BF_INTRINSIC_OP_RDMSR_IDX_VAL.get(): {
                auto const ret{syscall_intrinsic_op_rdmsr(mut_tls, mut_intrinsic)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_INTRINSIC_OP_WRMSR_IDX_VAL.get(): {
                auto const ret{syscall_intrinsic_op_wrmsr(mut_tls, mut_intrinsic)};
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

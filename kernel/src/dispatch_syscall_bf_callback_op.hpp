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

#ifndef DISPATCH_SYSCALL_BF_CALLBACK_OP_HPP
#define DISPATCH_SYSCALL_BF_CALLBACK_OP_HPP

#include "dispatch_syscall_helpers.hpp"

#include <bf_constants.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_bootstrap syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_callback_op_register_bootstrap(tls_t const &tls) noexcept -> syscall::bf_status_t
    {
        auto const callback{get_callback(tls.ext_reg1)};
        if (bsl::unlikely(callback.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        bool const already_registered_by_active_ext{
            has_active_ext_registered_a_callback(tls, tls.ext->bootstrap_ip(), "bootstrap")};
        if (bsl::unlikely(already_registered_by_active_ext)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        tls.ext->set_bootstrap_ip(callback);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_vmexit syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_callback_op_register_vmexit(tls_t &mut_tls) noexcept -> syscall::bf_status_t
    {
        auto const callback{get_callback(mut_tls.ext_reg1)};
        if (bsl::unlikely(callback.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        bool const already_registered_by_active_ext{
            has_active_ext_registered_a_callback(mut_tls, mut_tls.ext->vmexit_ip(), "vmexit")};
        if (bsl::unlikely(already_registered_by_active_ext)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        bool const already_registered_by_any_ext{
            has_any_ext_registered_a_callback(mut_tls.ext_vmexit, "vmexit")};
        if (bsl::unlikely(already_registered_by_any_ext)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext->set_vmexit_ip(callback);
        mut_tls.ext_vmexit = mut_tls.ext;

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_fail syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_callback_op_register_fail(tls_t &mut_tls) noexcept -> syscall::bf_status_t
    {
        auto const callback{get_callback(mut_tls.ext_reg1)};
        if (bsl::unlikely(callback.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        bool const already_registered_by_active_ext{
            has_active_ext_registered_a_callback(mut_tls, mut_tls.ext->fail_ip(), "fail")};
        if (bsl::unlikely(already_registered_by_active_ext)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        bool const already_registered_by_any_ext{
            has_any_ext_registered_a_callback(mut_tls.ext_fail, "fail")};
        if (bsl::unlikely(already_registered_by_any_ext)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext->set_fail_ip(callback);
        mut_tls.ext_fail = mut_tls.ext;

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_callback_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_bf_callback_op(tls_t &mut_tls) noexcept -> syscall::bf_status_t
    {
        if (bsl::unlikely(!verify_handle_for_current_ext(mut_tls))) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        switch (syscall::bf_syscall_index(mut_tls.ext_syscall).get()) {
            case syscall::BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL.get(): {
                auto const ret{syscall_bf_callback_op_register_bootstrap(mut_tls)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL.get(): {
                auto const ret{syscall_bf_callback_op_register_vmexit(mut_tls)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL.get(): {
                auto const ret{syscall_bf_callback_op_register_fail(mut_tls)};
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

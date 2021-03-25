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

#ifndef DISPATCH_SYSCALL_CALLBACK_OP_FAILURE_HPP
#define DISPATCH_SYSCALL_CALLBACK_OP_FAILURE_HPP

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/likely.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_bootstrap syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///
    constexpr void
    syscall_callback_op_register_bootstrap_failure(tls_t &tls, ext_t &ext) noexcept
    {
        if (!tls.state_reversal_required) {
            return;
        }

        ext.set_bootstrap_ip(bsl::safe_uintmax::failure());
    }

    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_vmexit syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///
    constexpr void
    syscall_callback_op_register_vmexit_failure(tls_t &tls, ext_t &ext) noexcept
    {
        if (!tls.state_reversal_required) {
            return;
        }

        ext.set_vmexit_ip(bsl::safe_uintmax::failure());
        tls.ext_vmexit = nullptr;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_fail syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///
    constexpr void
    syscall_callback_op_register_fail_failure(tls_t &tls, ext_t &ext) noexcept
    {
        if (!tls.state_reversal_required) {
            return;
        }

        ext.set_fail_ip(bsl::safe_uintmax::failure());
        tls.ext_fail = nullptr;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_callback_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///
    constexpr void
    dispatch_syscall_callback_op_failure(tls_t &tls, ext_t &ext) noexcept
    {
        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL.get(): {
                syscall_callback_op_register_bootstrap_failure(tls, ext);
                break;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL.get(): {
                syscall_callback_op_register_vmexit_failure(tls, ext);
                break;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL.get(): {
                syscall_callback_op_register_fail_failure(tls, ext);
                break;
            }

            default: {
                break;
            }
        }
    }
}

#endif

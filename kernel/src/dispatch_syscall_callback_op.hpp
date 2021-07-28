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

#ifndef DISPATCH_SYSCALL_CALLBACK_OP_HPP
#define DISPATCH_SYSCALL_CALLBACK_OP_HPP

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
    ///   @param mut_tls the current TLS block
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_callback_op_register_bootstrap(tls_t &mut_tls, ext_t &mut_ext) noexcept
        -> syscall::bf_status_t
    {
        bsl::safe_uintmax const callback{mut_tls.ext_reg1};
        if (bsl::unlikely(callback.is_zero())) {
            bsl::error() << "the bootstrap callback cannot be null"    // --
                         << bsl::endl                                  // --
                         << bsl::here();                               // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        if (bsl::unlikely(mut_ext.bootstrap_ip())) {
            bsl::error() << "mut_ext "                                      // --
                         << bsl::hex(mut_ext.id())                          // --
                         << " already registered a bootstrap callback\n"    // --
                         << bsl::here();                                    // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_ext.set_bootstrap_ip(callback);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_vmexit syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_callback_op_register_vmexit(tls_t &mut_tls, ext_t &mut_ext) noexcept
        -> syscall::bf_status_t
    {
        bsl::safe_uintmax const callback{mut_tls.ext_reg1};
        if (bsl::unlikely(callback.is_zero())) {
            bsl::error() << "the vmexit callback cannot be null"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        if (bsl::unlikely(mut_ext.vmexit_ip())) {
            bsl::error() << "mut_ext "                                   // --
                         << bsl::hex(mut_ext.id())                       // --
                         << " already registered a vmexit callback\n"    // --
                         << bsl::here();                                 // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        if (bsl::unlikely(nullptr != mut_tls.ext_vmexit)) {
            bsl::error() << "mut_ext "                                                  // --
                         << bsl::hex(static_cast<ext_t *>(mut_tls.ext_vmexit)->id())    // --
                         << " already registered a vmexit callback\n"                   // --
                         << bsl::here();                                                // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_ext.set_vmexit_ip(callback);
        mut_tls.ext_vmexit = &mut_ext;

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_callback_op_register_fail syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_callback_op_register_fail(tls_t &mut_tls, ext_t &mut_ext) noexcept
        -> syscall::bf_status_t
    {
        bsl::safe_uintmax const callback{mut_tls.ext_reg1};
        if (bsl::unlikely(callback.is_zero())) {
            bsl::error() << "the fast fail callback cannot be null"    // --
                         << bsl::endl                                  // --
                         << bsl::here();                               // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        if (bsl::unlikely(mut_ext.fail_ip())) {
            bsl::error() << "mut_ext "                                      // --
                         << bsl::hex(mut_ext.id())                          // --
                         << " already registered a fast fail callback\n"    // --
                         << bsl::here();                                    // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        if (bsl::unlikely(nullptr != mut_tls.ext_fail)) {
            bsl::error() << "mut_ext "                                                // --
                         << bsl::hex(static_cast<ext_t *>(mut_tls.ext_fail)->id())    // --
                         << " already registered a fast fail callback\n"              // --
                         << bsl::here();                                              // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_ext.set_fail_ip(callback);
        mut_tls.ext_fail = &mut_ext;

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_callback_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_callback_op(tls_t &mut_tls, ext_t &mut_ext) noexcept -> syscall::bf_status_t
    {
        if (bsl::unlikely(!mut_ext.is_handle_valid(bsl::to_umax(mut_tls.ext_reg0)))) {
            bsl::error() << "invalid handle "             // --
                         << bsl::hex(mut_tls.ext_reg0)    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        switch (syscall::bf_syscall_index(bsl::to_umax(mut_tls.ext_syscall)).get()) {
            case syscall::BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL.get(): {
                auto const ret{syscall_callback_op_register_bootstrap(mut_tls, mut_ext)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL.get(): {
                auto const ret{syscall_callback_op_register_vmexit(mut_tls, mut_ext)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL.get(): {
                auto const ret{syscall_callback_op_register_fail(mut_tls, mut_ext)};
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

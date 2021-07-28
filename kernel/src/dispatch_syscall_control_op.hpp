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

#ifndef DISPATCH_SYSCALL_CONTROL_OP_HPP
#define DISPATCH_SYSCALL_CONTROL_OP_HPP

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <return_to_mk.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Dispatches the bf_callback_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_control_op(tls_t const &tls, ext_t const &ext) noexcept -> syscall::bf_status_t
    {
        switch (syscall::bf_syscall_index(bsl::to_umax(tls.ext_syscall)).get()) {
            case syscall::BF_CONTROL_OP_EXIT_IDX_VAL.get(): {
                return_to_mk(bsl::exit_failure);

                // Unreachable
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_CONTROL_OP_WAIT_IDX_VAL.get(): {
                if (ext.is_started()) {
                    return_to_mk(bsl::exit_failure);
                }
                else {
                    return_to_mk(bsl::exit_success);
                }

                // Unreachable
                return syscall::BF_STATUS_SUCCESS;
            }

            default: {
                break;
            }
        }

        bsl::error() << "unknown syscall "           //--
                     << bsl::hex(tls.ext_syscall)    //--
                     << bsl::endl                    //--
                     << bsl::here();                 //--

        return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
    }
}

#endif

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

#ifndef TEST_DISPATCH_SYSCALL_CALLBACK_OP_HPP
#define TEST_DISPATCH_SYSCALL_CALLBACK_OP_HPP

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Dispatches the bf_callback_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_callback_op(tls_t &tls, ext_t &ext) noexcept -> bsl::errc_type
    {
        bsl::discard(tls);
        bsl::discard(ext);

        return bsl::errc_success;
    }
}

#endif

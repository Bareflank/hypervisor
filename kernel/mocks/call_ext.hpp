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

#ifndef MOCKS_CALL_EXT_HPP
#define MOCKS_CALL_EXT_HPP

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Calls an extension. This can be used to execute an
    ///     extension's entry point, or it can be used to call an extension's
    ///     callback that was registered using the entry point. It should
    ///     be noted that once this function is called, it is likely that
    ///     the extension will execute syscalls. When this happens, the
    ///     extension will call back into the microkernel before this function
    ///     has completed it's execution.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ip the instruction pointer to call into
    ///   @param sp the stack pointer to use
    ///   @param arg0 the first argument to pass the extension
    ///   @param arg1 the second argument to pass the extension
    ///   @return returns the exit status from the extension
    ///
    [[nodiscard]] constexpr auto
    call_ext(
        bsl::uint64 const ip,
        bsl::uint64 const sp,
        bsl::uint64 const arg0,
        bsl::uint64 const arg1) noexcept -> bsl::errc_type
    {
        bsl::discard(sp);
        bsl::discard(arg0);
        bsl::discard(arg1);

        if (ip == bsl::safe_u64::magic_1()) {
            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }
}

#endif

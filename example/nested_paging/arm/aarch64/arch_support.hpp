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

#ifndef ARCH_SUPPORT_HPP
#define ARCH_SUPPORT_HPP

#include <mk_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Implements the architecture specific VMExit handler.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle the handle to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    constexpr void
    vmexit(
        syscall::bf_handle_t &handle,
        bsl::safe_u16 const &vsid,
        bsl::safe_u64 const &exit_reason) noexcept
    {
        bsl::discard(handle);
        bsl::discard(vsid);
        bsl::discard(exit_reason);
    }

    /// <!-- description -->
    ///   @brief Initializes a VS with architecture specific stuff.
    ///
    /// <!-- inputs/outputs -->
    ///   @param handle the handle to use
    ///   @param vsid the VS being intialized
    ///   @return Returns bsl::errc_success on success and bsl::errc_failure
    ///     on failure.
    ///
    [[nodiscard]] constexpr auto
    init_vs(syscall::bf_handle_t &handle, bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::discard(handle);
        bsl::discard(vsid);

        return bsl::errc_success;
    }
}

#endif

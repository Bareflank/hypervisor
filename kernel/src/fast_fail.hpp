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

#ifndef FAST_FAIL_HPP
#define FAST_FAIL_HPP

#include <ext_t.hpp>
#include <return_to_vmexit_loop.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the main entry point for fast fails that occur
    ///     after a successful launch of the hypervisor. Once this occurs,
    ///     the fast fail path either has to be handled by an extension,
    ///     or a halt() will occur.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param pmut_ext the ext_t to handle the fail
    ///   @return Returns bsl::errc_success if the fail was handled,
    ///     bsl::errc_failure otherwise.
    ///
    [[nodiscard]] constexpr auto
    fast_fail(tls_t &mut_tls, intrinsic_t &mut_intrinsic, ext_t *const pmut_ext) noexcept
        -> bsl::errc_type
    {
        bsl::print() << bsl::red << "\nfast failing:";
        bsl::print() << bsl::rst << bsl::endl;

        if (nullptr != pmut_ext) {
            auto const ret{pmut_ext->fail(mut_tls, mut_intrinsic)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        return bsl::errc_failure;
    }
}

#endif

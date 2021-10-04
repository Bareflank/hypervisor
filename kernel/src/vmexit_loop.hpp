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

#ifndef VMEXIT_LOOP_HPP
#define VMEXIT_LOOP_HPP

#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <vmexit_log_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the main entry point for VMExits that occur
    ///     after a successful launch of the hypervisor.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vs_pool the VPS pool to use
    ///   @param mut_log the VMExit log to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    vmexit_loop(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vs_pool_t &mut_vs_pool,
        vmexit_log_t &mut_log) noexcept -> bsl::errc_type
    {
        while (true) {
            auto const exit_reason{mut_vs_pool.run(mut_tls, mut_intrinsic, mut_log)};
            if (bsl::unlikely(exit_reason.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const ret{mut_tls.ext_vmexit->vmexit(mut_tls, mut_intrinsic, exit_reason)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_tls.first_launch_succeeded = bsl::safe_u64::magic_1().get();
        }
    }
}

#endif

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
#include <vps_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the main entry point for VMExits that occur
    ///     after a successful launch of the hypervisor.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @param vps_pool the VPS pool to use
    ///   @param ext the ext_t to handle the VMExit
    ///   @param log the VMExit log to use
    ///   @return Returns bsl::exit_success on success, bsl::exit_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    vmexit_loop(
        tls_t &tls,
        intrinsic_t &intrinsic,
        vps_pool_t &vps_pool,
        ext_t &ext,
        vmexit_log_t &log) noexcept -> bsl::exit_code
    {
        auto const exit_reason{vps_pool.run(tls, intrinsic, tls.active_vpsid, log)};
        if (bsl::unlikely(!exit_reason)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::exit_failure;
        }

        auto const ret{ext.vmexit(tls, intrinsic, exit_reason)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::exit_failure;
        }

        return bsl::exit_success;
    }
}

#endif

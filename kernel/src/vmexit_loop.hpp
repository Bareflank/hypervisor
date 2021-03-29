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
    ///   @tparam TLS_CONCEPT defines the type of TLS block to use
    ///   @tparam EXT_CONCEPT defines the type of ext_t to use
    ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
    ///   @param tls the current TLS block
    ///   @param ext_vmexit the ext_t to handle the VMExit
    ///   @param vps_pool the VPS pool to use
    ///   @return Returns bsl::exit_success on success and bsl::exit_failure
    ///     otherwise
    ///
    template<typename TLS_CONCEPT, typename EXT_CONCEPT, typename VPS_POOL_CONCEPT>
    [[nodiscard]] constexpr auto
    vmexit_loop(TLS_CONCEPT &tls, EXT_CONCEPT &ext_vmexit, VPS_POOL_CONCEPT &vps_pool) noexcept
        -> bsl::exit_code
    {
        auto const exit_reason{vps_pool.run(tls, tls.active_vpsid)};
        if (bsl::unlikely(!exit_reason)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::exit_failure;
        }

        auto const ret{ext_vmexit.vmexit(tls, exit_reason)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::exit_failure;
        }

        return bsl::exit_success;
    }
}

#endif

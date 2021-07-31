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

#ifndef DUMMY_VS_POOL_T_HPP
#define DUMMY_VS_POOL_T_HPP

#include "dummy_errc_types.hpp"

#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @class mk::dummy_vs_pool_t
    ///
    /// <!-- description -->
    ///   @brief Provides the base vs_pool_t for testing.
    ///
    class dummy_vs_pool_t final
    {
    public:
        /// <!-- description -->
        ///   @brief If a vs_t is assigned to the requested VP, the ID of
        ///     the vs_t is returned. Otherwise, this function will return
        ///     bsl::safe_u16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vpid the ID fo the VP to query
        ///   @return If a vs_t is assigned to the requested VP, the ID of
        ///     the vs_t is returned. Otherwise, this function will return
        ///     bsl::safe_u16::failure()
        ///
        [[nodiscard]] static constexpr auto
        is_assigned_to_vp(tls_t &tls, bsl::safe_u16 const &vpid) noexcept -> bsl::safe_u16
        {
            if (tls.test_ret == errc_vs_pool_failure) {
                return vpid;
            }

            return bsl::safe_u16::failure();
        }
    };
}

#endif

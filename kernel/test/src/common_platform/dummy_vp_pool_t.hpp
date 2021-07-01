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

#ifndef DUMMY_VP_POOL_T_HPP
#define DUMMY_VP_POOL_T_HPP

#include "dummy_errc_types.hpp"

#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @class mk::dummy_vp_pool_t
    ///
    /// <!-- description -->
    ///   @brief Provides the base vp_pool_t for testing.
    ///
    class dummy_vp_pool_t final
    {
    public:
        /// <!-- description -->
        ///   @brief If a vp_t in the pool is assigned to the requested VM,
        ///     the ID of the first vp_t found is returned. Otherwise, this
        ///     function will return bsl::safe_uint16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid the ID fo the VM to query
        ///   @return If a vp_t in the pool is assigned to the requested VM,
        ///     the ID of the first vp_t found is returned. Otherwise, this
        ///     function will return bsl::safe_uint16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_assigned_to_vm(tls_t &tls, bsl::safe_uint16 const &vmid) const noexcept
            -> bsl::safe_uint16
        {
            if (tls.test_ret == errc_vp_pool_failure) {
                return vmid;
            }

            return bsl::safe_uint16::failure();
        }
    };
}

#endif

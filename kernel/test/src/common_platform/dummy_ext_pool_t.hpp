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

#ifndef DUMMY_EXT_POOL_T_HPP
#define DUMMY_EXT_POOL_T_HPP

#include "dummy_errc_types.hpp"

#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @class mk::dummy_ext_pool_t
    ///
    /// <!-- description -->
    ///   @brief Provides the base ext_pool_t for testing.
    ///
    class dummy_ext_pool_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Tells each extension that a VM was created so that it
        ///     can initialize it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid the ID of the VM that was created.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        signal_vm_created(tls_t &tls, bsl::safe_u16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::discard(vmid);

            if (tls.test_ret == errc_ext_pool_failure) {
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Tells each extension that a VM was destroyed so that it
        ///     can release it's VM specific resources.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param vmid the ID of the VM that was destroyed.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        signal_vm_destroyed(tls_t &tls, bsl::safe_u16 const &vmid) noexcept -> bsl::errc_type
        {
            bsl::discard(vmid);

            if (tls.test_ret == errc_ext_pool_failure) {
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }
    };
}

#endif

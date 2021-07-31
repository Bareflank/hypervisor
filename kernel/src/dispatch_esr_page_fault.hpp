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

#ifndef DISPATCH_ESR_PAGE_FAULT_HPP
#define DISPATCH_ESR_PAGE_FAULT_HPP

#include <ext_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the ESR handler for page faults
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param pmut_ext the extension that made the syscall
    ///   @return Returns bsl::errc_success if the exception was handled,
    ///     bsl::errc_failure otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_esr_page_fault(
        tls_t &mut_tls, page_pool_t &mut_page_pool, ext_t *const pmut_ext) noexcept
        -> bsl::errc_type
    {
        /// NOTE:
        /// - When the microkernel is still bootstrapping, the pmut_ext field in
        ///   the TLS has not yet been set, so pmut_ext could actually be a
        ///   nullptr which is why it is not passed by reference.
        ///

        if (bsl::unlikely(nullptr == pmut_ext)) {
            return bsl::errc_failure;
        }

        return pmut_ext->map_page_direct(mut_tls, mut_page_pool, bsl::to_umx(mut_tls.esr_pf_addr));
    }
}

#endif

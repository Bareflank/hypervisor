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

#ifndef DISPATCH_ESR_NMI_HPP
#define DISPATCH_ESR_NMI_HPP

#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the main entry point for NMI exceptions (which
    ///     on AMD do not occur as NMIs are blocked).
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsic_t to use
    ///
    constexpr void
    dispatch_esr_nmi(tls_t const &tls, intrinsic_t const &intrinsic) noexcept
    {
        bsl::discard(tls);
        bsl::discard(intrinsic);
    }
}

#endif

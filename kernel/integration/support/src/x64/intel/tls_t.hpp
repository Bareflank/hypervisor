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

#ifndef TLS_T_HPP
#define TLS_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace syscall
{
    /// @class example::tls_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's Thread Local Storage (TLS).
    ///     Extensions can use this to store data specific to a PP as needed.
    ///     The tls_t can also be used during unit testing to store testing
    ///     specific logic and data to ensure tests can support constexpr
    ///     style unit testing. Also note that this is stored in the arch
    ///     specific folders as it usually needs to store arch specific
    ///     resources. In this simple example, we leave this empty.
    ///
    /// <!-- notes -->
    ///   @note IMPORTANT: Extensions are limited to a single 4k page for the
    ///     TLS data. Technically, extensions are given 2 4k pages, but one of
    ///     the pages is dedicated to TLS data defined by the specification
    ///     and populated by the microkernel (e.g., the general purpose
    ///     registers and ID information). For this reason, if more than a
    ///     page is needed, the TLS block should store pointers to memory that
    ///     is allocated.
    ///
    struct tls_t final
    {
        /// @brief dummy data for example purposes only.
        bsl::safe_umx dummy;
    };

    /// @brief defines the max size supported for the TLS block
    constexpr auto MAX_TLS_SIZE{HYPERVISOR_PAGE_SIZE};

    /// @brief ensure that the tls_t does not exceed the max supported size
    static_assert(!(sizeof(tls_t) > MAX_TLS_SIZE));
}

#endif

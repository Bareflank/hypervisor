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

#ifndef EXT_TLS_T_HPP
#define EXT_TLS_T_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>    // IWYU pragma: keep
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief A thread is a PP, meaning each PP represents a thread. Each
    ///     extension is given two pages of TLS storage per thread. The first
    ///     page contains the TLS data, which is created by thread_local.
    ///     This is just a page that is allocated, so we don't add it here.
    ///     After the TLS data, the ELF TLS spec requires us to define "tp".
    ///     This is a pointer to itself and is used by the asm code the compiler
    ///     generates for thread_local. The rest of the space we can use for
    ///     whatever we want. Currently, we use this for variables defined in
    ///     the ABI. For example, we store the general purpose registers and
    ///     ID information here so that the extension can quickly get access
    ///     to this information.
    ///
    struct ext_tcb_t final
    {
        /// @brief stores tp as defined by the ELF TLS spec
        bsl::uintmx tp;
        /// @brief the rest contains the TCB, which is defined by the ABI
        bsl::array<bsl::uint8, (HYPERVISOR_PAGE_SIZE - sizeof(bsl::uintmx)).checked().get()> tcb;
    };

    /// @brief sanity check
    static_assert(sizeof(ext_tcb_t) == HYPERVISOR_PAGE_SIZE);
}

#endif

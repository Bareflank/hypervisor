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

#include <basic_entries_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>

#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace lib
{
    /// <!-- description -->
    ///   @brief Defines the extension's mocked version of tls_t, used for
    ///     unit testing. Specifically, this version only contains portions
    ///     that are common for all architectures.
    ///
    struct tls_t final
    {
        /// --------------------------------------------------------------------
        /// Context Information
        /// --------------------------------------------------------------------

        /// @brief stores the currently active VMID
        bsl::uint16 ppid;
        /// @brief stores the total number of online PPs
        bsl::uint16 online_pps;

        /// @brief stores the currently active root page table
        void *active_rpt;

        /// --------------------------------------------------------------------
        /// Unit Test Only
        /// --------------------------------------------------------------------

        /// @brief API specific return type for tests
        bsl::errc_type test_ret;
        /// @brief API specific return type for tests
        bsl::safe_u64 test_virt;
        /// @brief API specific return type for tests
        bsl::safe_u64 test_phys;
        /// @brief API specific return type for tests
        basic_entries_t<l3e_t, l2e_t, l1e_t, l0e_t> test_ents;
    };
}

#endif

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

#ifndef MOCKS_GS_T_HPP
#define MOCKS_GS_T_HPP

#include <basic_page_4k_t.hpp>

#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief  Defines the extension's mocked version of gs_t, used for
    ///     unit testing. Specifically, this version is architecture specific.
    ///
    struct gs_t final
    {
        /// @brief tells certain mocks when to fail
        bsl::errc_type test_ret;
        /// @brief stores the cpuid value to return from intrinsic_cpuid_impl
        bsl::safe_u64 cpuid_val{};
        /// @brief stores the MSR bitmap used by this vs_t
        lib::basic_page_4k_t *msr_bitmap{};
        /// @brief stores the physical address of the MSR bitmap above
        bsl::safe_umx msr_bitmap_phys{};
    };
}

#endif

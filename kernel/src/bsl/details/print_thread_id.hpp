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

#ifndef MK_BSL_DETAILS_PRINT_THREAD_ID_HPP
#define MK_BSL_DETAILS_PRINT_THREAD_ID_HPP

#include <get_current_tls.hpp>

#include <bsl/convert.hpp>
#include <bsl/is_constant_evaluated.hpp>
#include <bsl/safe_integral.hpp>

namespace bsl::details
{
    /// <!-- description -->
    ///   @brief Outputs the current thread ID info
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of outputter provided
    ///   @param o the outputter
    ///
    template<typename T>
    constexpr void
    print_thread_id(out<T> const o) noexcept
    {
        if (is_constant_evaluated()) {
            return;
        }

        safe_uintmax thread_id{mk::get_current_tls()->thread_id};

        o << " ["                                                                      // --
          << bsl::cyan << bsl::fmt("#018x", thread_id) << bsl::reset_color << " - "    // --
          << bsl::black << "MK" << bsl::reset_color                                    // --
          << ']';                                                                      // --
    }
}

#endif

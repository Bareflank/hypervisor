/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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
///
/// @file print.hpp
///

#ifndef BSL_PRINT_HPP
#define BSL_PRINT_HPP

#include "cstdint.hpp"
#include <cstdio>    // PRQA S 1-10000 // NOLINT

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides a printf like function that is implemented using
    ///     a technique similar to the technique implemented by {fmt}. Note
    ///     that this function does not throw, nor does it return an error.
    ///     If an error occurs, it is ignored and the function returns. Also,
    ///     if fputs() is not defined, you must define it as this function
    ///     uses fputs() to actually output to the console.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam ARGS defines the types of arguments passed to this function
    ///   @param fmt the format string that defines what to print
    ///   @param args the associated arguments for the given format string
    ///
    template<typename CharT, bsl::uintmax N, typename... ARGS>
    constexpr void
    print(CharT const (&fmt)[N], ARGS &&... args) noexcept    // NOLINT
    {                                                         // PRQA S 1-10000 // NOLINT
#pragma clang diagnostic push                                 // PRQA S 1-10000 // NOLINT
#pragma clang diagnostic ignored "-Wformat-security"          // PRQA S 1-10000 // NOLINT
#pragma clang diagnostic ignored "-Wformat-nonliteral"        // PRQA S 1-10000 // NOLINT
        std::printf(fmt, args...);                            // PRQA S 1-10000 // NOLINT
#pragma clang diagnostic pop                                  // PRQA S 1-10000 // NOLINT
    }                                                         // PRQA S 1-10000 // NOLINT

#pragma clang diagnostic push                             // PRQA S 1-10000 // NOLINT
#pragma clang diagnostic ignored "-Wformat-security"      // PRQA S 1-10000 // NOLINT
#pragma clang diagnostic ignored "-Wformat-nonliteral"    // PRQA S 1-10000 // NOLINT

    template<bsl::uintmax N, typename... ARGS>
    constexpr void
    print2(const char (&arr)[N], ARGS &&... args) noexcept    // NOLINT
    {
        // constexpr bsl::view yourmom{arr};
        std::printf(arr, args...);    // PRQA S 1-10000 // NOLINT
    }                                 // PRQA S 1-10000 // NOLINT

#pragma clang diagnostic pop    // PRQA S 1-10000 // NOLINT

}

#endif

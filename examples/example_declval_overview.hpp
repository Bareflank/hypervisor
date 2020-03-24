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

#ifndef EXAMPLE_DECLVAL_OVERVIEW_HPP
#define EXAMPLE_DECLVAL_OVERVIEW_HPP

#include <bsl/declval.hpp>
#include <bsl/is_same.hpp>
#include "example_class_nodefault.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    inline void
    example_declval_overview() noexcept
    {
        using example_declval_type =    // --
            decltype(bsl::declval<example_class_nodefault>().get());

        if (bsl::is_same<example_declval_type, bool>::value) {
            bsl::print("success\n");
        }
    }
}

#endif

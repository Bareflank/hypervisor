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

#ifndef EXAMPLE_DELEGATE_OVERVIEW_HPP
#define EXAMPLE_DELEGATE_OVERVIEW_HPP

#include <bsl/delegate.hpp>
#include <bsl/print.hpp>

#include "example_function.hpp"
#include "example_class_subclass.hpp"

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
    example_delegate_overview() noexcept
    {
        example_class_subclass const c;
        bsl::delegate const func1{&example_function};
        bsl::delegate const func2{c, &example_class_subclass::get};

        auto const res1{func1(true)};
        if (auto const val = res1.get_if()) {
            if (*val) {
                bsl::print("success\n");
            }
        }

        auto const res2{func2()};
        if (auto const val = res2.get_if()) {
            if (*val) {
                bsl::print("success\n");
            }
        }
    }
}

#endif

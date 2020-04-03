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
///
/// @file declval.hpp
///

#ifndef BSL_DECLVAL_HPP
#define BSL_DECLVAL_HPP

#include "add_rvalue_reference.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Converts any type T to a reference type, making it possible
    ///     to use member functions in decltype expressions without the need
    ///     to go through constructors.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type T to get a reference type from
    ///   @return Cannot be called and thus never returns a value. The return
    ///     type is T&& unless T is (possibly cv-qualified) void, in which
    ///     case the return type is T.
    ///
    template<typename T>
    constexpr add_rvalue_reference_t<T> declval() noexcept;
}

#endif

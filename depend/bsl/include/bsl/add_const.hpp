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
/// @file add_const.hpp
///

#ifndef BSL_ADD_CONST_HPP
#define BSL_ADD_CONST_HPP

#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::add_const
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T,
    ///     except that a topmost const qualifier is added.
    ///   @include example_add_const_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to add a const qualifier to
    ///
    template<typename T>
    class add_const final : public type_identity<T const>
    {};

    /// @brief a helper that reduces the verbosity of bsl::add_const
    template<typename T>
    using add_const_t = typename add_const<T>::type;

    /// @cond doxygen off

    template<typename T>
    class add_const<T const> final : public type_identity<T const>
    {};

    /// @endcond doxygen on
}

#endif

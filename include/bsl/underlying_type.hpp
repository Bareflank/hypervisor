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
/// @file underlying_type.hpp
///

#ifndef BSL_UNDERLYING_TYPE_HPP
#define BSL_UNDERLYING_TYPE_HPP

#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::underlying_type
    ///
    /// <!-- description -->
    ///   @brief If T is a complete enumeration type, provides a member typedef
    ///     type that names the underlying type of T.
    ///   @include example_enum.hpp
    ///   @include example_underlying_type_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    class underlying_type final :    // --
        public type_identity<__underlying_type(T)>
    {};

    /// @brief a helper that reduces the verbosity of bsl::underlying_type
    template<typename T>
    using underlying_type_t = typename underlying_type<T>::type;
}

#endif

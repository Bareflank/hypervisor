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
/// @file is_signed.hpp
///

#ifndef BSL_IS_SIGNED_HPP
#define BSL_IS_SIGNED_HPP

#include "bool_constant.hpp"
#include "cstdint.hpp"
#include "is_floating_point.hpp"
#include "true_type.hpp"

namespace bsl
{
    /// @class bsl::is_signed
    ///
    /// <!-- description -->
    ///   @brief If the provided type is a signed type (taking into account
    ///     const qualifications), provides the member constant value
    ///     equal to true. Otherwise the member constant value is false.
    ///   @include example_is_signed_overview.hpp
    ///
    /// <!-- notes -->
    ///   @note We only support the cstdint.hpp basic fixed-width types
    ///     which is different compared to the standard library version of
    ///     this type trait. This is because, the fixed-width types are the
    ///     only types that we support.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    class is_signed final :    // --
        public bool_constant<is_floating_point<T>::value>
    {};

    /// @cond doxygen off

    template<>
    class is_signed<bsl::int8> final : public true_type
    {};

    template<>
    class is_signed<bsl::int8 const> final : public true_type
    {};

    template<>
    class is_signed<bsl::int16> final : public true_type
    {};

    template<>
    class is_signed<bsl::int16 const> final : public true_type
    {};

    template<>
    class is_signed<bsl::int32> final : public true_type
    {};

    template<>
    class is_signed<bsl::int32 const> final : public true_type
    {};

    template<>
    class is_signed<bsl::int64> final : public true_type
    {};

    template<>
    class is_signed<bsl::int64 const> final : public true_type
    {};

    /// @endcond doxygen on
}

#endif

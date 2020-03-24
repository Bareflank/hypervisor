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
/// @file is_fundamental.hpp
///

#ifndef BSL_IS_FUNDAMENTAL_HPP
#define BSL_IS_FUNDAMENTAL_HPP

#include "bool_constant.hpp"
#include "is_arithmetic.hpp"
#include "is_void.hpp"
#include "is_null_pointer.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Checks if the provided type "T" is a fundamental type
        ///     and if so, returns true, otherwise returns false.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type to query
        ///   @return Returns true if "T" is fundamental, false otherwise.
        ///
        template<typename T>
        [[nodiscard]] constexpr bool
        check_is_fundamental() noexcept
        {
            if (is_arithmetic<T>::value) {
                return true;
            }

            if (is_void<T>::value) {
                return true;
            }

            return is_null_pointer<T>::value;
        }
    }

    /// @class bsl::is_fundamental
    ///
    /// <!-- description -->
    ///   @brief If the provided type is a fundamental type, provides the member
    ///     constant value equal to true. Otherwise the member constant value
    ///     is false.
    ///   @include example_is_fundamental_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    class is_fundamental final : public bool_constant<details::check_is_fundamental<T>()>
    {};
}

#endif

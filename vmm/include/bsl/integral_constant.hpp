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
/// @file integral_constant.hpp
///

#ifndef BSL_INTEGRAL_CONSTANT_HPP
#define BSL_INTEGRAL_CONSTANT_HPP

namespace bsl
{
    /// @class bsl::integral_constant
    ///
    /// <!-- description -->
    ///   @brief If the provided type is an array type (taking into account
    ///     const qualifications), provides the member constant value
    ///     equal to true. Otherwise the member constant value is false.
    ///   @include example_integral_constant_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of integral being stored
    ///
    template<typename T, T v>
    class integral_constant
    {
    public:
        /// @brief provides the member typedef "type"
        using type = integral_constant<T, v>;
        /// @brief provides the member typedef "value_type"
        using value_type = T;

        /// @brief the type T that stores the integral constant
        static constexpr value_type value{v};

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::integral_constant
        ///
        ~integral_constant() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr integral_constant(integral_constant const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr integral_constant(integral_constant &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        constexpr integral_constant &operator=(integral_constant const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        constexpr integral_constant &operator=(integral_constant &&o) &noexcept = default;
    };
}

#endif

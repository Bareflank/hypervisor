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
/// @file value_type_identity.hpp
///

#ifndef BSL_VALUE_TYPE_IDENTITY_HPP
#define BSL_VALUE_TYPE_IDENTITY_HPP

namespace bsl
{
    /// @class bsl::value_type_identity
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef "value_type" that names T.
    ///   @include example_value_type_identity_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type that defines the member typedef "value_type"
    ///
    template<typename T>
    class value_type_identity
    {
    public:
        /// @brief the member typedef "value_type" being provided
        using value_type = T;

        /// <!-- description -->
        ///   @brief default constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        constexpr value_type_identity() noexcept = default;

    protected:
        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr value_type_identity(value_type_identity const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr value_type_identity(value_type_identity &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr value_type_identity &    // --
        operator=(value_type_identity const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr value_type_identity &    // --
        operator=(value_type_identity &&o) &noexcept = default;

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::value_type_identity
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~value_type_identity() noexcept = default;
    };

    /// @brief a helper that reduces the verbosity of bsl::value_type_identity
    template<typename T>
    using value_type_identity_t = typename value_type_identity<T>::value_type;
}

#endif

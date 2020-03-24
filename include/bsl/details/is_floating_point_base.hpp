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
/// @file is_floating_point_base.hpp
///

#ifndef BSL_DETAILS_IS_FLOATING_POINT_BASE_HPP
#define BSL_DETAILS_IS_FLOATING_POINT_BASE_HPP

#include "../true_type.hpp"
#include "../false_type.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::is_floating_point_base
        ///
        /// <!-- description -->
        ///   @brief If the provided type is a float type (taking into account
        ///     const qualifications), provides the member constant value
        ///     equal to true. Otherwise the member constant value is false.
        ///
        /// <!-- notes -->
        ///   @note We do not support floating point numbers. This is only
        ///     implemented so that we can detect attempts to use floating
        ///     point types and error out.
        ///
        /// <!-- template parameters -->
        ///   @tparam T the type to query
        ///
        template<typename T>
        class is_floating_point_base : public false_type
        {
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
            constexpr is_floating_point_base(is_floating_point_base const &o) noexcept = default;

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
            constexpr is_floating_point_base(is_floating_point_base &&o) noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::is_floating_point_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~is_floating_point_base() noexcept = default;
        };

        /// @class bsl::is_floating_point_base
        ///
        /// <!-- description -->
        ///   @brief If the provided type is a float type (taking into account
        ///     const qualifications), provides the member constant value
        ///     equal to true. Otherwise the member constant value is false.
        ///
        ///   SUPPRESSION: PRQA 2427 - false positive
        ///   - We suppress this because A3-9-1 states that the fixed width
        ///     types shall be used instead of the non-fixed width types. These
        ///     are floating point numbers which are allowed by the spec.
        ///
        /// <!-- notes -->
        ///   @note We do not support floating point numbers. This is only
        ///     implemented so that we can detect attempts to use floating
        ///     point types and error out.
        ///
        template<>
        class is_floating_point_base<float> : public true_type    // PRQA S 2427
        {
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
            constexpr is_floating_point_base(is_floating_point_base const &o) noexcept = default;

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
            constexpr is_floating_point_base(is_floating_point_base &&o) noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::is_floating_point_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~is_floating_point_base() noexcept = default;
        };

        /// @class bsl::is_floating_point_base
        ///
        /// <!-- description -->
        ///   @brief If the provided type is a float type (taking into account
        ///     const qualifications), provides the member constant value
        ///     equal to true. Otherwise the member constant value is false.
        ///
        ///   SUPPRESSION: PRQA 2427 - false positive
        ///   - We suppress this because A3-9-1 states that the fixed width
        ///     types shall be used instead of the non-fixed width types. These
        ///     are floating point numbers which are allowed by the spec.
        ///
        /// <!-- notes -->
        ///   @note We do not support floating point numbers. This is only
        ///     implemented so that we can detect attempts to use floating
        ///     point types and error out.
        ///
        template<>
        class is_floating_point_base<float const> : public true_type    // PRQA S 2427
        {
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
            constexpr is_floating_point_base(is_floating_point_base const &o) noexcept = default;

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
            constexpr is_floating_point_base(is_floating_point_base &&o) noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::is_floating_point_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~is_floating_point_base() noexcept = default;
        };

        /// @class bsl::is_floating_point_base
        ///
        /// <!-- description -->
        ///   @brief If the provided type is a float type (taking into account
        ///     const qualifications), provides the member constant value
        ///     equal to true. Otherwise the member constant value is false.
        ///
        ///   SUPPRESSION: PRQA 2427 - false positive
        ///   - We suppress this because A3-9-1 states that the fixed width
        ///     types shall be used instead of the non-fixed width types. These
        ///     are floating point numbers which are allowed by the spec.
        ///
        /// <!-- notes -->
        ///   @note We do not support floating point numbers. This is only
        ///     implemented so that we can detect attempts to use floating
        ///     point types and error out.
        ///
        template<>
        class is_floating_point_base<double> : public true_type    // PRQA S 2427
        {
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
            constexpr is_floating_point_base(is_floating_point_base const &o) noexcept = default;

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
            constexpr is_floating_point_base(is_floating_point_base &&o) noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::is_floating_point_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~is_floating_point_base() noexcept = default;
        };

        /// @class bsl::is_floating_point_base
        ///
        /// <!-- description -->
        ///   @brief If the provided type is a float type (taking into account
        ///     const qualifications), provides the member constant value
        ///     equal to true. Otherwise the member constant value is false.
        ///
        ///   SUPPRESSION: PRQA 2427 - false positive
        ///   - We suppress this because A3-9-1 states that the fixed width
        ///     types shall be used instead of the non-fixed width types. These
        ///     are floating point numbers which are allowed by the spec.
        ///
        /// <!-- notes -->
        ///   @note We do not support floating point numbers. This is only
        ///     implemented so that we can detect attempts to use floating
        ///     point types and error out.
        ///
        template<>
        class is_floating_point_base<double const> : public true_type    // PRQA S 2427
        {
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
            constexpr is_floating_point_base(is_floating_point_base const &o) noexcept = default;

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
            constexpr is_floating_point_base(is_floating_point_base &&o) noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::is_floating_point_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~is_floating_point_base() noexcept = default;
        };

        /// @class bsl::is_floating_point_base
        ///
        /// <!-- description -->
        ///   @brief If the provided type is a float type (taking into account
        ///     const qualifications), provides the member constant value
        ///     equal to true. Otherwise the member constant value is false.
        ///
        ///   SUPPRESSION: PRQA 2427 - false positive
        ///   - We suppress this because A3-9-1 states that the fixed width
        ///     types shall be used instead of the non-fixed width types. These
        ///     are floating point numbers which are allowed by the spec.
        ///
        ///   SUPPRESSION: PRQA 2441 - false positive
        ///   - We suppress this because A0-4-2 states that long double should
        ///     not be used. This is a false positive because long double is
        ///     not used here to define a type, but rather to provide a
        ///     specialization, which is needed to ensure long double is not
        ///     used.
        ///
        /// <!-- notes -->
        ///   @note We do not support floating point numbers. This is only
        ///     implemented so that we can detect attempts to use floating
        ///     point types and error out.
        ///
        template<>
        class is_floating_point_base<long double> : public true_type    // PRQA S 2427, 2441
        {
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
            constexpr is_floating_point_base(is_floating_point_base const &o) noexcept = default;

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
            constexpr is_floating_point_base(is_floating_point_base &&o) noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::is_floating_point_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~is_floating_point_base() noexcept = default;
        };

        /// @class bsl::is_floating_point_base
        ///
        /// <!-- description -->
        ///   @brief If the provided type is a float type (taking into account
        ///     const qualifications), provides the member constant value
        ///     equal to true. Otherwise the member constant value is false.
        ///
        ///   SUPPRESSION: PRQA 2427 - false positive
        ///   - We suppress this because A3-9-1 states that the fixed width
        ///     types shall be used instead of the non-fixed width types. These
        ///     are floating point numbers which are allowed by the spec.
        ///
        ///   SUPPRESSION: PRQA 2441 - false positive
        ///   - We suppress this because A0-4-2 states that long double should
        ///     not be used. This is a false positive because long double is
        ///     not used here to define a type, but rather to provide a
        ///     specialization, which is needed to ensure long double is not
        ///     used.
        ///
        /// <!-- notes -->
        ///   @note We do not support floating point numbers. This is only
        ///     implemented so that we can detect attempts to use floating
        ///     point types and error out.
        ///
        template<>
        class is_floating_point_base<long double const> : public true_type    // PRQA S 2427, 2441
        {
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
            constexpr is_floating_point_base(is_floating_point_base const &o) noexcept = default;

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
            constexpr is_floating_point_base(is_floating_point_base &&o) noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base const &o) &noexcept = default;

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
            [[maybe_unused]] constexpr is_floating_point_base &    // --
            operator=(is_floating_point_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::is_floating_point_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~is_floating_point_base() noexcept = default;
        };
    }
}

#endif

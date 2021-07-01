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

#ifndef MOCKS_INTRINSIC_HPP
#define MOCKS_INTRINSIC_HPP

#include <gs_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>

namespace example
{
    /// @class example::intrinsic_t
    ///
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics used for unit testing.
    ///     Specifically, this version only contains portions that are common
    ///     for all architectures.
    ///
    class intrinsic_t final
    {
        /// @brief stores the return value for initialize
        bsl::errc_type m_initialize{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this intrinsic_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(gs_t const &gs, tls_t const &tls) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);

            return m_initialize;
        }

        /// <!-- description -->
        ///   @brief Sets the return value of initialize.
        ///     (unit testing only)
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the bsl::errc_type to return when executing
        ///     initialize
        ///
        constexpr void
        set_initialize(bsl::errc_type const &errc) noexcept
        {
            m_initialize = errc;
        }

        /// <!-- description -->
        ///   @brief Release the intrinsic_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///
        static constexpr void
        release(gs_t const &gs, tls_t const &tls) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
        }
    };
}

#endif

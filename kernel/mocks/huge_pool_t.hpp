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

#ifndef MOCKS_HUGE_POOL_T_HPP
#define MOCKS_HUGE_POOL_T_HPP

#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief If you see this function in an error, it means that you are
    ///     attempting to perform a deallocation on a nullptr. This is not
    ///     allowed, although at runtime this will be safely handled.
    ///
    inline void
    attempting_to_deallocate_nullptr() noexcept
    {}

    /// @class mk::huge_pool_t
    ///
    /// <!-- description -->
    ///   @brief Implements a mocked version of huge_pool_t.
    ///
    class huge_pool_t final
    {
        /// @brief if true, allocate() returns nullptr
        bool m_allocate_fails{};

    public:
        /// <!-- description -->
        ///   @brief Allocates memory from the huge pool.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param size the total number of bytes to allocate.
        ///   @return Returns bsl::span containing the allocated memory
        ///
        [[nodiscard]] constexpr auto
        allocate(tls_t &tls, bsl::safe_uintmax const &size) noexcept -> bsl::span<bsl::uint8>
        {
            bsl::discard(tls);

            if (bsl::unlikely(!size)) {
                bsl::error() << "invalid size "    // --
                             << bsl::hex(size)     // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return {};
            }

            if (bsl::unlikely(size.is_zero())) {
                bsl::error() << "invalid size "    // --
                             << bsl::hex(size)     // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return {};
            }

            if (m_allocate_fails) {
                return {};
            }

            return {new bsl::uint8[size.get()], size.get()};
        }

        /// <!-- description -->
        ///   @brief If set to true, allocate() returns nullptr.
        ///
        /// <!-- inputs/outputs -->
        ///   @param fails if true, allocate() returns nullptr.
        ///
        constexpr void
        set_allocate_fails(bool const fails) noexcept
        {
            m_allocate_fails = fails;
        }

        /// <!-- description -->
        ///   @brief Not supported
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param buf the bsl::span containing the memory to deallocate
        ///
        constexpr void
        deallocate(tls_t &tls, bsl::span<bsl::uint8> const &buf) noexcept
        {
            bsl::discard(tls);

            if (bsl::unlikely(!buf)) {
                attempting_to_deallocate_nullptr();
                bsl::error() << "attempting to deallocate nullptr\n" << bsl::here();
                return;
            }

            delete[] buf.data();    // GRCOV_EXCLUDE_BR
        }

        /// <!-- description -->
        ///   @brief Dumps the page_pool_t
        ///
        constexpr void
        dump() const noexcept
        {}
    };
}

#endif

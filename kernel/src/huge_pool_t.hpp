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

#ifndef HUGE_POOL_T_HPP
#define HUGE_POOL_T_HPP

#include <bsl/byte.hpp>
#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/span.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// @class mk::huge_pool_t
    ///
    /// <!-- description -->
    ///   @brief TODO
    ///
    class huge_pool_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores the range of memory used by this allocator
        bsl::span<bsl::byte> m_pool{};
        /// @brief stores the virtual address base of the page pool.
        bsl::safe_uintmax m_base_virt{};
        /// @brief stores the huge pool's cursor
        bsl::safe_uintmax m_cursor{};

    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr huge_pool_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates the page pool given a mutable_buffer_t to
        ///     the page pool as well as the virtual address base of the
        ///     page pool which is used for virt to phys translations.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pool the mutable_buffer_t of the page pool
        ///   @param base_virt the base virtual address base of the page pool
        ///        constexpr bsl::errc_type
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(bsl::span<bsl::byte> &pool, bsl::safe_uintmax const &base_virt) &noexcept
            -> bsl::errc_type
        {
            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "huge_pool_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            if (bsl::unlikely(pool.empty())) {
                m_pool = {};
                m_base_virt = bsl::safe_uintmax::zero(true);
                m_cursor = bsl::safe_uintmax::zero(true);

                bsl::error() << "pool is empty\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(base_virt.is_zero())) {
                m_pool = {};
                m_base_virt = bsl::safe_uintmax::zero(true);
                m_cursor = bsl::safe_uintmax::zero(true);

                bsl::error() << "base_virt is 0 or invalid\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_pool = pool;
            m_base_virt = base_virt;
            m_cursor = bsl::ZERO_UMAX;

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the huge_pool_t
        ///
        constexpr void
        release() &noexcept
        {
            m_cursor = bsl::safe_uintmax::zero(true);
            m_base_virt = bsl::safe_uintmax::zero(true);
            m_pool = {};

            m_initialized = {};
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created huge_pool_t
        ///
        constexpr ~huge_pool_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr huge_pool_t(huge_pool_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr huge_pool_t(huge_pool_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(huge_pool_t const &o) &noexcept
            -> huge_pool_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(huge_pool_t &&o) &noexcept
            -> huge_pool_t & = default;
    };
}

#endif

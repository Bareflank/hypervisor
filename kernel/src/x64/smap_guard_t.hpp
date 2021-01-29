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

#ifndef SMAP_GUARD_HPP
#define SMAP_GUARD_HPP

#include <bsl/is_constant_evaluated.hpp>

namespace mk
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Unlocks SMAP
        ///
        extern "C" void unlock_smap() noexcept;

        /// <!-- description -->
        ///   @brief Locks SMAP
        ///
        extern "C" void lock_smap() noexcept;
    }

    /// @class mk::smap_guard_t
    ///
    /// <!-- description -->
    ///   @brief Ensures that user-space memory is accessible from the
    ///     microkernel. Once this class loses scope, extension memory may
    ///     no longer be accessible.
    ///
    class smap_guard_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr smap_guard_t() noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            details::unlock_smap();
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~smap_guard_t() noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            details::lock_smap();
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr smap_guard_t(smap_guard_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr smap_guard_t(smap_guard_t &&o) noexcept = delete;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(smap_guard_t const &o) &noexcept
            -> smap_guard_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(smap_guard_t &&o) &noexcept
            -> smap_guard_t & = delete;
    };
}

#endif

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

#ifndef MOCKS_SPINLOCK_T_HPP
#define MOCKS_SPINLOCK_T_HPP

#include <bf_constants.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>

namespace mk
{
    /// @class mk::spinlock_t
    ///
    /// <!-- description -->
    ///   @brief Implements a mocked version of spinlock_t
    ///
    /// <!-- notes -->
    ///   @note This spinlock_t is designed to detect and prevent deadlock
    ///     when the same PP attempts to take the lock more than once. This
    ///     could occur for example if a hardware exception fires before
    ///     the lock is released. It also handles the case when the lock is
    ///     taken, and then an ESR fires that is legit and must take the
    ///     lock as well.
    ///
    class spinlock_t final
    {
        /// @brief stores whether or not the spin lock is locked.
        bool m_flag{};

    public:
        /// <!-- description -->
        ///   @brief Locks the spinlock_t. This will not return until the
        ///     spinlock_t can be successfully acquired.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        lock(tls_t const &tls) noexcept
        {
            bsl::discard(tls);
            m_flag = true;
        }

        /// <!-- description -->
        ///   @brief Unlocks the spinlock_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///
        constexpr void
        unlock(tls_t const &tls) noexcept
        {
            bsl::discard(tls);
            m_flag = false;
        }

        /// <!-- description -->
        ///   @brief Returns true if the spinlock_t is locked
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the spinlock_t is locked
        ///
        [[nodiscard]] constexpr auto
        is_locked() const noexcept -> bool
        {
            return m_flag;
        }
    };
}

#endif

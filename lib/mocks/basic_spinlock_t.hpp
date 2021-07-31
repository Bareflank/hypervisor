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

#ifndef MOCK_BASIC_SPINLOCK_T_HPP
#define MOCK_BASIC_SPINLOCK_T_HPP

#include <bsl/discard.hpp>

namespace lib
{
    /// @class lib::basic_spinlock_t
    ///
    /// <!-- description -->
    ///   @brief Implements a mocked version of basic_spinlock_t
    ///
    /// <!-- notes -->
    ///   @note Implements a basic_spinlock_t. Unlike the std::lock_guard_t
    ///     this lock is aware of which PP has acquired the lock. If the same
    ///     PP attempts to acquire the lock, the lock is ignored, and a
    ///     warning is outputted.
    ///
    class basic_spinlock_t final
    {
        /// @brief stores whether or not the spin lock is locked.
        bool m_flag{};

    public:
        /// <!-- description -->
        ///   @brief Locks the basic_spinlock_t. This will not return until the
        ///     basic_spinlock_t can be successfully acquired.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_TYPE the type of TLS block to use
        ///   @param tls the current TLS block
        ///
        template<typename TLS_TYPE>
        constexpr void
        lock(TLS_TYPE const &tls) noexcept
        {
            bsl::discard(tls);
            m_flag = true;
        }

        /// <!-- description -->
        ///   @brief Unlocks the basic_spinlock_t.
        ///
        constexpr void
        unlock() noexcept
        {
            m_flag = false;
        }

        /// <!-- description -->
        ///   @brief Returns true if the basic_spinlock_t is locked
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the basic_spinlock_t is locked
        ///
        [[nodiscard]] constexpr auto
        is_locked() const noexcept -> bool
        {
            return m_flag;
        }
    };
}

#endif

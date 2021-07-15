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

#ifndef LOCK_GUARD_T_HPP
#define LOCK_GUARD_T_HPP

#include <tls_t.hpp>

namespace mk
{
    /// @class mk::lock_guard_t
    ///
    /// <!-- description -->
    ///   @brief Implements a lock_guard_t. Unlike the std::lock_guard_t this lock
    ///     guard is aware of which PP has acquired the lock. If the same
    ///     PP attempts to acquire the lock, the lock is ignored, and a
    ///     warning is outputted. This prevents deadlock, for example, when
    ///     a lock was not released due to a hardware exception, or when
    ///     the programmer makes a mistake.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of mutex being locked
    ///
    template<typename T>
    class lock_guard_t final
    {
        /// @brief stores the TLS that owns the lock
        tls_t const &m_tls;
        /// @brief stores the lock that is being guarded
        T &m_lock;

    public:
        /// <!-- description -->
        ///   @brief Creates a lock_guard_t, locking the provided
        ///     spinlock/mutex on construction.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param mut_lck the spinlock/mutex to guard
        ///
        constexpr lock_guard_t(tls_t const &tls, T &mut_lck) noexcept    // --
            : m_tls{tls}, m_lock{mut_lck}
        {
            m_lock.lock(m_tls);
        }

        /// <!-- description -->
        ///   @brief Do not allow temporaries.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param lck the spinlock/mutex to guard
        ///
        constexpr lock_guard_t(tls_t const &tls, T const &lck) noexcept = delete;

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~lock_guard_t() noexcept
        {
            m_lock.unlock(m_tls);
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr lock_guard_t(lock_guard_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr lock_guard_t(lock_guard_t &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(lock_guard_t const &o) &noexcept -> lock_guard_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(lock_guard_t &&mut_o) &noexcept -> lock_guard_t & = default;
    };
}

#endif

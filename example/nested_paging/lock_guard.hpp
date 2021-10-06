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

#ifndef LOCK_GUARD_HPP
#define LOCK_GUARD_HPP

namespace example
{
    /// <!-- description -->
    ///   @brief Implements a lock_guard.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of mutex being locked
    ///
    template<typename T>
    class lock_guard final
    {
        /// @brief stores the lock that is being guarded
        T &m_lock;

    public:
        /// <!-- description -->
        ///   @brief Creates a lock_guard, locking the provided
        ///     spinlock/mutex on construction.
        ///
        /// <!-- inputs/outputs -->
        ///   @param lck the spinlock/mutex to guard
        ///
        explicit constexpr lock_guard(T &lck) noexcept    // --
            : m_lock{lck}
        {
            m_lock.lock();
        }

        /// <!-- description -->
        ///   @brief Do not allow temporaries.
        ///
        /// <!-- inputs/outputs -->
        ///   @param lck the spinlock/mutex to guard
        ///
        constexpr lock_guard(T const &lck) noexcept = delete;

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~lock_guard() noexcept
        {
            m_lock.unlock();
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr lock_guard(lock_guard const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr lock_guard(lock_guard &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(lock_guard const &o) noexcept -> lock_guard & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(lock_guard &&o) noexcept -> lock_guard & = default;
    };
}

#endif

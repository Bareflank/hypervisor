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

#ifndef SPINLOCK_HPP
#define SPINLOCK_HPP

#include <bsl/is_constant_evaluated.hpp>

#pragma clang diagnostic ignored "-Watomic-implicit-seq-cst"

namespace example
{
    /// <!-- description -->
    ///   @brief Implements a spinlock
    ///
    class spinlock final
    {
        /// @brief stores whether or not the lock is acquired
        _Atomic bool m_flag;

    public:
        /// <!-- description -->
        ///   @brief Default constructor.
        ///
        // We cannot member initialize atomics so this is not possible
        // NOLINTNEXTLINE(bsl-class-member-init)
        constexpr spinlock() noexcept
        {
            // This is the only way to initialize this
            // NOLINTNEXTLINE(bsl-implicit-conversions-forbidden)
            m_flag = false;
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~spinlock() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr spinlock(spinlock const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr spinlock(spinlock &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(spinlock const &o) noexcept -> spinlock & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(spinlock &&o) noexcept -> spinlock & = default;

        /// <!-- description -->
        ///   @brief Locks the spinlock. This will not return until the
        ///     spinlock can be successfully acquired.
        ///
        constexpr void
        lock() noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            while (__c11_atomic_exchange(&m_flag, true, __ATOMIC_ACQUIRE)) {
                while (__c11_atomic_load(&m_flag, __ATOMIC_RELAXED)) {
                }
            }
        }

        /// <!-- description -->
        ///   @brief Unlocks the spinlock.
        ///
        constexpr void
        unlock() noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            __c11_atomic_store(&m_flag, false, __ATOMIC_RELEASE);
        }
    };
}

#endif

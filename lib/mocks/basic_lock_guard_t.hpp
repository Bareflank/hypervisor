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

#ifndef MOCK_BASIC_LOCK_GUARD_T_HPP
#define MOCK_BASIC_LOCK_GUARD_T_HPP

namespace lib
{
    /// @class lib::basic_lock_guard_t
    ///
    /// <!-- description -->
    ///   @brief Implements a basic_lock_guard_t. Unlike the std::basic_lock_guard_t this
    ///     lock guard is aware of which PP has acquired the lock. If the same
    ///     PP attempts to acquire the lock, the lock is ignored, and a
    ///     warning is outputted.
    ///
    /// <!-- template parameters -->
    ///   @tparam L the type of mutex being locked
    ///
    template<typename L>
    class basic_lock_guard_t final
    {
        /// @brief stores the lock that is being guarded
        L &m_lock;

    public:
        /// <!-- description -->
        ///   @brief Creates a basic_lock_guard_t, locking the provided
        ///     lock on construction.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_TYPE the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param mut_lck the lock to guard
        ///
        template<typename TLS_TYPE>
        constexpr basic_lock_guard_t(TLS_TYPE const &tls, L &mut_lck) noexcept    // --
            : m_lock{mut_lck}
        {
            m_lock.lock(tls);
        }

        /// <!-- description -->
        ///   @brief Do not allow temporaries.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_TYPE the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param lck the lock to guard
        ///
        template<typename TLS_TYPE>
        constexpr basic_lock_guard_t(TLS_TYPE const &tls, L const &lck) noexcept = delete;

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~basic_lock_guard_t() noexcept
        {
            m_lock.unlock();
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr basic_lock_guard_t(basic_lock_guard_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///
        constexpr basic_lock_guard_t(basic_lock_guard_t &&mut_o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(basic_lock_guard_t const &o) &noexcept
            -> basic_lock_guard_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] auto operator=(basic_lock_guard_t &&mut_o) &noexcept
            -> basic_lock_guard_t & = default;
    };
}

#endif

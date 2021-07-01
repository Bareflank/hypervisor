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

#ifndef MOCKS_LOCK_GUARD_T_HPP
#define MOCKS_LOCK_GUARD_T_HPP

#include <tls_t.hpp>

#include <bsl/discard.hpp>

namespace mk
{
    /// @class mk::lock_guard_t
    ///
    /// <!-- description -->
    ///   @brief Implements a mocked version of lock_guard_t.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of mutex being locked
    ///
    template<typename T>
    class lock_guard_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Creates a lock_guard_t, locking the provided
        ///     spinlock/mutex on construction.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param lck the spinlock/mutex to guard
        ///
        constexpr lock_guard_t(tls_t const &tls, T const &lck) noexcept    // --
        {
            bsl::discard(tls);
            bsl::discard(lck);
        }
    };
}

#endif

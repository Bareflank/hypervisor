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

#ifndef BASIC_ENTRIES_T_HPP
#define BASIC_ENTRIES_T_HPP

namespace lib
{
    /// <!-- description -->
    ///   @brief Returns the result of get_entries(), providing all of the
    ///     entries seen during a translation.
    ///
    ///
    /// <!-- template parameters -->
    ///   @tparam L3E_TYPE the type of level-3 table to use
    ///   @tparam L2E_TYPE the type of level-2 table to use
    ///   @tparam L1E_TYPE the type of level-1 table to use
    ///   @tparam L0E_TYPE the type of level-0 table to use
    ///
    template<typename L3E_TYPE, typename L2E_TYPE, typename L1E_TYPE, typename L0E_TYPE>
    struct basic_entries_t final
    {
        /// @brief a pointer to the resulting l3e_t
        L3E_TYPE *l3e;
        /// @brief a pointer to the resulting l2e_t
        L2E_TYPE *l2e;
        /// @brief a pointer to the resulting l1e_t
        L1E_TYPE *l1e;
        /// @brief a pointer to the resulting l0e_t
        L0E_TYPE *l0e;
    };
}

#endif

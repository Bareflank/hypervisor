/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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
///
/// @file addressof.hpp
///

#ifndef BSL_ADDRESSOF_HPP
#define BSL_ADDRESSOF_HPP

namespace bsl
{
    /// <!-- description -->
    ///   @brief Obtains the actual address of the object or function arg,
    ///     even in presence of overloaded operator& (i.e., this should be
    ///     used to get the address of an object instead of using & as
    ///     that could be unsafe).
    ///   @include example_addressof_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of object to get the address of.
    ///   @param val the object of type T to get the address of.
    ///   @return Returns the address of val
    ///
    template<typename T>
    [[nodiscard]] constexpr T *
    addressof(T &val) noexcept
    {
        return __builtin_addressof(val);
    }

    /// <!-- description -->
    ///   @brief Prevents the user from getting an address to a const as that
    ///     would allow you to get the address of an rvalue which could result
    ///     in UB.
    ///   @include example_addressof_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of object to get the address of.
    ///   @param val the object of type T to get the address of.
    ///   @return Returns the address of val
    ///
    template<typename T>
    T const *addressof(T const &&val) = delete;
}

#endif

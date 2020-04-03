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
///
/// @file enable_if.hpp
///

#ifndef BSL_ENABLE_IF_HPP
#define BSL_ENABLE_IF_HPP

namespace bsl
{
    /// @class bsl::enable_if
    ///
    /// <!-- description -->
    ///   @brief Defines a conditional "if" statement for SFINAE overload
    ///     resolution. If B is true, bsl::enable_if has a public member
    ///     typedef of type T, otherwise, there is no public member typedef.
    ///   @include example_enable_if_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam B if B is true, bsl::enable_if has a public member
    ///     typedef of type T, otherwise, there is no public member typedef.
    ///   @tparam T the type of typedef that is defined if B is true
    ///
    template<bool B, typename T = void>
    struct enable_if final
    {};

    /// @brief a helper that reduces the verbosity of bsl::enable_if
    template<bool B, typename T = void>
    using enable_if_t = typename enable_if<B, T>::type;

    /// @cond doxygen off

    template<typename T>
    struct enable_if<true, T> final
    {
        /// @brief provides the member typedef "type"
        using type = T;
    };

    /// @endcond doxygen on
}

#endif

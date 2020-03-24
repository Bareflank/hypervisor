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
/// @file remove_extent.hpp
///

#ifndef BSL_REMOVE_EXTENT_HPP
#define BSL_REMOVE_EXTENT_HPP

#include "cstdint.hpp"
#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::remove_extent
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T,
    ///     except that its topmost extent is removed.
    ///   @include example_remove_extent_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to remove the extent from
    ///
    template<typename T>
    class remove_extent final : public type_identity<T>
    {};

    /// @brief a helper that reduces the verbosity of bsl::remove_extent
    template<typename T>
    using remove_extent_t = typename remove_extent<T>::type;

    /// @cond doxygen off

    template<typename T>
    struct remove_extent<T[]> final : public type_identity<T>    // NOLINT
    {};

    template<typename T, bsl::uintmax N>
    struct remove_extent<T[N]> final : public type_identity<T>    // NOLINT
    {};

    /// @endcond doxygen on
}

#endif

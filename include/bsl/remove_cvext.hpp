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
/// @file remove_cvext.hpp
///

#ifndef BSL_REMOVE_CVEXT_HPP
#define BSL_REMOVE_CVEXT_HPP

#include "remove_all_extents.hpp"
#include "remove_cv.hpp"

namespace bsl
{
    /// @class bsl::remove_cvext
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T,
    ///     except that its topmost const, volatile and extent qualifiers
    ///     are removed.
    ///   @include example_remove_cvext_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to remove the const, volatile and extent
    ///     qualifiers from
    ///
    template<typename T>
    class remove_cvext final :    // --
        public type_identity<remove_cv_t<remove_all_extents_t<T>>>
    {};

    /// @brief a helper that reduces the verbosity of bsl::remove_cvext
    template<typename T>
    using remove_cvext_t = typename remove_cvext<T>::type;
}

#endif

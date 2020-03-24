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
/// @file invoke_result.hpp
///

#ifndef BSL_INVOKE_RESULT_HPP
#define BSL_INVOKE_RESULT_HPP

#include "details/invoke_traits.hpp"

namespace bsl
{
    /// @class bsl::invoke_result
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the result of
    ///     calling bsl::invoke<F, ARGS...> if the provided template arguments
    ///     are valid.
    ///   @include example_invoke_result_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam FUNC the type that defines the function being called
    ///   @tparam TN the types that define the arguments passed to the
    ///     provided function when called.
    ///
    template<typename FUNC, typename... TN>
    class invoke_result final : public details::invoke_traits<void, FUNC, TN...>
    {};

    /// @brief a helper that reduces the verbosity of bsl::invoke_result
    template<typename FUNC, typename... TN>
    using invoke_result_t = typename invoke_result<FUNC, TN...>::type;
}

#endif

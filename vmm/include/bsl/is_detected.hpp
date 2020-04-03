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
/// @file is_detected.hpp
///

#ifndef BSL_IS_DETECTED_HPP
#define BSL_IS_DETECTED_HPP

#include "detected.hpp"
#include "is_convertible.hpp"
#include "is_same.hpp"

namespace bsl
{
    /// @brief The alias template is_detected is equivalent to typename
    ///   detected_or<bsl::nonesuch, Op, Args...>::value_t.
    ///   It is an alias for bsl::true_type if the template-id Op<Args...>
    ///   denotes a valid type; otherwise it is an alias for bsl::false_type.
    template<template<class...> class Op, typename... Args>
    using is_detected = typename details::detector<nonesuch, void, Op, Args...>::value_t;

    /// @brief The alias template is_detected_exact checks whether
    ///   detected_t<Op, Args...> is Expected.
    template<class Expected, template<class...> class Op, class... Args>
    using is_detected_exact = is_same<Expected, detected_t<Op, Args...>>;

    /// @brief The alias template is_detected_convertible checks whether
    ///   detected_t<Op, Args...> is convertible to To.
    template<class To, template<class...> class Op, class... Args>
    using is_detected_convertible = is_convertible<detected_t<Op, Args...>, To>;
}

#endif

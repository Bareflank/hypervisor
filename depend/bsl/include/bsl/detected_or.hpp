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
/// @file detected_or.hpp
///

#ifndef BSL_DETECTED_OR_HPP
#define BSL_DETECTED_OR_HPP

#include "details/detector.hpp"

namespace bsl
{
    /// @brief The alias template detected_or is an alias for an unspecified
    ///   class type with two public member typedefs value_t and type, which
    ///   are defined as follows:
    ///   - If the template-id OP<ARGS...> denotes a valid type, then value_t
    ///     is an alias for bsl::true_type, and type is an alias for
    ///     OP<ARGS...>;
    ///   - Otherwise, value_t is an alias for bsl::false_type and type is
    ///     an alias for DEFAULT.
    template<class Default, template<class...> class Op, class... Args>
    using detected_or = details::detector<Default, void, Op, Args...>;

    /// @brief a helper that reduces the verbosity of bsl::detected_or
    template<typename Default, template<class...> class Op, typename... Args>
    using detected_or_t = typename details::detector<Default, void, Op, Args...>::type;
}

#endif
